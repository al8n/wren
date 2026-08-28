//! RFC 9110 §14.4's `Content-Range`, read and written.

use super::{RangeError, specifier::numeral_lt};
use crate::grammar::{eq_ignore_ascii, is_field_vchar, is_token};

/// The `range-unit` every value this crate CONSTRUCTS carries.
///
/// A parsed value keeps the sender's own bytes instead — §14.1 makes unit names
/// case-insensitive, so `BYTES` is this unit, and normalising it would lose what
/// was received.
const BYTES: &[u8] = b"bytes";

/// What follows the `range-unit` and its `SP`.
///
/// Three shapes rather than the grammar's two, because a unit this crate does
/// not define has no shape it can be read into — see
/// [`ContentRange::other_range_resp`].
#[derive(Debug, Copy, Clone)]
enum Body<'a> {
  /// `range-resp = incl-range "/" ( complete-length / "*" )`.
  Range {
    /// The `first-pos`.
    first: u64,
    /// The `last-pos`, inclusive.
    last: u64,
    /// The `complete-length`, `None` where the field wrote `*`.
    complete: Option<u64>,
  },
  /// `unsatisfied-range = "*/" complete-length`.
  Unsatisfied {
    /// The `complete-length`, which this form is nothing without.
    complete: u64,
  },
  /// Everything after the `SP`, verbatim, for a unit other than `bytes`.
  Other {
    /// The span exactly as the sender wrote it, which is the whole of what a
    /// unit this crate does not read gets read as.
    span: &'a [u8],
    /// Whether that span is §14.4's `unsatisfied-range`, `"*/" complete-length`
    /// — a CLASSIFICATION kept beside the span rather than in place of it.
    ///
    /// §14.4 prints `unsatisfied-range = "*/" complete-length` and attaches no
    /// unit condition to either half, so the SHAPE is unit-independent even
    /// where the meaning is not: whatever `25` counts under `exampleunit`, a
    /// value of that shape names no `first-pos` and no `last-pos` and so
    /// encloses nothing. That is a fact about the grammar rather than about the
    /// unit, and [`generic_body`] already decides it. **Do not discard that
    /// answer**: without it `exampleunit */25` reaches
    /// [`encode_part_header`](super::multipart::encode_part_header) as an
    /// ordinary opaque span and is written into a body part, which is what
    /// RFC 9110 §15.3.7.2's per-part correspondence rule forbids.
    ///
    /// What is NOT taken out of the span is the `complete-length`:
    /// [`ContentRange::complete_length`] stays `None` here, because reporting a
    /// number means reading digits whose unit this crate does not know, and
    /// §14.1.1 leaves that to the unit. Classifying costs nothing that way —
    /// the span is still handed back whole by
    /// [`ContentRange::other_range_resp`] and still written back verbatim.
    unsatisfied: bool,
  },
}

/// RFC 9110 §14.4's `Content-Range`, the whole value of the field.
///
/// ```text
/// Content-Range       = range-unit SP
///                       ( range-resp / unsatisfied-range )
///
/// range-resp          = incl-range "/" ( complete-length / "*" )
/// incl-range          = first-pos "-" last-pos
/// unsatisfied-range   = "*/" complete-length
///
/// complete-length     = 1*DIGIT
/// ```
///
/// **Both directions, and the same two rules in each.** §14.4 states a validity
/// rule the grammar above does not carry: "A Content-Range field value is
/// invalid if it contains a range-resp that has a last-pos value less than its
/// first-pos value, or a complete-length value less than or equal to its
/// last-pos value." [`parse`](Self::parse) refuses exactly what
/// [`bytes`](Self::bytes) refuses, so a value this crate writes can never be one
/// this crate would refuse to read.
///
/// **Positions rather than a [`RangeSpec`](super::RangeSpec).** That type's
/// fields are public, so a caller-constructed one carries no `last >= first`
/// guarantee — only [`RangesSpecifier::parse`](super::RangesSpecifier::parse)
/// establishes it. Nothing here takes one, and so nothing here inherits that
/// guarantee: [`bytes`](Self::bytes) establishes both of §14.4's rules from the
/// numbers it is handed, whatever produced them.
///
/// **No `PartialEq`, and the omission is the design.** A derive would compare
/// [`unit`](Self::unit) byte for byte, and §14.1's "All range unit names are
/// case-insensitive" makes `bytes 0-499/1234` and `BYTES 0-499/1234` one value
/// — which this type stores as two, on purpose, because normalising the unit
/// would lose what was received. A hand-written one would then have to answer
/// for the span [`other_range_resp`](Self::other_range_resp) hands back, and
/// there it would be guessing: §14.1.1 says "The range unit name determines what
/// kinds of range-spec are applicable to its own specifiers", so whether two
/// spans under a unit this crate does not implement denote the same range is
/// that unit's question and not this crate's. A caller that needs equality
/// compares [`unit`](Self::unit) with `eq_ignore_ascii_case` and then the
/// accessors it cares about — the same shape
/// [`MediaType`](crate::media::MediaType) prescribes in its own documentation,
/// which derives neither trait at all and directs a caller to its own
/// case-insensitive accessors instead.
#[derive(Debug, Copy, Clone)]
pub struct ContentRange<'a> {
  /// The `range-unit` exactly as the sender wrote it, or [`BYTES`] for a value
  /// this crate constructed.
  unit: &'a [u8],
  /// What followed the `SP`.
  body: Body<'a>,
}

impl<'a> ContentRange<'a> {
  /// A `bytes` `range-resp`: the inclusive positions enclosed, and the complete
  /// length of the selected representation where it is known.
  ///
  /// `complete_length` is optional because RFC 9110 §14.4 says so: "For byte
  /// ranges, a sender SHOULD indicate the complete length of the representation
  /// from which the range has been extracted, unless the complete length is
  /// unknown or difficult to determine. An asterisk character ("*") in place of
  /// the complete-length indicates that the representation length was unknown
  /// when the header field was generated." `None` writes that asterisk.
  ///
  /// # Errors
  ///
  /// [`RangeError::InconsistentContentRange`] for either half of §14.4's
  /// validity rule — a `last` below `first`, or a `complete_length` less than
  /// **or equal to** `last`. The equality is not a rounding of the rule: a
  /// representation of `last + 1` octets is the shortest one whose last octet
  /// is at `last`, so a complete length of exactly `last` describes content that
  /// ends before the range it encloses. §14.4 attaches the consequence to the
  /// reader — "The recipient of an invalid Content-Range MUST NOT attempt to
  /// recombine the received content with a stored representation" — and this
  /// refusal is what keeps this crate from generating one.
  ///
  /// A zero-length representation therefore has no `range-resp` at all, since
  /// every `complete_length` of 0 is at or below every `last`. That is the same
  /// gap [`Resolved::EmptyRepresentation`](super::Resolved::EmptyRepresentation)
  /// names on the request side, seen from the response side, and §14.2's
  /// zero-length MAY-ignore is the exit from it there.
  pub const fn bytes(
    first: u64,
    last: u64,
    complete_length: Option<u64>,
  ) -> Result<Self, RangeError> {
    // The two clauses of one sentence, in the order it states them.
    if last < first {
      return Err(RangeError::InconsistentContentRange);
    }
    match complete_length {
      // An unknown total contradicts nothing, so `*` passes the second clause
      // by having no value to compare.
      Some(complete) if complete <= last => Err(RangeError::InconsistentContentRange),
      None | Some(_) => Ok(Self {
        unit: BYTES,
        body: Body::Range {
          first,
          last,
          complete: complete_length,
        },
      }),
    }
  }

  /// RFC 9110 §14.4's `unsatisfied-range`: `"*/" complete-length`.
  ///
  /// Infallible, and the length is required rather than optional, because this
  /// form is nothing else — §14.4: "A server generating a 416 (Range Not
  /// Satisfiable) response to a byte-range request SHOULD send a Content-Range
  /// header field with an unsatisfied-range value", and "The complete-length in
  /// a 416 response indicates the current length of the selected
  /// representation."
  ///
  /// # Which responses are 416s is not settled here
  ///
  /// §14.2 grants that status to a ranges-specifier that is **valid** and
  /// unsatisfiable. A specifier
  /// [`RangesSpecifier::parse`](super::RangesSpecifier::parse) refused —
  /// [`RangeError::MalformedSpecifier`] or [`RangeError::TooManySpecs`] — is
  /// not one, and over it the same section hands the server a CHOICE rather
  /// than an outcome: "A server that supports range requests MAY ignore or
  /// reject a Range header field that contains an invalid ranges-specifier
  /// (Section 14.1.1), a ranges-specifier with more than two overlapping
  /// ranges, or a set of many small ranges that are not listed in ascending
  /// order". Ignoring it is a 200 carrying the whole representation and no
  /// `Content-Range` at all — the branch
  /// [`MAX_RANGE_SPECS`](super::MAX_RANGE_SPECS) is written for, on the
  /// strength of §14.2's outright "A server MAY ignore the Range header field"
  /// — and rejecting it is a status §14.2 leaves the server to pick. Neither
  /// branch is a 416, and which one is taken is the caller's.
  /// [`Resolved::EmptyRepresentation`](super::Resolved::EmptyRepresentation) is
  /// not a 416 either: §14.1.2 makes it satisfiable, and a caller reading it as
  /// unsatisfiable inverts that section.
  #[inline]
  pub const fn unsatisfied(complete_length: u64) -> Self {
    Self {
      unit: BYTES,
      body: Body::Unsatisfied {
        complete: complete_length,
      },
    }
  }

  /// Reads a whole `Content-Range` field value.
  ///
  /// The value arrives with its surrounding whitespace already stripped, because
  /// RFC 9110 §5.5 puts that on whoever read the field rather than on this
  /// reader: "A field value does not include leading or trailing whitespace.
  /// When a specific version of HTTP allows such whitespace to appear in a
  /// message, a field parsing implementation MUST exclude such whitespace prior
  /// to evaluating the field value." RFC 9112 §5.1 is one such version, and the
  /// one that names that whitespace `OWS`: "The field line value does not
  /// include that leading or trailing whitespace: OWS occurring before the first
  /// non-whitespace octet of the field line value, or after the last
  /// non-whitespace octet of the field line value, is excluded by parsers when
  /// extracting the field line value from a field line." The `SP` this splits on
  /// is §14.4's own, one space and not a run of them.
  ///
  /// The `range-unit` is matched against `bytes` with ASCII case-insensitivity,
  /// because §14.1 says "All range unit names are case-insensitive" — matching
  /// the token exactly would read `Content-Range: BYTES 0-499/1234` as an opaque
  /// span and deny a recombiner the positions it needs. [`unit`](Self::unit)
  /// still returns the sender's own bytes.
  ///
  /// # Obligations this cannot discharge
  ///
  /// Each turns on a fact this crate never sees, so each is the caller's:
  ///
  /// - §14.4: "If a 206 (Partial Content) response contains a Content-Range
  ///   header field with a range unit (Section 14.1) that the recipient does not
  ///   understand, the recipient MUST NOT attempt to recombine it with a stored
  ///   representation.  A proxy that receives such a message SHOULD forward it
  ///   downstream." [`other_range_resp`](Self::other_range_resp) being `Some` is
  ///   exactly the condition, since this crate understands `bytes` alone.
  /// - §14.4: "The recipient of an invalid Content-Range MUST NOT attempt to
  ///   recombine the received content with a stored representation." An `Err`
  ///   from here is that value; there is nothing to recombine from.
  /// - §14.4: "A server MUST ignore a Content-Range header field received in a
  ///   request with a method for which Content-Range support is not defined."
  ///   This function takes no method and cannot check it.
  /// - §14.5, a separate rule turning on a separate fact — the rule above is
  ///   about the METHOD, this one about the RESOURCE: "An origin server SHOULD
  ///   respond with a 400 (Bad Request) status code if it receives
  ///   Content-Range on a PUT for a target resource that does not support
  ///   partial PUT requests." Partial PUT support is per-resource and, in
  ///   §14.5's own words, "inconsistent and depends on private agreements with
  ///   user agents", so no reading of the value can settle it; this function
  ///   sees neither the resource nor the method. An `Ok` from here says the
  ///   value is a well-formed `Content-Range`, never that a partial PUT was
  ///   invited.
  /// - §14.4: "The Content-Range header field has no meaning for status codes
  ///   that do not explicitly describe its semantic.  For this specification,
  ///   only the 206 (Partial Content) and 416 (Range Not Satisfiable) status
  ///   codes describe a meaning for Content-Range." It takes no status either.
  ///
  /// # Errors
  ///
  /// [`RangeError::MalformedContentRange`] when the value is not a
  /// `Content-Range`: no `SP`, a `range-unit` that is not a §5.6.2 `token`, or —
  /// under `bytes` — anything after the `SP` that is neither a `range-resp` nor
  /// an `unsatisfied-range`. Leading zeros are digits like any other, so `007`
  /// is 7.
  ///
  /// And, under any OTHER unit, a span behind the `SP` that is not
  /// `1*field-vchar`: empty, or carrying an octet §5.5 keeps out of a field
  /// value — a CR, an LF, a NUL, any other CTL — or a second SP or a HTAB,
  /// which §14.4's own production has no room for. That is the whole of the
  /// GRAMMAR checked there, and it is checked so that
  /// [`other_range_resp`](Self::other_range_resp) can promise it; §14.1.1
  /// leaves the span's MEANING to the range unit, and this reader still leaves
  /// it there.
  ///
  /// It also covers a numeral no `u64` holds, and that is a deliberate limit
  /// rather than the overflow §14.1.2 warns of: "recipients MUST anticipate
  /// potentially large decimal numerals and prevent parsing errors due to
  /// integer conversion overflows". Nothing here converts one — a numeral past
  /// `u64::MAX` is refused whole, never truncated. The refusal is affordable in
  /// a way [`RangesSpecifier`](super::RangesSpecifier)'s would not have been:
  /// refusing a `Range` costs the client the 206 §14.2 SHOULD-ed it, whichever
  /// of that section's two branches — ignore or reject — the server then takes,
  /// whereas the only thing §14.4 grants a recipient over a `Content-Range` it
  /// cannot read is to decline to recombine, which is what this `Err` says. A
  /// `u64` of octets addresses sixteen exabytes, and every position this crate
  /// hands back is one.
  ///
  /// [`RangeError::InconsistentContentRange`] for either half of §14.4's
  /// validity rule, which [`bytes`](Self::bytes) states in full.
  ///
  /// **That rule reaches every unit, not only `bytes`.** §14.4 states it over
  /// `range-resp`, whose numerals are `1*DIGIT`, and attaches no unit condition
  /// to either clause — so `widgets 9-1/25` and `widgets 0-9/9` are each
  /// invalid here for the same reason `bytes 9-1/25` and `bytes 0-9/9` are. The
  /// span still has to MATCH that numeric shape first: §14.6's own
  /// `exampleunit 1.2-4.3/25` does not, so no clause has a numeral to compare
  /// and the value comes back opaque as before. Where a numeral exceeds a
  /// [`u64`] the comparison is made on the digits rather than on a conversion,
  /// as [`RangesSpecifier::parse`](super::RangesSpecifier::parse) already does
  /// for §14.1.1's identically shaped clause, so no value is refused merely for
  /// being large under a unit whose positions are not octets.
  ///
  /// # §14.4's second alternative reaches every unit too
  ///
  /// `unsatisfied-range = "*/" complete-length` sits inside the same printed
  /// grammar, under the same single `range-unit` slot, with no unit condition on
  /// either half — so a span of that shape is that alternative whatever unit
  /// names it, and [`is_unsatisfied`](Self::is_unsatisfied) says so for
  /// `exampleunit */25` exactly as for `bytes */25`. Recognising the shape is
  /// all that happens: the span is still opaque, so
  /// [`other_range_resp`](Self::other_range_resp) still hands it back whole and
  /// [`complete_length`](Self::complete_length) still declines to read digits
  /// whose unit §14.1.1 leaves to that unit.
  ///
  /// What the recognition is FOR is
  /// [`encode_part_header`](super::multipart::encode_part_header), whose
  /// refusal of a body part enclosing nothing is §15.3.7.2's and carries no unit
  /// condition either. Recognising the shape here and discarding the answer lets
  /// `exampleunit */25` head a body part while `bytes */25` is refused.
  pub fn parse(value: &'a [u8]) -> Result<Self, RangeError> {
    let Some(space) = value.iter().position(|&b| b == b' ') else {
      return Err(RangeError::MalformedContentRange);
    };
    let (Some(unit), Some(rest)) = (value.get(..space), value.get(space.saturating_add(1)..))
    else {
      return Err(RangeError::MalformedContentRange);
    };
    // §14.1: `range-unit = token`.
    if !is_token(unit) {
      return Err(RangeError::MalformedContentRange);
    }
    if !eq_ignore_ascii(unit, "bytes") {
      // `1*DIGIT` is what RFC 9110 §14.4 writes for every position, and §14.6's
      // own example is `Content-Range: exampleunit 1.2-4.3/25`, which those
      // digits do not admit: the specification contradicts its own example and
      // the reader has to survive the example. So the span is handed back
      // unread rather than forced through a grammar that is not its unit's.
      //
      // Whole, and `unsatisfied-range` included: the SPAN is never split, not
      // even for that form. Reading half of a value would mean answering with a
      // `complete-length` while dropping the bytes it came out of, and only the
      // unit's own specification can say what those bytes mean — §14.1.1 gives
      // the range unit the job of determining "what kinds of range-spec are
      // applicable to its own specifiers".
      //
      // Handing the span over whole is not the same as declining to RECOGNISE
      // its shape, and the two are easily run together. §14.4 prints
      // `unsatisfied-range = "*/" complete-length` with no unit condition on
      // either half, so a value of that shape names no positions whatever its
      // unit counts; `Body::Other`'s `unsatisfied` field is that recognition,
      // recorded beside the span rather than instead of it.
      //
      // Unread is not unconstrained, and the OCTETS are checked even though the
      // meaning is not. Whatever a unit's own specification makes of this span,
      // the span is a piece of a FIELD VALUE, and RFC 9110 §5.5 bounds one:
      // `field-value = *field-content`, `field-content = field-vchar [ 1*( SP /
      // HTAB / field-vchar ) field-vchar ]`, `field-vchar = VCHAR / obs-text`.
      // No CR and no LF is in it. §14.4 then accounts for the one whitespace
      // character its own production contains — the `SP` this split has already
      // consumed — and neither alternative behind that `SP` contains another,
      // which §14.1.1's `other-range = 1*( %x21-2B / %x2D-7E )` says in as many
      // words on the request side and §14.6's own example demonstrates. What is
      // left is `1*field-vchar`, and `is_opaque_range_resp` is that rule.
      //
      // It subsumes two narrower tests. `example unit 1.2-4.3/25` is malformed
      // rather than a value under a unit named `example`, because the second
      // `SP` is not a `field-vchar`; and both alternatives are non-empty,
      // because `1*` names at least one octet.
      //
      // The check is here rather than at the encoder because THIS is the one
      // entrance: `Body::Other` is constructed nowhere else, and `encode` and
      // `multipart::encode_part_header` copy the span back out verbatim —
      // the second of them into a header line of a body this crate frames,
      // where a CRLF would be a field line this crate wrote and no one sent.
      if !is_opaque_range_resp(rest) {
        return Err(RangeError::MalformedContentRange);
      }
      // Unread is not unchecked, and §14.4's two validity clauses are the
      // second thing that binds a span this reader does not interpret. They are
      // stated over `range-resp`, whose `incl-range` and `complete-length` are
      // `1*DIGIT`, and they carry NO unit condition — so a value matching that
      // numeric shape has to satisfy them whatever its unit names. `widgets
      // 9-1/25` and `widgets 0-9/9` are each invalid by one of the two, and
      // §14.4 attaches the same consequence to a recipient of either that it
      // attaches under `bytes`.
      //
      // A span that does NOT match the shape stays opaque, which is what keeps
      // §14.6's own `exampleunit 1.2-4.3/25` readable: `1.2` is not `1*DIGIT`,
      // so no clause has a numeral to apply and the whole span is handed back
      // as before.
      //
      // The representation does not change either — a consistent `widgets
      // 0-9/25` is still `Body::Other`, still `other_range_resp` `Some`, still
      // written back verbatim. §14.1.1 gives the range unit the job of
      // determining "what kinds of range-spec are applicable to its own
      // specifiers", so what those numerals MEAN stays that unit's question.
      // What is asked here is only the arithmetic §14.4 asks of the numerals
      // themselves.
      //
      // And the shape the walk recognised is KEPT, which is the half easiest to
      // throw away. `unsatisfied` below is `generic_body`'s own answer carried
      // into the value; without it `exampleunit */25` and `exampleunit 0-9/25`
      // are the same undifferentiated `Body::Other`, and §15.3.7.2's
      // "corresponding to the range being enclosed in that body part" has
      // nothing to be enforced against under a unit this crate does not read.
      // See the field's own documentation for why the `complete-length` is not
      // lifted out with it.
      let unsatisfied = match generic_body(rest) {
        Some(GenericBody::Range {
          first,
          last,
          complete,
        }) => {
          // "a last-pos value less than its first-pos value"
          if numeral_lt(last, first) {
            return Err(RangeError::InconsistentContentRange);
          }
          // "or a complete-length value less than or equal to its last-pos
          // value"
          if let Some(complete) = complete
            && !numeral_lt(last, complete)
          {
            return Err(RangeError::InconsistentContentRange);
          }
          false
        }
        // §14.4's clauses are both stated over a `range-resp`, so this form has
        // no `last-pos` for either to compare against — nothing to check, and
        // the recognition itself is what is worth keeping.
        Some(GenericBody::Unsatisfied) => true,
        // A span matching neither shape carries no numerals at all, and is no
        // more `unsatisfied-range` than it is `range-resp`.
        None => false,
      };
      return Ok(Self {
        unit,
        body: Body::Other {
          span: rest,
          unsatisfied,
        },
      });
    }
    // `unsatisfied-range = "*/" complete-length`, tried first because its
    // opening is the one shape no `incl-range` can have. `complete-length` is
    // `1*DIGIT`, so `bytes */*` is neither alternative.
    if let Some(complete) = rest.strip_prefix(b"*/") {
      let Some(complete) = numeral(complete) else {
        return Err(RangeError::MalformedContentRange);
      };
      return Ok(Self {
        unit,
        body: Body::Unsatisfied { complete },
      });
    }
    // `range-resp = incl-range "/" ( complete-length / "*" )`, then
    // `incl-range = first-pos "-" last-pos`.
    let Some(slash) = rest.iter().position(|&b| b == b'/') else {
      return Err(RangeError::MalformedContentRange);
    };
    let (Some(incl), Some(total)) = (rest.get(..slash), rest.get(slash.saturating_add(1)..)) else {
      return Err(RangeError::MalformedContentRange);
    };
    let Some(hyphen) = incl.iter().position(|&b| b == b'-') else {
      return Err(RangeError::MalformedContentRange);
    };
    let (Some(first), Some(last)) = (incl.get(..hyphen), incl.get(hyphen.saturating_add(1)..))
    else {
      return Err(RangeError::MalformedContentRange);
    };
    let (Some(first), Some(last)) = (numeral(first), numeral(last)) else {
      return Err(RangeError::MalformedContentRange);
    };
    // `( complete-length / "*" )`: only the literal asterisk is the unknown, and
    // an asterisk with anything after it is neither branch.
    let complete = if total == b"*" {
      None
    } else {
      let Some(total) = numeral(total) else {
        return Err(RangeError::MalformedContentRange);
      };
      Some(total)
    };
    // §14.4's two validity rules, over a value that is already grammar — asked
    // of the CONSTRUCTOR, so the reader and the writer cannot come to disagree
    // about which values are invalid. What comes back is rebuilt around the
    // sender's own unit, since `bytes` writes this crate's spelling of it.
    let checked = Self::bytes(first, last, complete)?;
    Ok(Self {
      unit,
      body: checked.body,
    })
  }

  /// Writes this value back, returning how many bytes it took.
  ///
  /// The digits are canonical rather than the sender's: a parsed `007`
  /// re-encodes as `7`. Every value §14.4 prints is written back byte for byte,
  /// which is what `the_seven_printed_examples_round_trip` pins.
  ///
  /// # The response shape this field belongs to
  ///
  /// RFC 9110 §15.3.7.1 makes this field a MUST when a **single** part is
  /// transferred: "the server generating the 206 response MUST generate a
  /// Content-Range header field, describing what range of the selected
  /// representation is enclosed". §15.3.7.2 makes it a MUST **NOT** when several
  /// are: "a server MUST NOT generate a Content-Range header field in the HTTP
  /// header section of a multiple part response (this field will be sent in each
  /// part instead)". Which shape a response has is the caller's and this crate
  /// never sees it, so nothing here can refuse the wrong one. The per-part
  /// fields the second sentence names are this same encoder's output, written
  /// once into each part's header area instead of once into the message's.
  ///
  /// # Errors
  ///
  /// [`RangeError::BufferTooSmall`] when `out` is shorter than the value. The
  /// length is measured before anything is written, so a call that cannot fit
  /// leaves `out` untouched rather than handing a caller who reuses its buffer
  /// the head of one value over the tail of another.
  pub fn encode(&self, out: &mut [u8]) -> Result<usize, RangeError> {
    let len = self.encoded_len();
    let Some(room) = out.get_mut(..len) else {
      return Err(RangeError::BufferTooSmall);
    };
    match self.write_into(room) {
      // Not a second size test but the same one, asked of the writer rather
      // than of the measurement: `write_into` fills `room` exactly, and this
      // arm is what it answers if it ever measured differently from
      // `encoded_len`. A refusal is then the report, since a `Content-Range`
      // written from two disagreeing sizes is one no recipient may recombine.
      Some(()) => Ok(len),
      None => Err(RangeError::BufferTooSmall),
    }
  }

  /// The `range-unit`, exactly as the sender wrote it.
  #[inline]
  pub const fn unit(&self) -> &'a [u8] {
    self.unit
  }

  /// The inclusive `first-pos` and `last-pos`, for a `bytes` `range-resp`.
  ///
  /// `None` for the unsatisfied form, which names no positions, and for a unit
  /// other than `bytes`, whose positions §14.4's `1*DIGIT` may not even describe.
  #[inline]
  pub const fn incl_range(&self) -> Option<(u64, u64)> {
    match self.body {
      Body::Range { first, last, .. } => Some((first, last)),
      Body::Unsatisfied { .. } | Body::Other { .. } => None,
    }
  }

  /// The `complete-length`.
  ///
  /// `None` where the field wrote `*` for a total that "was unknown when the
  /// header field was generated" (RFC 9110 §14.4), and `None` for a unit other
  /// than `bytes`, where the whole value is handed back by
  /// [`other_range_resp`](Self::other_range_resp) instead. The two are told
  /// apart by that accessor rather than by this one.
  ///
  /// `None` **even where [`is_unsatisfied`](Self::is_unsatisfied) is true under
  /// such a unit.** That answer is a fact about the value's SHAPE, which §14.4
  /// states without a unit condition; a number would be a fact about what the
  /// digits COUNT, which §14.1.1 leaves to the range unit — "The range unit
  /// name determines what kinds of range-spec are applicable to its own
  /// specifiers." The digits are in the span
  /// [`other_range_resp`](Self::other_range_resp) hands back, unread and whole.
  #[inline]
  pub const fn complete_length(&self) -> Option<u64> {
    match self.body {
      Body::Range { complete, .. } => complete,
      Body::Unsatisfied { complete } => Some(complete),
      Body::Other { .. } => None,
    }
  }

  /// Whether the value is §14.4's `unsatisfied-range`, `"*/" complete-length`.
  ///
  /// **True under every unit**, and that is what §14.4 says: it prints
  /// `unsatisfied-range = "*/" complete-length` inside one grammar with one
  /// `range-unit` slot, and attaches no unit condition to either half. So the
  /// shape is unit-independent even though the meaning of `complete-length` is
  /// not — whatever the digits count, a value spelled this way names no
  /// `first-pos` and no `last-pos`, and encloses nothing.
  ///
  /// That distinction is the whole of what this accessor asserts, and it is
  /// deliberately narrower than a claim to have READ the value: under a unit other
  /// than `bytes` the span is still opaque, [`other_range_resp`](Self::other_range_resp)
  /// is still `Some`, [`complete_length`](Self::complete_length) is still `None`
  /// and [`encode`](Self::encode) still writes the sender's own bytes back. Only
  /// the shape is recognised.
  ///
  /// **What turns on it** is RFC 9110 §15.3.7.2's per-part rule: "Within the
  /// header area of each body part in the multipart content, the server MUST
  /// generate a Content-Range header field corresponding to the range being
  /// enclosed in that body part." A value enclosing nothing corresponds to no
  /// enclosed range, so
  /// [`encode_part_header`](super::multipart::encode_part_header) refuses one —
  /// under `exampleunit` exactly as under `bytes`, because this answer does not
  /// depend on which of the two it is. An implementation whose generic walk
  /// recognises the shape and then discards the arm leaves `exampleunit */25` to
  /// be written into a body part the `bytes` spelling of which is refused.
  #[inline]
  pub const fn is_unsatisfied(&self) -> bool {
    match self.body {
      Body::Unsatisfied { .. } => true,
      Body::Other { unsatisfied, .. } => unsatisfied,
      Body::Range { .. } => false,
    }
  }

  /// Everything after the `SP`, verbatim, when the unit is not `bytes`, and
  /// `None` for `bytes` itself.
  ///
  /// `Some` is also §14.4's own condition for the recombination MUST NOT that
  /// [`parse`](Self::parse) lists: a unit this crate does not understand is one
  /// this crate cannot recombine from.
  ///
  /// # What the span is guaranteed to hold
  ///
  /// `1*field-vchar` — at least one octet, every one of them RFC 9110 §5.5's
  /// `field-vchar` (`VCHAR / obs-text`), and so no SP, no HTAB and no CTL. A
  /// value this accessor hands back can be written into a field value or into a
  /// `multipart/byteranges` part header without carrying a line break in with
  /// it, which is what [`encode`](Self::encode) and
  /// [`multipart::encode_part_header`](super::multipart::encode_part_header) do
  /// with it. Whether those octets DENOTE a range, and which one, is the range
  /// unit's question and is not answered here — §14.1.1: "The range unit name
  /// determines what kinds of range-spec are applicable to its own specifiers."
  #[inline]
  pub const fn other_range_resp(&self) -> Option<&'a [u8]> {
    match self.body {
      Body::Other { span, .. } => Some(span),
      Body::Range { .. } | Body::Unsatisfied { .. } => None,
    }
  }

  /// How many bytes [`encode`](Self::encode) writes.
  ///
  /// Saturating, so a length no `usize` holds becomes one no buffer satisfies —
  /// which is [`RangeError::BufferTooSmall`], the answer such a call has anyway.
  ///
  /// Visible to the whole `range` module so the
  /// [`multipart`](super::multipart) writer can size a part header around this
  /// field before writing any of it, rather than discovering the field does not
  /// fit halfway through one.
  pub(super) fn encoded_len(&self) -> usize {
    // `range-unit SP`, which every shape below carries.
    let head = self.unit.len().saturating_add(1);
    match self.body {
      Body::Range {
        first,
        last,
        complete,
      } => {
        let total = match complete {
          Some(complete) => digit_count(complete),
          // The `*` of `( complete-length / "*" )`.
          None => 1,
        };
        head
          .saturating_add(digit_count(first))
          // `-` and `/`.
          .saturating_add(2)
          .saturating_add(digit_count(last))
          .saturating_add(total)
      }
      // `*/`.
      Body::Unsatisfied { complete } => {
        head.saturating_add(2).saturating_add(digit_count(complete))
      }
      Body::Other { span, .. } => head.saturating_add(span.len()),
    }
  }

  /// Fills `out` — which is exactly [`encoded_len`](Self::encoded_len) long —
  /// with the value, or answers `None` without finishing if it is not.
  fn write_into(&self, out: &mut [u8]) -> Option<()> {
    let out = put(out, self.unit)?;
    let out = put(out, b" ")?;
    let out = match self.body {
      Body::Range {
        first,
        last,
        complete,
      } => {
        let out = put_decimal(out, first)?;
        let out = put(out, b"-")?;
        let out = put_decimal(out, last)?;
        let out = put(out, b"/")?;
        match complete {
          Some(complete) => put_decimal(out, complete)?,
          None => put(out, b"*")?,
        }
      }
      Body::Unsatisfied { complete } => {
        let out = put(out, b"*/")?;
        put_decimal(out, complete)?
      }
      Body::Other { span, .. } => put(out, span)?,
    };
    out.is_empty().then_some(())
  }
}

/// Whether `rest` — everything behind a `Content-Range`'s `SP`, under a unit
/// this crate does not read — is `1*field-vchar`.
///
/// The outermost grammar that reaches a span whose meaning belongs to someone
/// else. RFC 9110 §5.5 opens with what makes it apply at all: "HTTP field
/// values consist of a sequence of characters in a format defined by the
/// field's grammar." The field's grammar here is §14.4's, and §14.4 defers the
/// span's INTERPRETATION to the range unit; what neither defers is that the
/// bytes are still a field value, bounded by §5.5's `field-vchar` / SP / HTAB.
///
/// `obs-text` is in and both line-break octets are out, which is the whole
/// point of taking §5.5 as the bound rather than plain `VCHAR`: §5.5 tells a
/// recipient to "treat other allowed octets in field content (i.e., obs-text)
/// as opaque data", and an opaque span is exactly the case that sentence
/// describes. A CR or an LF is not an allowed octet at all, so nothing about
/// opacity admits one.
///
/// SP and HTAB come off on §14.4's own authority rather than §5.5's: its
/// `Content-Range = range-unit SP ( range-resp / unsatisfied-range )` contains
/// exactly one whitespace character, the caller has already split at it, and
/// neither alternative behind it holds another. §5.5 would admit an interior SP
/// or HTAB in some other field; this one has no room for either.
fn is_opaque_range_resp(rest: &[u8]) -> bool {
  !rest.is_empty() && rest.iter().all(|byte| is_field_vchar(*byte))
}

/// RFC 9110 §14.4's `( range-resp / unsatisfied-range )` recognised WITHOUT the
/// unit, with each numeral left as its digits.
///
/// ```text
/// range-resp          = incl-range "/" ( complete-length / "*" )
/// incl-range          = first-pos "-" last-pos
/// unsatisfied-range   = "*/" complete-length
///
/// complete-length     = 1*DIGIT
/// ```
///
/// §14.4 prints one grammar and gives it one `range-unit` slot, so both
/// alternatives behind the `SP` are stated for every unit rather than for
/// `bytes`. What §14.1.1 makes unit-specific is the MEANING — "The range unit
/// name determines what kinds of range-spec are applicable to its own
/// specifiers" — and §14.6's own `exampleunit 1.2-4.3/25` is a unit taking that
/// permission, which is why `None` here is an ordinary answer and not a fault.
///
/// **Why both alternatives are recognised when only one carries a rule.**
/// §14.4's invalidity sentence is stated entirely over `range-resp`: "A
/// Content-Range field value is invalid if it contains a range-resp that has a
/// last-pos value less than its first-pos value, or a complete-length value
/// less than or equal to its last-pos value." An `unsatisfied-range` names no
/// `last-pos`, so neither clause has a pair to compare and
/// [`Unsatisfied`](GenericBody::Unsatisfied) is the answer *recognised, and
/// nothing to check*. It is told apart from `None` because the two say different
/// things — one is §14.4's own second alternative, the other is a span this
/// grammar does not reach — and because a clause added to that form later
/// attaches here rather than to a fall-through.
///
/// **And because the recognition is itself the answer to a question.** *Nothing
/// to check* is not *nothing to report*: [`ContentRange::parse`] stores this arm
/// as `Body::Other`'s `unsatisfied`, which is what
/// [`ContentRange::is_unsatisfied`] reports and what
/// [`encode_part_header`](super::multipart::encode_part_header) refuses a body
/// part on. A caller that matches this arm and does nothing with it throws away
/// a distinction this function has already drawn, one frame up.
///
/// The numerals come back as DIGITS rather than as values, which is the whole
/// reason this is separate from the `bytes` path: §14.4's clauses compare the
/// numerals against each other, [`numeral_lt`] does that exactly at any length,
/// and a `range-resp` under some other unit is under no obligation to fit a
/// `u64`. The `bytes` path converts instead, and [`numeral`] says why that
/// difference is deliberate.
fn generic_body(rest: &[u8]) -> Option<GenericBody<'_>> {
  // `unsatisfied-range` first, because its opening is the one shape no
  // `incl-range` can have — the same order the `bytes` path takes.
  if let Some(complete) = rest.strip_prefix(b"*/")
    && is_digits(complete)
  {
    return Some(GenericBody::Unsatisfied);
  }
  let slash = rest.iter().position(|&b| b == b'/')?;
  let incl = rest.get(..slash)?;
  let total = rest.get(slash.saturating_add(1)..)?;
  let hyphen = incl.iter().position(|&b| b == b'-')?;
  let first = incl.get(..hyphen)?;
  let last = incl.get(hyphen.saturating_add(1)..)?;
  if !is_digits(first) || !is_digits(last) {
    return None;
  }
  // `( complete-length / "*" )`: only the literal asterisk is the unknown, and
  // an asterisk with anything after it is neither branch.
  let complete = if total == b"*" {
    None
  } else if is_digits(total) {
    Some(total)
  } else {
    return None;
  };
  Some(GenericBody::Range {
    first,
    last,
    complete,
  })
}

/// Which of RFC 9110 §14.4's two alternatives a span behind the `SP` matched,
/// read without the unit.
///
/// See [`generic_body`], which is the only thing that builds one.
enum GenericBody<'a> {
  /// `range-resp = incl-range "/" ( complete-length / "*" )`, each numeral as
  /// its digits.
  Range {
    /// The `first-pos`, `1*DIGIT`.
    first: &'a [u8],
    /// The `last-pos`, `1*DIGIT`.
    last: &'a [u8],
    /// The `complete-length`, `None` where the value wrote `*`.
    complete: Option<&'a [u8]>,
  },
  /// `unsatisfied-range = "*/" complete-length`, which §14.4's validity clauses
  /// say nothing about.
  Unsatisfied,
}

/// Whether `digits` is `1*DIGIT`.
///
/// The alphabet only. What the digits are worth is [`numeral`]'s question under
/// `bytes` and [`numeral_lt`]'s under any other unit, and neither of those is
/// asked of a span that is not this shape.
fn is_digits(digits: &[u8]) -> bool {
  !digits.is_empty() && digits.iter().all(u8::is_ascii_digit)
}

/// A `1*DIGIT` numeral's value, or `None` when the bytes are not `1*DIGIT` or no
/// `u64` holds what they spell.
///
/// The other numeral reader in this module's sibling, `specifier`'s, answers
/// `Pos::Beyond` for the second case instead. The two differ because their
/// sections do, and the argument is DEFINEDNESS. Every §14.1.2 rule has a
/// defined answer for a numeral past `u64::MAX` — such a `first-pos` is at or
/// above every possible length, such a `last-pos` is already that section's own
/// normalisation condition, such a `suffix-length` exceeds every representation
/// — so `Pos::Beyond` leaves every one of them total. §14.4 has no such answer:
/// its two validity clauses compare the numerals against EACH OTHER, and a
/// position past `u64::MAX` against another one settles neither. §14.1.1's
/// identically shaped clause does not transfer the sibling's way out, either:
/// there the digits are still in hand and the comparison is made on them before
/// any conversion, and the answer wanted is a verdict about the value. Here the
/// positions are handed on to a recipient that recombines AT them, and a
/// position no `u64` holds names no offset to recombine at. So `None` is the
/// only total answer left, which is why the same numeral is refused in this
/// module and carried in its sibling.
///
/// A SECOND argument sits on `ContentRange::parse`, and it is about cost rather
/// than definedness: what refusing the whole value takes from each side. Both
/// arguments point the same way here; neither stands in for the other.
fn numeral(digits: &[u8]) -> Option<u64> {
  if digits.is_empty() {
    return None;
  }
  let mut value: u64 = 0;
  for &byte in digits {
    // One step answers both questions `1*DIGIT` asks of a byte: `checked_sub`
    // rejects everything below `0` and the filter everything above `9`.
    let digit = byte.checked_sub(b'0').filter(|digit| *digit < 10)?;
    value = value.checked_mul(10)?.checked_add(u64::from(digit))?;
  }
  Some(value)
}

/// How many decimal digits `value` is written with.
///
/// One for zero, because `1*DIGIT` names at least one digit and `0` is how that
/// value is spelled.
const fn digit_count(value: u64) -> usize {
  let mut count = 1usize;
  let mut rest = value;
  while rest >= 10 {
    rest = rest.div_euclid(10);
    count = count.saturating_add(1);
  }
  count
}

/// One `DIGIT`, as the ASCII byte that spells it.
///
/// The remainder is taken HERE rather than at each call site, so no caller can
/// hand this a value that spells a byte outside `0` through `9`; the last arm is
/// nine's own, since `rem_euclid(10)` answers nothing above it. `crate::date`'s
/// own `ascii_digit` is written against the same argument.
// gate-exempt: crate::date — named for contrast: the module holding the twin of
// this helper, written against the same argument for `2DIGIT` and `4DIGIT`
// columns. Nothing here calls it; its own is `u16`-wide and this one is `u64`.
const fn ascii_digit(value: u64) -> u8 {
  match value.rem_euclid(10) {
    0 => b'0',
    1 => b'1',
    2 => b'2',
    3 => b'3',
    4 => b'4',
    5 => b'5',
    6 => b'6',
    7 => b'7',
    8 => b'8',
    _ => b'9',
  }
}

/// Writes `bytes` at the front of `out` and hands back what is left of it, or
/// `None` when `out` is shorter than `bytes`.
///
/// Visible to the whole `range` module because the sibling
/// [`multipart`](super::multipart) writer frames the same field values: one
/// copy of a measure-then-fill step, so the two encoders cannot come to write
/// bytes at different offsets.
pub(super) fn put<'o>(out: &'o mut [u8], bytes: &[u8]) -> Option<&'o mut [u8]> {
  let (head, rest) = out.split_at_mut_checked(bytes.len())?;
  head.copy_from_slice(bytes);
  Some(rest)
}

/// Writes `value` as `1*DIGIT` at the front of `out` and hands back what is left
/// of it, or `None` when `out` is shorter than the numeral.
///
/// Filled from the least significant end, which is the end a decimal expansion
/// is available at: the width is taken from [`digit_count`] first, and the
/// division then walks backwards into it.
fn put_decimal(out: &mut [u8], value: u64) -> Option<&mut [u8]> {
  let (head, rest) = out.split_at_mut_checked(digit_count(value))?;
  let mut remaining = value;
  for slot in head.iter_mut().rev() {
    *slot = ascii_digit(remaining);
    remaining = remaining.div_euclid(10);
  }
  Some(rest)
}
