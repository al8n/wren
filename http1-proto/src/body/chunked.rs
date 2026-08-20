//! RFC 9112 §7.1's chunked transfer coding, inbound: the sub-machine that turns
//! `chunk-size [ chunk-ext ] CRLF chunk-data CRLF` into body items, and the
//! §7.1.2 trailer section that closes it.
//!
//! Chunked is where a framing disagreement becomes a smuggled message (§11.2),
//! so every rule here is strict and none of them is recovered from: a
//! chunk-size takes hex digits and nothing else — no whitespace, no sign, no
//! `0x` — a chunk-ext is parsed even though its meaning is ignored, every
//! terminator is a full CRLF, and a trailer line is the same field line the
//! head scanner validates. A recipient that skipped any of those bytes without
//! reading them would be taking the sender's word for where the next chunk
//! begins.
//!
//! Nothing is buffered here. What this decoder cannot decide from the bytes in
//! hand — a chunk-size line whose CRLF has not arrived — is reported as
//! need-more-input with nothing consumed, leaving the partial line in the
//! caller's buffer exactly as the head scanner does. Two bounds keep that
//! request from being unbounded: a chunk-size line that cannot legally
//! terminate inside `MAX_CHUNK_LINE_BYTES` is refused rather than waited on,
//! and the trailer section is a field section (RFC 9110 §6.5), so it carries
//! the head's own caps.
//!
//! OFFSETS. Every `MalformedDetail` this module reports is relative to the
//! slice the current `feed` was handed. A body decoder sees a moving window of
//! a stream it has no absolute position in — the head that framed the body may
//! have arrived several reads ago — so the window is the only frame of
//! reference at this layer. The connection state machine, which knows where the
//! window sat, is what turns such an offset into a position in the stream.

use super::{BodyItem, MAX_CHUNK_EXT_BYTES, claim};
use crate::{
  error::H1Error,
  grammar::{is_field_vchar, is_token_byte},
  head::{LineEnd, MAX_HEAD_BYTES, MAX_HEADERS, delimit_line, malformed, validate_field_line},
};

/// The `chunk-size`'s share of the line budget below (RFC 9112 §7.1).
///
/// `u64::MAX` is exactly sixteen hex digits wide, so sixteen spells every size
/// this core can represent. `1*HEXDIG` also admits unlimited LEADING zeros,
/// which carry no value and would carry no bound either; they are not counted
/// out digit by digit — the line budget is what refuses them — and this is the
/// share of that budget a size is allowed to want.
const MAX_CHUNK_SIZE_DIGITS: usize = 16;

/// Bytes a chunk-size line may occupy before its CRLF: a size and the whole
/// extension budget.
///
/// A bound on need-more-input rather than a rule of the grammar. A line that
/// has not terminated inside it cannot terminate legally, so it is refused
/// where it stands instead of being waited on — otherwise "the CRLF has not
/// arrived yet" is an allocation whose size the peer chooses.
const MAX_CHUNK_LINE_BYTES: usize = MAX_CHUNK_SIZE_DIGITS.saturating_add(MAX_CHUNK_EXT_BYTES);

/// RFC 9112 §2.2, and §11.2 for why it is a MUST rather than a preference: a
/// chunked body's own framing lines are delimited by CRLF exactly like a head's.
const BARE_CR_OR_LF: &str = "bare CR or LF in the chunked body";

/// A chunk-size line past the budget. Bounded work, not a grammar rule: the
/// line is refused whether it broke `1*HEXDIG` or merely padded it.
const CHUNK_LINE_TOO_LONG: &str = "chunk-size line is too long";

/// The extension budget alone, which is the part of the line a peer can grow
/// without changing the length it announces.
const CHUNK_EXT_TOO_LONG: &str = "chunk extensions are too long";

/// RFC 9112 §7.1: the CRLF after `chunk-data` is what separates a chunk's last
/// octet from the next chunk's size.
const CHUNK_DATA_CRLF: &str = "chunk-data is not followed by CRLF";

/// Incremental decoder for ONE chunked body (RFC 9112 §7.1).
///
/// Driven by [`BodyDecoder`](super::BodyDecoder), which owns the framing
/// decision and the two-phase finish; this type owns only the §7.1 states.
/// Reaching the end of the trailer section is reported through
/// [`is_complete`](Self::is_complete) rather than by emitting `Finished`, so
/// every framing this core decodes finishes through the same shell.
///
/// An `H1Error` from [`feed`](Self::feed) is terminal for the connection, and
/// the decoder does not latch it: every rule here is a function of the state
/// and the bytes offered, so a caller that feeds the same bytes again is
/// answered the same way rather than being told something new.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct Decoder {
  stage: Stage,
}

impl Decoder {
  /// Builds a decoder positioned at the first chunk-size line.
  pub(super) const fn new() -> Self {
    Self { stage: Stage::Size }
  }

  /// Whether the trailer section's final CRLF has been consumed — the body's
  /// last octet, after which nothing in the stream belongs to this message.
  pub(super) const fn is_complete(&self) -> bool {
    matches!(self.stage, Stage::Complete)
  }

  /// Decodes what it can from `input`, returning how many leading octets the
  /// body claimed and at most one item.
  ///
  /// `(0, None)` means no progress is possible from these bytes and more input
  /// is needed; a positive count with no item is progress the caller should
  /// keep pumping on (a chunk-size line consumed, a chunk's trailing CRLF), and
  /// is not an end of anything.
  pub(super) fn feed<'a>(
    &mut self,
    input: &'a [u8],
  ) -> Result<(usize, Option<BodyItem<'a>>), H1Error> {
    match self.stage {
      Stage::Size => self.read_size_line(input),
      Stage::Data(remaining) => Ok(self.read_data(remaining, input)),
      Stage::DataCrlf => self.read_data_crlf(input),
      Stage::Trailers { bytes, lines } => self.read_trailer_line(bytes, lines, input),
      // The shell turns a complete sub-machine into `State::Complete` on the
      // same call, so this arm is only reached by a caller pumping a decoder it
      // already owns no bytes of.
      Stage::Complete => Ok((0, None)),
    }
  }

  /// Reads `chunk-size [ chunk-ext ] CRLF` (RFC 9112 §7.1).
  ///
  /// The whole line is decided at once or not at all: a size without the CRLF
  /// that ends its line is a length the next read could still change, and
  /// acting on it is how two recipients end up disagreeing about where the
  /// chunk-data begins (§11.2).
  fn read_size_line<'a>(
    &mut self,
    input: &'a [u8],
  ) -> Result<(usize, Option<BodyItem<'a>>), H1Error> {
    let (line, end) = match delimit_line(input) {
      LineEnd::Crlf { body, end } => (body, end),
      // Nothing is proven yet — unless what has arrived is already longer than
      // any chunk-size line this core will read, in which case no continuation
      // can rescue it and waiting would be an unbounded buffer the peer
      // controls.
      LineEnd::Partial if unterminated_len(input) > MAX_CHUNK_LINE_BYTES => {
        return Err(malformed(MAX_CHUNK_LINE_BYTES, CHUNK_LINE_TOO_LONG));
      }
      LineEnd::Partial => return Ok((0, None)),
      LineEnd::Bare(at) => return Err(malformed(at, BARE_CR_OR_LF)),
    };
    if line.len() > MAX_CHUNK_LINE_BYTES {
      return Err(malformed(MAX_CHUNK_LINE_BYTES, CHUNK_LINE_TOO_LONG));
    }

    let (size, digits) = parse_chunk_size(line)?;
    // Everything past the digits is `chunk-ext`: bounded, parsed, and then
    // dropped. The line begins at `input`'s first byte, so an offset within it
    // is already an offset within the fed slice.
    let ext = line.get(digits..).unwrap_or_default();
    if ext.len() > MAX_CHUNK_EXT_BYTES {
      return Err(malformed(
        digits.saturating_add(MAX_CHUNK_EXT_BYTES),
        CHUNK_EXT_TOO_LONG,
      ));
    }
    validate_chunk_ext(ext, digits)?;

    // RFC 9112 §7.1: `last-chunk = 1*("0") [ chunk-ext ] CRLF` — a chunk-size
    // of zero IS the last chunk however many digits spelled it, and what
    // follows is the trailer section rather than chunk-data.
    match size {
      0 => {
        self.stage = Stage::Trailers { bytes: 0, lines: 0 };
        Ok((end, Some(BodyItem::TrailersStart)))
      }
      remaining => {
        self.stage = Stage::Data(remaining);
        Ok((end, None))
      }
    }
  }

  /// Reads `chunk-data`: the announced octets and not one more, however many
  /// the caller offers.
  fn read_data<'a>(&mut self, remaining: u64, input: &'a [u8]) -> (usize, Option<BodyItem<'a>>) {
    let Some((claimed, left)) = claim(remaining, input) else {
      return (0, None);
    };
    self.stage = match left {
      0 => Stage::DataCrlf,
      left => Stage::Data(left),
    };
    (claimed.len(), Some(BodyItem::Data(claimed)))
  }

  /// Reads the CRLF that RFC 9112 §7.1 puts after every chunk's data.
  ///
  /// Not decoration: it is the only thing separating a chunk's last octet from
  /// the next chunk's size, so a chunk whose length lied about its data is
  /// caught exactly here.
  fn read_data_crlf<'a>(
    &mut self,
    input: &'a [u8],
  ) -> Result<(usize, Option<BodyItem<'a>>), H1Error> {
    match input {
      // A lone CR is inconclusive: its LF may be in the next read (§2.2).
      [] | [b'\r'] => Ok((0, None)),
      [b'\r', b'\n', ..] => {
        self.stage = Stage::Size;
        Ok((2, None))
      }
      [b'\r', ..] => Err(malformed(1, CHUNK_DATA_CRLF)),
      _ => Err(malformed(0, CHUNK_DATA_CRLF)),
    }
  }

  /// Reads one line of the RFC 9112 §7.1.2 trailer section: a field line to
  /// emit, or the empty line that ends the section and the body with it.
  fn read_trailer_line<'a>(
    &mut self,
    bytes: usize,
    lines: usize,
    input: &'a [u8],
  ) -> Result<(usize, Option<BodyItem<'a>>), H1Error> {
    let (body, end) = match delimit_line(input) {
      LineEnd::Crlf { body, end } => (body, end),
      // The section is bounded whether or not its lines terminate, so a peer
      // cannot hold the connection open by never closing one. Measured the same
      // way the chunk-size line's budget is — the terminator's first byte is
      // not line content — so where a read split cannot decide the answer.
      LineEnd::Partial if bytes.saturating_add(unterminated_len(input)) > MAX_HEAD_BYTES => {
        return Err(H1Error::HeadTooLarge(MAX_HEAD_BYTES));
      }
      LineEnd::Partial => return Ok((0, None)),
      LineEnd::Bare(at) => return Err(malformed(at, BARE_CR_OR_LF)),
    };
    let bytes = bytes.saturating_add(end);
    if bytes > MAX_HEAD_BYTES {
      return Err(H1Error::HeadTooLarge(MAX_HEAD_BYTES));
    }

    // The empty line closes the trailer section, and it is the body's last
    // octet: `chunked-body = *chunk last-chunk trailer-section CRLF`.
    if body.is_empty() {
      self.stage = Stage::Complete;
      return Ok((end, None));
    }

    let lines = lines.saturating_add(1);
    if lines > MAX_HEADERS {
      return Err(H1Error::TooManyHeaders(MAX_HEADERS));
    }
    // Offset 0: in this stage the fed slice begins at the line, so the shared
    // validator's absolute offsets are already relative to the input. `false`
    // because a trailer section has no start-line, which leaves §5.2 obs-fold
    // as the only reading of a line that opens with whitespace.
    let field = validate_field_line(body, 0, false)?;
    // A validated field name is a `token` (RFC 9110 §5.6.2) and therefore
    // ASCII, so this cannot fail; it is answered rather than unwrapped, since
    // nothing in this core may panic on wire data.
    let Ok(name) = core::str::from_utf8(field.name) else {
      return Err(malformed(0, "trailer field name is not a token"));
    };

    self.stage = Stage::Trailers { bytes, lines };
    Ok((
      end,
      Some(BodyItem::TrailerField {
        name,
        value: field.value,
      }),
    ))
  }
}

/// Where a decoder stands within a chunked body (RFC 9112 §7.1).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Stage {
  /// Reading a `chunk-size [ chunk-ext ] CRLF` line.
  Size,
  /// Reading `chunk-data`: this many octets of the current chunk are still
  /// owed. Never zero — a chunk that runs out becomes `DataCrlf`.
  Data(u64),
  /// Reading the CRLF that terminates `chunk-data`.
  DataCrlf,
  /// Reading the §7.1.2 trailer section, with what it has spent of the field
  /// section's caps.
  Trailers {
    /// Trailer-section octets consumed so far, against `MAX_HEAD_BYTES`.
    bytes: usize,
    /// Trailer field lines seen so far, against `MAX_HEADERS`.
    lines: usize,
  },
  /// The trailer section's final CRLF has been consumed.
  Complete,
}

/// Reads `chunk-size = 1*HEXDIG` (RFC 9112 §7.1) off the front of a chunk-size
/// line, returning its value and how many digits spelled it.
///
/// Hex and nothing else: no sign, no `0x`, no leading whitespace, no trailing
/// one. Every byte this refuses is a byte some other parser might have read as
/// part of a length, and a length two recipients read differently is the §11.2
/// smuggling primitive itself.
///
/// The accumulation is checked rather than wrapping. A chunk-size is a u64 here
/// exactly as a `Content-Length` is (RFC 9110 §8.6); seventeen significant hex
/// digits do not fit one, and a wrap would turn an absurd announced length into
/// a small plausible one.
// `pub(crate)` for the link-time panic test only (`crate::__no_panic_internals`
// forwards it): this is the leaf of the chunk-size path, and the stage that
// calls it advances decoder state, which a `#[no_panic]` shim cannot be wrapped
// around. `read_size_line` above remains its only production caller.
pub(crate) fn parse_chunk_size(line: &[u8]) -> Result<(u64, usize), H1Error> {
  let mut size = 0u64;
  let mut digits = 0usize;
  for (offset, &byte) in line.iter().enumerate() {
    let Some(value) = hex_value(byte) else {
      break;
    };
    let Some(next) = size.checked_mul(16).and_then(|s| s.checked_add(value)) else {
      return Err(malformed(offset, "chunk-size does not fit in 64 bits"));
    };
    size = next;
    digits = offset.saturating_add(1);
  }
  // `1*HEXDIG`: no digit at all is a missing size, not a zero-length chunk.
  if digits == 0 {
    return Err(malformed(0, "chunk-size is not a hexadecimal number"));
  }
  Ok((size, digits))
}

/// The value of one `HEXDIG` (RFC 5234 core rule; ABNF literals are
/// case-insensitive, so both cases count), or `None` for a byte that is not one.
fn hex_value(byte: u8) -> Option<u64> {
  // Each arm bounds its own subtraction, so the wrapping forms are exact here;
  // they stand in for the plain operators the crate denies.
  match byte {
    b'0'..=b'9' => Some(u64::from(byte.wrapping_sub(b'0'))),
    b'a'..=b'f' => Some(u64::from(byte.wrapping_sub(b'a').wrapping_add(10))),
    b'A'..=b'F' => Some(u64::from(byte.wrapping_sub(b'A').wrapping_add(10))),
    _ => None,
  }
}

/// Validates `chunk-ext` (RFC 9112 §7.1.1):
/// `*( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )`, with
/// `chunk-ext-name = token` and `chunk-ext-val = token / quoted-string`.
///
/// The extensions are IGNORED — no recipient is required to understand any of
/// them — but they are parsed all the same, because bytes a recipient skipped
/// without reading are bytes it cannot claim to have delimited: a quoted-string
/// holding a `;` reads as ext to one parser and as structure to another.
///
/// The `BWS` is real: RFC 9110 §5.6.3 defines it as `OWS` that senders must not
/// generate and recipients must parse, and §7.1.1 puts it around the `;`, the
/// name, and the `=`. It appears nowhere ELSE, which is what makes `5 CRLF` — a
/// space with no `;` behind it — a violation rather than an extension: that
/// whitespace has no repetition to belong to.
///
/// `at` rebases every offset onto the fed slice.
fn validate_chunk_ext(ext: &[u8], at: usize) -> Result<(), H1Error> {
  let mut cursor = 0usize;
  loop {
    let before_bws = cursor;
    cursor = skip_bws(ext, cursor);
    if cursor >= ext.len() {
      return if cursor == before_bws {
        Ok(())
      } else {
        Err(malformed(
          at.saturating_add(before_bws),
          "whitespace after the chunk-size",
        ))
      };
    }
    if ext.get(cursor) != Some(&b';') {
      return Err(malformed(
        at.saturating_add(cursor),
        "expected \";\" before a chunk extension",
      ));
    }

    cursor = skip_bws(ext, cursor.saturating_add(1));
    let name_end = token_end(ext, cursor);
    // `token = 1*tchar` (RFC 9110 §5.6.2): an extension with no name is not an
    // empty extension, it is a `;` that means nothing.
    if name_end == cursor {
      return Err(malformed(
        at.saturating_add(cursor),
        "chunk extension name is not a token",
      ));
    }
    cursor = name_end;

    // The optional `= value`. Without one, `cursor` stays at the end of the
    // name and the next round's BWS skip walks whatever follows — which is
    // legal only if it leads to another `;`.
    let after_name = skip_bws(ext, cursor);
    if ext.get(after_name) == Some(&b'=') {
      let value_at = skip_bws(ext, after_name.saturating_add(1));
      match chunk_ext_value_end(ext, value_at) {
        Ok(value_end) => cursor = value_end,
        Err(offset) => {
          return Err(malformed(
            at.saturating_add(offset),
            "chunk extension value is not a token or quoted-string",
          ));
        }
      }
    }
  }
}

/// Walks one `chunk-ext-val = token / quoted-string` (RFC 9112 §7.1.1),
/// returning the offset just past it or the offset of the byte that broke it.
fn chunk_ext_value_end(ext: &[u8], from: usize) -> Result<usize, usize> {
  if ext.get(from) == Some(&b'"') {
    return quoted_string_end(ext, from);
  }
  let end = token_end(ext, from);
  if end == from { Err(from) } else { Ok(end) }
}

/// Walks a `quoted-string` (RFC 9110 §5.6.4:
/// `DQUOTE *( qdtext / quoted-pair ) DQUOTE`) from its opening DQUOTE at
/// `from`, returning the offset just past its closing one.
///
/// The escape is why this is a walk and not a search for the next DQUOTE: in
/// `"a\"b"` the middle quote is content, and a recipient that ended the string
/// there would read the rest of the extension as structure.
fn quoted_string_end(ext: &[u8], from: usize) -> Result<usize, usize> {
  let mut cursor = from.saturating_add(1);
  while let Some(&byte) = ext.get(cursor) {
    match byte {
      b'"' => return Ok(cursor.saturating_add(1)),
      b'\\' => {
        // `quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )`: the backslash
        // takes exactly one byte with it, and not every byte may be taken.
        let escaped_at = cursor.saturating_add(1);
        let Some(&escaped) = ext.get(escaped_at) else {
          return Err(cursor);
        };
        if !is_quoted_pair_byte(escaped) {
          return Err(escaped_at);
        }
        cursor = escaped_at.saturating_add(1);
      }
      _ if is_qdtext(byte) => cursor = cursor.saturating_add(1),
      _ => return Err(cursor),
    }
  }
  // Ran out of line inside the string. The chunk-size line is complete by the
  // time its extensions are read, so this is an unterminated quoted-string and
  // never a short read.
  Err(cursor)
}

/// RFC 9110 §5.6.4 `qdtext`: what may stand for itself inside a quoted-string —
/// the escapable byte set minus the two bytes that would end or escape it.
const fn is_qdtext(byte: u8) -> bool {
  is_quoted_pair_byte(byte) && byte != b'"' && byte != b'\\'
}

/// The byte a `quoted-pair` may escape (RFC 9110 §5.6.4):
/// `HTAB / SP / VCHAR / obs-text`. CTLs are not in it, so a CR or LF cannot be
/// smuggled into a chunk-size line behind a backslash.
const fn is_quoted_pair_byte(byte: u8) -> bool {
  is_field_vchar(byte) || byte == b' ' || byte == b'\t'
}

/// Offset just past the `token` (RFC 9110 §5.6.2) beginning at `from`; equal to
/// `from` when there is no token there at all.
fn token_end(bytes: &[u8], from: usize) -> usize {
  let rest = bytes.get(from..).unwrap_or_default();
  let run = rest
    .iter()
    .position(|&byte| !is_token_byte(byte))
    .unwrap_or(rest.len());
  from.saturating_add(run)
}

/// How much LINE an unterminated read holds — what
/// [`LineEnd::Crlf`]`::body` would measure if the terminator arrived.
///
/// A `Partial` slice ends in a lone CR or in no CR at all (RFC 9112 §2.2), and
/// that CR is not line content: it is the first byte of a terminator whose LF
/// has not arrived. Counting it against a line budget would make the SAME byte
/// stream decode or fail depending on where the transport split it — a line of
/// exactly the budget passing when its CRLF lands in one read and failing when
/// the CR and the LF land in two. Splits are the transport's choice and never
/// the protocol's, so the byte the terminator may own is discounted here and
/// the budget is spent on line content alone, exactly as the terminated check
/// spends it.
fn unterminated_len(input: &[u8]) -> usize {
  input
    .len()
    .saturating_sub(usize::from(input.last() == Some(&b'\r')))
}

/// Offset of the first byte past the `BWS` (RFC 9110 §5.6.3: `BWS = OWS`, i.e.
/// SP and HTAB) beginning at `from`.
fn skip_bws(bytes: &[u8], from: usize) -> usize {
  let rest = bytes.get(from..).unwrap_or_default();
  let run = rest
    .iter()
    .position(|&byte| byte != b' ' && byte != b'\t')
    .unwrap_or(rest.len());
  from.saturating_add(run)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{body::BodyDecoder, validate::BodyFraming};

  /// The two-chunk body every split pin below is cut apart at.
  const TWO_CHUNKS: &[u8] = b"4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n";

  // RFC 9112 §7.1 with §2.2: a chunked body's framing lines end at CRLF and
  // nowhere else, so a decoder that has not yet seen one asks for more input
  // rather than deciding — INCLUDING when what it holds ends in a lone CR,
  // whose LF may be in the next read (the split-CRLF rule at chunk-line
  // granularity). Nothing is consumed while nothing is decided: the partial
  // line stays in the caller's buffer, since this decoder never buffers.
  #[test]
  fn a_partial_chunk_line_asks_for_more_and_consumes_nothing() {
    for n in 0..TWO_CHUNKS.len() {
      let mut d = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
      let mut at = 0usize;
      // Pump the prefix dry; whatever it could not decide must end in
      // need-more-input, never in a violation.
      loop {
        let rest = TWO_CHUNKS.get(..n).and_then(|p| p.get(at..)).unwrap_or(b"");
        let (consumed, item) = match d.feed(rest) {
          Ok(step) => step,
          Err(e) => panic!("prefix {n} rejected: {e:?}"),
        };
        at = at.saturating_add(consumed);
        if consumed == 0 && item.is_none() {
          break;
        }
      }
      assert!(!d.is_finished(), "prefix {n} finished early");
    }
    // The lone-CR cases spelled out, one per line the body has.
    let mut size = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert_eq!(size.feed(b"4\r").unwrap(), (0, None));
    let mut data = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert_eq!(data.feed(b"4\r\n").unwrap(), (3, None));
    assert_eq!(
      data.feed(b"wiki").unwrap(),
      (4, Some(BodyItem::Data(b"wiki")))
    );
    assert_eq!(data.feed(b"\r").unwrap(), (0, None));
    assert_eq!(data.feed(b"\r\n").unwrap(), (2, None));
  }

  // RFC 9112 §7.1 / §7.1.2: the item stream of a chunked body, in order — the
  // chunk-size line consumes bytes and yields nothing, chunk-data is `Data`,
  // the last chunk opens the trailer section exactly once, and the empty line
  // that closes it puts the body on the shell's two-phase finish, so `Finished`
  // arrives on the following call and nothing is claimed after it.
  #[test]
  fn emits_data_then_trailers_then_finished() {
    let mut d = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert_eq!(d.feed(b"2;a=b\r\n").unwrap(), (7, None));
    assert_eq!(d.feed(b"hi").unwrap(), (2, Some(BodyItem::Data(b"hi"))));
    assert_eq!(d.feed(b"\r\n").unwrap(), (2, None));
    assert_eq!(
      d.feed(b"0\r\n").unwrap(),
      (3, Some(BodyItem::TrailersStart))
    );
    assert_eq!(
      d.feed(b"X-Sum: ok\r\n").unwrap(),
      (
        11,
        Some(BodyItem::TrailerField {
          name: "X-Sum",
          value: b"ok",
        })
      )
    );
    assert!(!d.is_finished());
    assert_eq!(d.feed(b"\r\nNEXT").unwrap(), (2, None));
    // The body's last octet is gone, so the bytes behind it are the next
    // message's and the decoder claims none of them.
    assert!(d.is_finished());
    assert_eq!(d.feed(b"NEXT").unwrap(), (0, Some(BodyItem::Finished)));
    assert_eq!(d.feed(b"NEXT").unwrap(), (0, None));
    assert_eq!(d.eof().unwrap(), None);
  }

  // RFC 9112 §7.1: the framing violations that make chunked a smuggling
  // primitive (§11.2) — a size that is not hex, chunk-data not followed by its
  // CRLF, and a bare LF standing in for a line terminator.
  #[test]
  fn rejects_chunk_framing_violations_without_a_heap() {
    let mut hex = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert!(hex.feed(b"zz\r\nhello\r\n").is_err());

    let mut crlf = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert_eq!(crlf.feed(b"5\r\n").unwrap(), (3, None));
    assert_eq!(
      crlf.feed(b"helloXX").unwrap(),
      (5, Some(BodyItem::Data(b"hello")))
    );
    assert!(crlf.feed(b"XX").is_err());

    let mut lf = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert!(lf.feed(b"5\nhello\r\n").is_err());

    // RFC 9112 §6.3: a close before the chunked body's last chunk is a
    // truncated message, not a body that merely ended.
    let mut cut = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert_eq!(cut.feed(b"5\r\n").unwrap(), (3, None));
    assert!(cut.eof().is_err());
  }

  // RFC 9112 §7.1: `chunk-data` is `1*OCTET` counted by the chunk-size, so it
  // is delimited by that count and by nothing in its own bytes. A body whose
  // payload happens to contain CRLF — any binary payload eventually does — must
  // survive intact, and the CRLF that ends the chunk is the one the count lands
  // on and not the first one seen.
  #[test]
  fn chunk_data_is_counted_not_line_delimited() {
    let mut d = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert_eq!(d.feed(b"6\r\n").unwrap(), (3, None));
    assert_eq!(
      d.feed(b"a\r\n\r\nb\r\n0\r\n\r\n").unwrap(),
      (6, Some(BodyItem::Data(b"a\r\n\r\nb")))
    );
    assert_eq!(d.feed(b"\r\n0\r\n\r\n").unwrap(), (2, None));
    assert_eq!(
      d.feed(b"0\r\n\r\n").unwrap(),
      (3, Some(BodyItem::TrailersStart))
    );
    assert_eq!(d.feed(b"\r\n").unwrap(), (2, None));
    assert!(d.is_finished());
  }

  // RFC 9112 §7.1 reads `chunk-size` as `1*HEXDIG`, and ABNF literals are
  // case-insensitive (RFC 5234 §2.3), so `a` and `A` are the same size — and
  // RFC 9110 §5.5's `field-value = *field-content` makes an empty trailer value
  // legal, in the trailer section exactly as in a head.
  #[test]
  fn hex_case_and_empty_trailer_values() {
    let mut lower = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert_eq!(lower.feed(b"a\r\n").unwrap(), (3, None));
    assert_eq!(
      lower.feed(b"0123456789\r\n").unwrap(),
      (10, Some(BodyItem::Data(b"0123456789")))
    );

    let mut upper = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert_eq!(upper.feed(b"A\r\n").unwrap(), (3, None));
    assert_eq!(
      upper.feed(b"0123456789\r\n").unwrap(),
      (10, Some(BodyItem::Data(b"0123456789")))
    );

    let mut empty = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    assert_eq!(
      empty.feed(b"0\r\n").unwrap(),
      (3, Some(BodyItem::TrailersStart))
    );
    assert_eq!(
      empty.feed(b"X-Sum:\r\n").unwrap(),
      (
        8,
        Some(BodyItem::TrailerField {
          name: "X-Sum",
          value: b"",
        })
      )
    );
    assert_eq!(empty.feed(b"\r\n").unwrap(), (2, None));
    assert!(empty.is_finished());
  }
}

#[cfg(all(test, any(feature = "std", feature = "alloc", feature = "no-atomic")))]
mod heap_tests {
  use super::*;
  use crate::{
    body::{BodyDecoder, BodyFault},
    validate::BodyFraming,
  };

  /// Everything one decode of a chunked body produced, in wire order.
  #[derive(Debug, Default)]
  struct Decoded {
    /// The chunk-data octets, concatenated.
    data: std::vec::Vec<u8>,
    /// Whether the §7.1.2 trailer section was announced.
    trailers_start: bool,
    /// The trailer field lines, in the order they arrived.
    trailers: std::vec::Vec<(std::string::String, std::vec::Vec<u8>)>,
    /// Whether the `Finished` item arrived.
    finished: bool,
  }

  /// Feeds `chunks` in order through a real `BodyDecoder`, exactly as a
  /// connection's receive path would: bytes accumulate in the CALLER's buffer,
  /// `feed` is pumped until it reports no progress, and whatever it did not
  /// consume stays buffered for the next read — this decoder never buffers.
  // `BodyFault` rather than `H1Error`: the shell's `feed` reports both a wire
  // violation and a policy refusal now, and these fixtures drive the shell.
  // Every stream here runs against an unbounded ceiling, so a `TooLarge` from
  // one would itself be a finding.
  fn decode(chunks: &[&[u8]]) -> Result<Decoded, BodyFault> {
    let mut decoder = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
    let mut out = Decoded::default();
    let mut buf = std::vec::Vec::new();
    for chunk in chunks {
      buf.extend_from_slice(chunk);
      let mut at = 0usize;
      loop {
        let (consumed, item) = decoder.feed(buf.get(at..).unwrap_or_default())?;
        match item {
          Some(BodyItem::Data(payload)) => {
            assert!(!payload.is_empty(), "an empty Data item was emitted");
            out.data.extend_from_slice(payload);
          }
          Some(BodyItem::TrailersStart) => {
            assert!(!out.trailers_start, "TrailersStart emitted twice");
            out.trailers_start = true;
          }
          Some(BodyItem::TrailerField { name, value }) => {
            assert!(out.trailers_start, "TrailerField before TrailersStart");
            out
              .trailers
              .push((std::string::String::from(name), value.to_vec()));
          }
          Some(BodyItem::Finished) => {
            assert!(!out.finished, "Finished emitted twice");
            out.finished = true;
          }
          None => {}
        }
        at = at.saturating_add(consumed);
        if consumed == 0 && item.is_none() {
          break;
        }
      }
      buf.drain(..at);
    }
    Ok(out)
  }

  /// Test driver: the decoded octets and whether the trailer section was
  /// announced.
  fn run(chunks: &[&[u8]]) -> Result<(std::vec::Vec<u8>, bool), BodyFault> {
    let decoded = decode(chunks)?;
    Ok((decoded.data, decoded.trailers_start))
  }

  /// Decodes `whole` entire and again at EVERY interior cut, asserting all of
  /// them produced the same items, and returns what they produced.
  ///
  /// Where a read ends is the transport's choice and never the sender's, so a
  /// cut that changes the answer is a decoder two peers can be made to disagree
  /// with (RFC 9112 §11.2) — the property this whole module is built to hold.
  fn decoded_at_every_cut(whole: &[u8]) -> Decoded {
    let entire = decode(&[whole]).expect("the whole stream");
    for cut in 1..whole.len() {
      let (head, tail) = whole.split_at(cut);
      let split = match decode(&[head, tail]) {
        Ok(split) => split,
        Err(e) => panic!("cut {cut} rejected: {e:?}"),
      };
      assert_eq!(split.data, entire.data, "cut {cut}");
      assert_eq!(split.trailers, entire.trailers, "cut {cut}");
      assert_eq!(split.trailers_start, entire.trailers_start, "cut {cut}");
      assert_eq!(split.finished, entire.finished, "cut {cut}");
    }
    entire
  }

  /// The refusing half of the same property: a stream this core will not decode
  /// is refused entire AND at every interior cut.
  fn rejected_at_every_cut(whole: &[u8]) {
    assert!(decode(&[whole]).is_err(), "the whole stream was accepted");
    for cut in 1..whole.len() {
      let (head, tail) = whole.split_at(cut);
      assert!(decode(&[head, tail]).is_err(), "cut {cut} was accepted");
    }
  }

  // RFC 9112 §7.1: `chunked-body = *chunk last-chunk trailer-section CRLF`, so
  // a one-chunk body decodes to its chunk-data and its last chunk opens the
  // trailer section even when no trailer field follows.
  #[test]
  fn decodes_simple_chunked() {
    let (data, trailers) = run(&[b"5\r\nhello\r\n0\r\n\r\n"]).unwrap();
    assert_eq!(data, b"hello");
    assert!(trailers);
  }

  // RFC 9112 §7.1 with §2.2: the transport chooses where a read ends and the
  // protocol does not, so EVERY cut through a chunked body has to decode to the
  // same octets — a decoder that decided anything from a boundary the sender
  // never chose is the §11.2 divergence.
  #[test]
  fn decodes_across_arbitrary_splits() {
    let whole = b"4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n";
    for cut in 1..whole.len() {
      let (data, _) = run(&[&whole[..cut], &whole[cut..]]).unwrap();
      assert_eq!(data, b"wikipedia", "cut {cut}");
    }
  }

  // RFC 9112 §7.1.1: `chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS
  // chunk-ext-val ] )`, `chunk-ext-val = token / quoted-string`. No recipient
  // has to understand an extension, but one that skipped its bytes unparsed
  // would be trusting the sender about where the chunk-size line ends.
  #[test]
  fn chunk_ext_ignored_but_validated_and_bounded() {
    let (data, _) = run(&[b"5;name=value;x=\"q s\"\r\nhello\r\n0\r\n\r\n"]).unwrap();
    assert_eq!(data, b"hello");
    assert!(run(&[b"5;bad ext\r\nhello\r\n0\r\n\r\n"]).is_err()); // SP in ext
    let long_ext = std::format!("5;x={}\r\nhello\r\n0\r\n\r\n", "a".repeat(300));
    assert!(run(&[long_ext.as_bytes()]).is_err()); // > 256
  }

  // RFC 9112 §7.1: `chunk-size = 1*HEXDIG` and every terminator is a CRLF;
  // §11.2 is why each of these is refused rather than repaired.
  #[test]
  fn rejects_chunk_framing_violations() {
    assert!(run(&[b"zz\r\nhello\r\n0\r\n\r\n"]).is_err()); // non-hex
    assert!(run(&[b"5\r\nhelloXX"]).is_err()); // missing data CRLF
    assert!(run(&[b"5\nhello\r\n0\r\n\r\n"]).is_err()); // bare LF
    assert!(run(&[b"FFFFFFFFFFFFFFFFF\r\n"]).is_err()); // u64 overflow (17 hex digits)
  }

  // RFC 9112 §7.1.2: the trailer section is a field section, so its lines are
  // validated as field lines are — and they are EMITTED, because a trailer the
  // recipient parsed and dropped is a field the connection layer can never
  // forward.
  #[test]
  fn trailer_lines_validated_and_emitted() {
    // Valid trailer passes AND surfaces as TrailerField; ws-before-colon rejected.
    assert!(run(&[b"1\r\na\r\n0\r\nX-Sum: ok\r\n\r\n"]).is_ok());
    assert!(run(&[b"1\r\na\r\n0\r\nX-Sum : ok\r\n\r\n"]).is_err());
  }

  // 9112 §7.1 edge grammar: multi-zero last-chunk valid; SP after chunk-size invalid.
  #[test]
  fn last_chunk_and_whitespace_edges() {
    assert!(run(&[b"1\r\na\r\n00\r\n\r\n"]).is_ok());
    assert!(run(&[b"1\r\na\r\n000\r\n\r\n"]).is_ok());
    assert!(run(&[b"5 \r\nhello\r\n0\r\n\r\n"]).is_err());
    assert!(run(&[b"1\r\na\r\n0 \r\n\r\n"]).is_err());
  }

  // RFC 9112 §7.1.2 with RFC 9110 §6.5: trailer fields reach the caller in the
  // order the sender wrote them, and they are trailer fields and nothing else —
  // a `Content-Length` after the last chunk cannot re-frame a body the chunked
  // coding already delimited (RFC 9112 §6.3 item 3), so it surfaces as a plain
  // field with no effect on the framing at all.
  #[test]
  fn trailer_fields_surface_in_wire_order_and_never_reframe() {
    let decoded = decode(&[b"1\r\na\r\n0\r\nContent-Length: 99\r\nX-Sum: ok\r\n\r\n"]).unwrap();
    assert_eq!(decoded.data, b"a");
    assert!(decoded.trailers_start);
    assert!(decoded.finished);
    assert_eq!(
      decoded.trailers,
      std::vec::Vec::from([
        (
          std::string::String::from("Content-Length"),
          std::vec::Vec::from(b"99".as_slice())
        ),
        (
          std::string::String::from("X-Sum"),
          std::vec::Vec::from(b"ok".as_slice())
        ),
      ])
    );

    // RFC 9112 §5.2 (obs-fold) and §5.1 (whitespace before the colon) apply to
    // a trailer line exactly as they do to a head's field line. A trailer
    // section has no start-line, so the FIRST line folding is obs-fold too.
    assert!(decode(&[b"0\r\n X-Sum: ok\r\n\r\n"]).is_err());
    assert!(decode(&[b"0\r\nX-Sum: ok\r\n b\r\n\r\n"]).is_err());
    assert!(decode(&[b"0\r\n: ok\r\n\r\n"]).is_err());
    assert!(decode(&[b"0\r\nX-Sum\r\n\r\n"]).is_err());
    assert!(decode(&[b"0\r\nX-Sum: o\x00k\r\n\r\n"]).is_err());
  }

  // RFC 9110 §5.6.4 `quoted-string` inside RFC 9112 §7.1.1's `chunk-ext-val`:
  // the delimiters a quoted-string HIDES are the reason the extensions are
  // parsed at all. A `;` between quotes is content, not the start of another
  // extension, and a `\"` escape keeps the string open past a quote — a
  // recipient that scanned for the next `;` or the next `"` would cut this line
  // somewhere the sender did not.
  #[test]
  fn a_quoted_chunk_ext_value_hides_its_delimiters() {
    assert_eq!(
      run(&[b"1;a=\"x;y\"\r\nq\r\n0\r\n\r\n"]).unwrap().0,
      b"q" // the `;` is inside the string
    );
    assert_eq!(
      run(&[b"1;a=\"x\\\"y\";b=c\r\nq\r\n0\r\n\r\n"]).unwrap().0,
      b"q" // the escaped quote does not end it
    );
    assert_eq!(run(&[b"1;a=\"\";b\r\nq\r\n0\r\n\r\n"]).unwrap().0, b"q");
    // An unterminated string, an unescapable byte behind the backslash, and a
    // `;` with no name behind it: each is a line this core will not delimit.
    assert!(run(&[b"1;a=\"xy\r\nq\r\n0\r\n\r\n"]).is_err());
    assert!(run(&[b"1;a=\"x\\\x00y\"\r\nq\r\n0\r\n\r\n"]).is_err());
    assert!(run(&[b"1;\r\nq\r\n0\r\n\r\n"]).is_err());
    assert!(run(&[b"1;a=b;\r\nq\r\n0\r\n\r\n"]).is_err());
    assert!(run(&[b"1;a=\r\nq\r\n0\r\n\r\n"]).is_err());
  }

  // RFC 9112 §7.1.1: the extension budget is a limit and not a budget one byte
  // short, so an ext of exactly `MAX_CHUNK_EXT_BYTES` is decoded and one byte
  // more is refused.
  #[test]
  fn the_chunk_ext_bound_is_exactly_max_chunk_ext_bytes() {
    // `;x=` is three of the ext's own bytes, so `n` fills the rest of the cap.
    let ext = |n: usize| std::format!("1;x={}\r\na\r\n0\r\n\r\n", "y".repeat(n));
    assert_eq!(
      run(&[ext(MAX_CHUNK_EXT_BYTES - 3).as_bytes()]).unwrap().0,
      b"a"
    );
    assert!(run(&[ext(MAX_CHUNK_EXT_BYTES - 2).as_bytes()]).is_err());
    // `last-chunk = 1*("0") [ chunk-ext ] CRLF`: the LAST chunk may carry
    // extensions too, and they are parsed and dropped like any other's.
    assert!(run(&[b"0;x=y\r\n\r\n"]).unwrap().1);
  }

  // RFC 9112 §7.1 with §2.2: the chunk-size line's budget must be spent on line
  // CONTENT, because a `Partial` read ends in a lone CR that may be the first
  // byte of the terminator rather than a byte of the line. Counting that CR
  // would make a line of exactly the budget decode when its CRLF arrives in one
  // read and fail when the CR and the LF arrive in two — the same bytes, a
  // different answer, chosen by the transport. Probed at the boundary in both
  // shapes, since one byte either side is where such an error hides.
  #[test]
  fn the_chunk_line_cap_is_split_stable_at_its_boundary() {
    // A line of exactly the budget: `1*("0")` is a legal last-chunk however
    // many zeros spell it, so this decodes and opens the trailer section.
    let at_cap = std::format!("{}\r\n\r\n", "0".repeat(MAX_CHUNK_LINE_BYTES));
    assert!(decoded_at_every_cut(at_cap.as_bytes()).trailers_start);
    // The cut the accounting turns on, named outright: between the CR and its
    // LF, where the pending terminator byte is the whole difference.
    let (head, tail) = at_cap.as_bytes().split_at(MAX_CHUNK_LINE_BYTES + 1);
    assert_eq!(head.last(), Some(&b'\r'));
    assert!(run(&[head, tail]).unwrap().1);

    // The same budget spent the way the constant is actually built — the widest
    // `u64` plus a full extension — and it too must not depend on the split.
    let full = std::format!(
      "{};x={}\r\n\r\n",
      "0".repeat(MAX_CHUNK_SIZE_DIGITS),
      "y".repeat(MAX_CHUNK_EXT_BYTES - 3)
    );
    assert_eq!(full.len(), MAX_CHUNK_LINE_BYTES + 4);
    assert!(decoded_at_every_cut(full.as_bytes()).trailers_start);

    // One byte over is refused, and refused the same way at every cut.
    let over = std::format!("{}\r\n\r\n", "0".repeat(MAX_CHUNK_LINE_BYTES + 1));
    rejected_at_every_cut(over.as_bytes());
    let (head, tail) = over.as_bytes().split_at(MAX_CHUNK_LINE_BYTES + 2);
    assert_eq!(head.last(), Some(&b'\r'));
    assert!(run(&[head, tail]).is_err());
  }

  // RFC 9112 §7.1.2: the trailer section is read across reads like everything
  // else here — `Stage::Trailers` carries its byte and line counts from one
  // feed to the next — so a trailer stream must decode identically at every cut
  // too, not just the chunk stream the split test above covers.
  #[test]
  fn a_trailer_stream_decodes_identically_at_every_cut() {
    let decoded = decoded_at_every_cut(b"1\r\na\r\n0\r\nX-Sum: ok\r\nX-B: 2\r\n\r\n");
    assert_eq!(decoded.data, b"a");
    assert!(decoded.finished);
    assert_eq!(
      decoded.trailers,
      std::vec::Vec::from([
        (
          std::string::String::from("X-Sum"),
          std::vec::Vec::from(b"ok".as_slice())
        ),
        (
          std::string::String::from("X-B"),
          std::vec::Vec::from(b"2".as_slice())
        ),
      ])
    );
  }

  // RFC 9112 §7.1: `1*HEXDIG` admits unlimited leading zeros, which a decoder
  // that only guarded the VALUE would have to keep buffering. The line is
  // bounded too, and the bound is enforced before the CRLF arrives — otherwise
  // "need more input" is an unbounded allocation a peer controls.
  #[test]
  fn a_chunk_size_line_that_cannot_terminate_is_refused_not_awaited() {
    let padded = std::format!("{}5\r\na\r\n0\r\n\r\n", "0".repeat(400));
    assert!(run(&[padded.as_bytes()]).is_err());
    let unterminated = "0".repeat(400);
    assert!(run(&[unterminated.as_bytes()]).is_err());
    // Sixteen digits is `u64::MAX`'s own width, so a fully padded legal size
    // still decodes.
    assert_eq!(
      run(&[b"0000000000000001\r\na\r\n0\r\n\r\n"]).unwrap().0,
      b"a"
    );
  }

  // RFC 9110 §6.5: a trailer section IS a field section, so it answers to the
  // same caps a head's fields do — RFC 6585 §5's 431 for either.
  #[test]
  fn the_trailer_section_carries_the_field_section_caps() {
    let mut at_cap = std::vec::Vec::from(&b"0\r\n"[..]);
    for i in 0..MAX_HEADERS {
      at_cap.extend_from_slice(std::format!("H{i}: v\r\n").as_bytes());
    }
    at_cap.extend_from_slice(b"\r\n");
    assert_eq!(
      decode(&[at_cap.as_slice()]).unwrap().trailers.len(),
      MAX_HEADERS
    );

    let mut too_many = std::vec::Vec::from(&b"0\r\n"[..]);
    for i in 0..=MAX_HEADERS {
      too_many.extend_from_slice(std::format!("H{i}: v\r\n").as_bytes());
    }
    too_many.extend_from_slice(b"\r\n");
    assert!(matches!(
      run(&[too_many.as_slice()]),
      Err(BodyFault::Violation(H1Error::TooManyHeaders(_)))
    ));

    // Under the line cap but over the byte cap: the two bounds are independent.
    let mut too_big = std::vec::Vec::from(&b"0\r\n"[..]);
    for i in 0..MAX_HEADERS {
      too_big.extend_from_slice(std::format!("H{i}: {}\r\n", "v".repeat(300)).as_bytes());
    }
    too_big.extend_from_slice(b"\r\n");
    assert!(too_big.len() > MAX_HEAD_BYTES);
    assert!(matches!(
      run(&[too_big.as_slice()]),
      Err(BodyFault::Violation(H1Error::HeadTooLarge(_)))
    ));
  }

  // RFC 9112 §6.3 item 6 read through §7.1: a chunked body ends at its trailer
  // section's empty line and nowhere else, so a close anywhere before that
  // truncates the message — including between the last chunk and the trailer
  // section it opened.
  #[test]
  fn eof_before_the_trailer_section_ends_is_a_truncation() {
    for prefix in [
      b"".as_slice(),
      b"5\r\n",
      b"5\r\nhel",
      b"5\r\nhello",
      b"5\r\nhello\r\n",
      b"5\r\nhello\r\n0\r\n",
      b"5\r\nhello\r\n0\r\nX-Sum: ok\r\n",
    ] {
      let mut decoder = BodyDecoder::new(BodyFraming::Chunked, u64::MAX);
      let mut at = 0usize;
      loop {
        let (consumed, item) = decoder.feed(prefix.get(at..).unwrap_or_default()).unwrap();
        at = at.saturating_add(consumed);
        if consumed == 0 && item.is_none() {
          break;
        }
      }
      assert!(!decoder.is_finished(), "{prefix:?} finished early");
      assert!(decoder.eof().is_err(), "{prefix:?} accepted a close");
    }
  }
}
