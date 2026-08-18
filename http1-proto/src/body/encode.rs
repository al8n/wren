//! Outbound chunked framing (RFC 9112 §7.1): the `chunk-size` line that opens a
//! chunk, the CRLF that closes one, and the `last-chunk` plus §7.1.2 trailer
//! section that ends the body.
//!
//! The payload itself never passes through here. A chunk is
//! `chunk-size CRLF chunk-data CRLF`, and this module writes the framing on
//! either side of `chunk-data` so the caller can send its own buffer straight
//! out between them — the whole point of a Sans-I/O core is that a body does
//! not need a copy to be framed.
//!
//! The head module owns the machinery: [`two_pass`] gives the same
//! measure-then-write guarantee (an exact `need`, and nothing written when the
//! buffer is short) and [`emit_fields`] writes the trailer section, because RFC
//! 9112 §7.1.2 gives a trailer section "the same syntax as the header section"
//! and this core has ONE implementation of that syntax per direction — the same
//! sharing `body::chunked` already does with `head::validate_field_line`
//! inbound.

use crate::{
  error::Error,
  grammar::eq_ignore_ascii,
  head::encode::{CRLF, FieldDigest, Headers, emit_fields, two_pass},
};

/// RFC 9112 §7.1 `chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF`: the
/// CRLF that follows the chunk-data, which the caller writes after its payload.
///
/// The same terminator every line of a message ends with, named separately
/// because this one closes a chunk rather than a line of a head.
pub(crate) const CHUNK_TERMINATOR: &[u8] = CRLF;

/// RFC 9112 §7.1 `last-chunk = 1*("0") [ chunk-ext ] CRLF`, in the one spelling
/// this core writes: a single `0` and no extension. No recipient is required to
/// understand an extension, so sending one buys nothing and costs a peer bytes
/// to parse.
const LAST_CHUNK: &[u8] = b"0\r\n";

/// Writes the `chunk-size CRLF` line that opens a chunk of `size` octets,
/// returning the bytes written.
///
/// The caller follows it with exactly `size` octets of payload and then
/// [`CHUNK_TERMINATOR`].
///
/// A zero `size` is REFUSED. RFC 9112 §7.1 spells `last-chunk` as `1*("0")`, so
/// a zero-size chunk header is not an empty chunk on the wire — it is the line
/// that ENDS the body, and the payload and terminator the caller would write
/// after it would be read as the trailer section and then as the next message
/// (the §11.2 smuggling primitive, self-inflicted). A caller with nothing to
/// send sends no chunk; the one legitimate `0` line comes from
/// [`encode_last_chunk_and_trailers`].
pub(crate) fn encode_chunk_header(size: usize, out: &mut [u8]) -> Result<usize, Error> {
  if size == 0 {
    return Err(Error::InvalidState(
      "a zero-size chunk header is the last-chunk",
    ));
  }
  let hex = HexSize::new(size);
  // A chunk-size line has no field section, so the digest it is checked against
  // is the empty one — and stays a real check: an emit routine that started
  // producing field lines here would be refused rather than silently written.
  two_pass(out, FieldDigest::new(), |sink| {
    sink.put(hex.digits());
    sink.put(CRLF);
    Ok(())
  })
}

/// The field names this core will not put in a trailer section, whatever the
/// caller asked for.
///
/// RFC 9110 §6.5.1: "A sender MUST NOT generate a trailer field unless the
/// sender knows the corresponding header field name's definition permits the
/// field to be sent in trailers". The same section gives the reason: "Many
/// fields cannot be processed outside the header section because their
/// evaluation is necessary prior to receiving the content, such as those that
/// describe message framing, routing, authentication, request modifiers,
/// response controls, or content format".
///
/// # The rule, not a list
///
/// Which field definitions permit a trailer is a REGISTRY question, and this
/// core does not carry the registry — so §6.5.1 stays mostly delegated to the
/// layer that knows what the message is. What this core can decide alone is
/// exactly this: **the fields it interprets itself.** If a name appears in
/// `head::scan`'s `KeyFields` — the record of every field this crate reads and
/// acts on — then the same name in a trailer section either contradicts what
/// this core already did with it or is silently ignored, and both are a lie told
/// to the peer. `Trailer` joins them for a reason of its own: it announces the
/// section, so it cannot BE one (§6.6.2).
///
/// That rule is what makes the set closed and checkable rather than four names
/// and then a fifth. Name by name:
///
/// - `Content-Length` and `Transfer-Encoding` (RFC 9112 §6.2, §6.1) — message
///   framing. A trailer stating either would be read by a recipient that merged
///   sections as a second, contradictory delimitation of a message this core has
///   already framed by the chunked coding (§11.2).
/// - `Host` (RFC 9110 §7.2) — routing, evaluated before the content by
///   definition.
/// - `Connection` (§7.6.1) — connection control, and "only meaningful for a
///   single transport-level connection". A trailer `Connection: close` would put
///   the closing signal on the wire while this end's state machine re-armed:
///   the peer reads a connection that is ending, the sender has one it will
///   reuse.
/// - `Upgrade` (§7.8) — a protocol switch is decided by the head, before any
///   content; and §7.6.1 requires the field to be named in `Connection`, which
///   is itself forbidden here, so a trailer `Upgrade` could not be a conforming
///   offer even in principle.
/// - `Expect` (§10.1.1) — a request modifier, which §6.5.1 names outright. An
///   expectation exists to be evaluated BEFORE the content; delivered after it,
///   it is a contradiction in terms.
/// - `Trailer` (§6.6.2) — announces the trailer section, so it cannot be one.
///
/// And the boundary, stated so it is not mistaken for an oversight: `TE`
/// (RFC 9110 §10.1.4) is hop-by-hop and is NOT here. This core never generates
/// or interprets it — it implements one transfer coding and negotiates none — so
/// it has no framing or routing decision a trailer `TE` could contradict, and it
/// falls to §6.5.1's delegated remainder like every other name.
const FORBIDDEN_TRAILERS: &[&str] = &[
  "Content-Length",
  "Transfer-Encoding",
  "Host",
  "Connection",
  "Upgrade",
  "Expect",
  "Trailer",
];

/// What a caller asking for one of those is told.
///
/// `pub(crate)` so the send side's own tests can pin WHICH refusal a trailer
/// section earns rather than merely that one happened.
pub(crate) const FORBIDDEN_TRAILER: &str =
  "this field name cannot be sent in a trailer section (RFC 9110 §6.5.1)";

/// Writes the `last-chunk`, the RFC 9112 §7.1.2 trailer section, and the empty
/// line that ends a chunked body, returning the bytes written.
///
/// Trailer names and values are validated exactly as a head's fields are (§7.1.2
/// gives the section "the same syntax as the header section"), and an empty
/// section is the ordinary case: `0 CRLF CRLF`.
///
/// WHICH fields may be trailers is mostly not decided here — see
/// [`FORBIDDEN_TRAILERS`] for the narrow set RFC 9110 §6.5.1 lets this core
/// refuse on its own, and for why the rest of that MUST NOT stays with the layer
/// that knows what the message is.
pub(crate) fn encode_last_chunk_and_trailers<H: Headers + ?Sized>(
  trailers: &H,
  out: &mut [u8],
) -> Result<usize, Error> {
  // One walk of the supplier ahead of the two `two_pass` makes, and the walk
  // this section's verdict is taken from. Refused BEFORE any pass, so a rejected
  // section leaves `out` untouched.
  //
  // It SIGNS what it read, which is what stops the verdict from being about a
  // different section than the one written. Without the digest a supplier could
  // show `Xyzw: 1` here and `Host: 1` to both encoder passes — same name length,
  // same byte count, a routing field smuggled into a trailer section past a
  // check that had already said yes (RFC 9110 §6.5.1).
  let mut forbidden = false;
  let mut digest = FieldDigest::new();
  trailers.for_each(&mut |name, value| {
    let name = name.as_bytes();
    digest.mix(name, value);
    forbidden |= FORBIDDEN_TRAILERS
      .iter()
      .any(|&banned| eq_ignore_ascii(name, banned));
  })?;
  if forbidden {
    return Err(Error::InvalidState(FORBIDDEN_TRAILER));
  }

  two_pass(out, digest, |sink| {
    sink.put(LAST_CHUNK);
    emit_fields(trailers, sink)?;
    // The empty line that closes the trailer section — and the body. A chunked
    // body with no trailers still ends with it (§7.1).
    sink.put(CRLF);
    Ok(())
  })
}

/// Hex digits wide enough for any `usize` this platform has: two per byte,
/// which is 16 on a 64-bit target and 4 on a 16-bit one. Measured rather than
/// assumed, because this core is built for cores where `usize` is not 64 bits.
const MAX_SIZE_DIGITS: usize = size_of::<usize>().saturating_mul(2);

/// A chunk size rendered as RFC 9112 §7.1 `chunk-size = 1*HEXDIG`.
///
/// Held in a fixed buffer filled from the RIGHT, so the digits are a suffix of
/// it and no allocation, no reversal, and no second pass over the number is
/// needed. The buffer starts as all `0`, which makes its unused prefix the
/// zero-PADDING of the same number: `1*HEXDIG` admits leading zeros, so the
/// whole buffer spells exactly the size its suffix does.
struct HexSize {
  /// The rendering, right-aligned.
  buffer: [u8; MAX_SIZE_DIGITS],
  /// Where the digits begin within it.
  start: usize,
}

impl HexSize {
  /// Renders `size`, most significant digit first and with no leading zeros.
  fn new(size: usize) -> Self {
    let mut buffer = [b'0'; MAX_SIZE_DIGITS];
    let mut rest = size;
    let mut start = MAX_SIZE_DIGITS;
    loop {
      start = start.saturating_sub(1);
      if let Some(slot) = buffer.get_mut(start) {
        *slot = hex_digit(rest);
      }
      // Four bits is far below `usize::BITS` on every platform Rust supports,
      // so the shift is always defined; answered rather than unwrapped, as a
      // codec may not panic on any input.
      rest = rest.checked_shr(4).unwrap_or(0);
      // `MAX_SIZE_DIGITS` nibbles cover the whole of a `usize`, so the second
      // condition cannot be what ends the loop; it is there so that a wrong
      // width would truncate the number rather than run off the front of the
      // buffer forever.
      if rest == 0 || start == 0 {
        break;
      }
    }
    Self { buffer, start }
  }

  /// The digits, most significant first.
  fn digits(&self) -> &[u8] {
    // `start` is an index into `buffer` by construction, so the fallback is
    // unreachable — and it is the zero-padded rendering of the SAME size, which
    // `1*HEXDIG` spells just as well, rather than an answer that would frame
    // the chunk differently.
    self.buffer.get(self.start..).unwrap_or(&self.buffer)
  }
}

/// The lowercase `HEXDIG` (RFC 5234) spelling the low four bits of `value`.
///
/// ABNF literals are case-insensitive, so a recipient reads either case; one
/// case is written so that a size has exactly one spelling here. Table-shaped
/// like the decoder's `hex_value` and total in the same way: every input maps
/// to a digit, so there is no error path to answer and none to get wrong.
const fn hex_digit(value: usize) -> u8 {
  match value & 0xF {
    0 => b'0',
    1 => b'1',
    2 => b'2',
    3 => b'3',
    4 => b'4',
    5 => b'5',
    6 => b'6',
    7 => b'7',
    8 => b'8',
    9 => b'9',
    10 => b'a',
    11 => b'b',
    12 => b'c',
    13 => b'd',
    14 => b'e',
    // The mask leaves 0..=15, so this arm is 15 and nothing else.
    _ => b'f',
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    body::{BodyDecoder, BodyItem},
    error::H1Error,
    validate::BodyFraming,
  };

  // RFC 9112 §7.1: `chunk-size = 1*HEXDIG` followed by CRLF, and
  // `last-chunk = 1*("0") [ chunk-ext ] CRLF` followed by the §7.1.2 trailer
  // section and the empty line that closes it.
  #[test]
  fn chunk_framing_writers() {
    let mut out = [0u8; 32];
    let n = encode_chunk_header(0x1A, &mut out).unwrap();
    assert_eq!(&out[..n], b"1a\r\n");
    let t: &[(&str, &[u8])] = &[("X-Sum", b"ok")];
    let n = encode_last_chunk_and_trailers(t, &mut out).unwrap();
    assert_eq!(&out[..n], b"0\r\nX-Sum: ok\r\n\r\n");
  }

  // RFC 9112 §7.1 `chunk-size = 1*HEXDIG`, with RFC 5234's case-insensitive
  // HEXDIG: this core writes lowercase, no `0x`, and no padding — and the `1*`
  // means a value needs at least one digit, zero included.
  #[test]
  fn chunk_sizes_are_lowercase_hex_without_padding() {
    let mut out = [0u8; 32];
    assert_eq!(HexSize::new(0).digits(), b"0");
    for (size, expected) in [
      (1usize, b"1\r\n".as_slice()),
      (0x0A, b"a\r\n"),
      (0x1A, b"1a\r\n"),
      (0xFF, b"ff\r\n"),
      (0x100, b"100\r\n"),
    ] {
      let n = encode_chunk_header(size, &mut out).unwrap();
      assert_eq!(&out[..n], expected, "{size:#x}");
    }
    // The widest size this platform can express: two hex digits per byte, all
    // `f`, and the writer's buffer is sized from `usize` rather than assumed.
    let n = encode_chunk_header(usize::MAX, &mut out).unwrap();
    let digits = size_of::<usize>() * 2;
    assert_eq!(&out[..digits], &[b'f'; 16][..digits]);
    assert_eq!(&out[digits..n], b"\r\n");
  }

  // RFC 9112 §7.1 `last-chunk = 1*("0")`: a zero-size chunk header IS that
  // line, so writing one mid-body would end the body and leave the payload
  // behind it to be read as the next message (§11.2). Refused, and the caller
  // is told which line it just asked for.
  #[test]
  fn a_zero_size_chunk_header_is_refused_as_the_last_chunk() {
    let mut out = [0xAAu8; 8];
    assert_eq!(
      encode_chunk_header(0, &mut out),
      Err(Error::InvalidState(
        "a zero-size chunk header is the last-chunk"
      ))
    );
    assert_eq!(out, [0xAAu8; 8]);
  }

  // RFC 9112 §7.1: `last-chunk CRLF` with no trailer field at all is the
  // ordinary end of a chunked body.
  #[test]
  fn a_chunked_body_ends_without_trailers() {
    let mut out = [0u8; 16];
    let none: &[(&str, &[u8])] = &[];
    let n = encode_last_chunk_and_trailers(none, &mut out).unwrap();
    assert_eq!(&out[..n], b"0\r\n\r\n");
  }

  // RFC 9112 §7.1.2: a trailer section has "the same syntax as the header
  // section", so a trailer name is a token and a trailer value is
  // grammar-checked. A CRLF smuggled through either would end the body early
  // and leave the rest to be read as the next message (§11.2).
  #[test]
  fn refuses_trailers_that_would_break_the_section() {
    let mut out = [0u8; 64];
    for bad in [
      &[("Bad Name", b"v".as_slice())] as &[(&str, &[u8])],
      &[("X", b"a\r\nInjected: x")],
      &[("", b"v")],
    ] {
      assert!(
        matches!(
          encode_last_chunk_and_trailers(bad, &mut out),
          Err(Error::Protocol(H1Error::Malformed(_)))
        ),
        "{bad:?}"
      );
    }
  }

  // RFC 9112 §7.1: framing bytes are part of the body's delimitation, so a
  // partly written chunk line is not a short write but a body the peer would
  // frame differently. The size is settled first and `out` is untouched.
  #[test]
  fn short_buffers_report_the_exact_need_and_write_nothing() {
    let mut out = [0xAAu8; 4];
    let Err(Error::BufferTooSmall { need, have: 4 }) = encode_chunk_header(0x1_0000, &mut out)
    else {
      panic!()
    };
    assert_eq!(need, b"10000\r\n".len());
    assert_eq!(out, [0xAAu8; 4]);

    let t: &[(&str, &[u8])] = &[("X-Sum", b"ok")];
    let Err(Error::BufferTooSmall { need, have: 4 }) = encode_last_chunk_and_trailers(t, &mut out)
    else {
      panic!()
    };
    assert_eq!(need, b"0\r\nX-Sum: ok\r\n\r\n".len());
    assert_eq!(out, [0xAAu8; 4]);
  }

  // RFC 9112 §7.1 both ways: a body framed by this module is decoded by this
  // crate's own §7.1 decoder back into the payload and the trailer that went
  // in. A disagreement between the two directions about where a chunk ends is
  // exactly the §11.2 smuggling primitive.
  #[test]
  fn an_encoded_chunked_body_decodes_back_to_its_payload() {
    let mut wire = [0u8; 64];
    let mut at = 0usize;
    at += encode_chunk_header(b"hello".len(), &mut wire[at..]).unwrap();
    wire[at..at + 5].copy_from_slice(b"hello");
    at += 5;
    wire[at..at + CHUNK_TERMINATOR.len()].copy_from_slice(CHUNK_TERMINATOR);
    at += CHUNK_TERMINATOR.len();
    let trailers: &[(&str, &[u8])] = &[("X-Sum", b"ok")];
    at += encode_last_chunk_and_trailers(trailers, &mut wire[at..]).unwrap();
    assert_eq!(&wire[..at], b"5\r\nhello\r\n0\r\nX-Sum: ok\r\n\r\n");

    let mut decoder = BodyDecoder::new(BodyFraming::Chunked);
    let mut rest: &[u8] = &wire[..at];
    let mut payload = [0u8; 8];
    let mut payload_len = 0usize;
    let mut trailer = None;
    let mut finished = false;
    loop {
      let (used, item) = decoder.feed(rest).unwrap();
      match item {
        Some(BodyItem::Data(data)) => {
          payload[payload_len..payload_len + data.len()].copy_from_slice(data);
          payload_len += data.len();
        }
        Some(BodyItem::TrailerField { name, value }) => trailer = Some((name, value)),
        Some(BodyItem::Finished) => {
          finished = true;
          break;
        }
        Some(BodyItem::TrailersStart) | None => {
          if used == 0 {
            break;
          }
        }
      }
      rest = &rest[used..];
    }
    assert_eq!(&payload[..payload_len], b"hello");
    assert_eq!(trailer, Some(("X-Sum", b"ok".as_slice())));
    assert!(finished);
  }
}
