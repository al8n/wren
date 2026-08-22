//! Outbound heads: the RFC 9112 §3 request-line or §4 status-line, the §5 field
//! lines that follow it, and the empty line that closes the section — written
//! into a slice the caller owns.
//!
//! Sans-I/O and no-alloc: an encoder never owns the bytes it produces, and it
//! never writes a byte the caller did not make room for. When the slice is too
//! small the call reports the EXACT size the message needs and writes NOTHING —
//! `out` comes back untouched — so a caller sizes its buffer from the error and
//! retries, instead of having to unsend a half-written message.
//!
//! TWO PASSES OVER ONE ROUTINE is what buys that. Every encoder here hands the
//! same emit closure a [`Sink`] twice: a `Measure` that counts the bytes, then a
//! `Writer` that writes them. The size a caller is quoted and the bytes it
//! sends are therefore produced by the same code rather than by a length
//! calculation kept in step with a writer by hand, and the capacity check
//! happens BETWEEN the passes, before a byte moves. The one input that can
//! still differ between the two is the caller's own [`Headers`] supplier, whose
//! idempotence is a documented contract — and one this module verifies rather
//! than trusts (see [`two_pass`]).
//!
//! REJECT, NEVER MANGLE. Every element an encoder is handed is validated
//! against the same grammar the parsers enforce, by the same functions: the
//! method and the request-target through the §3 codec's own `parse_method` and
//! `parse_target`, field names and values through [`crate::grammar`], the
//! reason-phrase through the §4 codec's own byte rule. Nothing is escaped,
//! trimmed, or dropped to make it fit — a value carrying a CRLF is a second
//! message the caller did not mean to send (RFC 9112 §11.1 response splitting,
//! §11.2 request smuggling), so it is refused rather than repaired.
//!
//! ELEMENTS ONLY. What an encoder checks is the grammar of the pieces it is
//! handed. Everything about the MESSAGE they form — which target form suits
//! which method, what framing fields the head may hold, whether a request
//! carries the `Host` RFC 9112 §3.2 requires — belongs to the layer that owns
//! the message: `crate::validate` on the way in, and on the way out
//! `connection::outbound`'s `declared` reduction and the rules stated over it.
//! That reduction is one walk of the supplier AHEAD of the two below, so a
//! request that owes a `Host` is refused before a byte of it is measured.
//!
//! NO SIZE CAP either. `MAX_HEAD_BYTES` bounds a head this core RECEIVES,
//! because bytes a peer sends are work this core did not ask for; an outbound
//! head is bounded by the caller's own buffer, and its exact size is what
//! [`Error::BufferTooSmall`] reports. Refusing to write a head that a peer
//! would accept, on the strength of this core's receive-side limit, would be a
//! rule no RFC has.
//!
//! OFFSETS. A `MalformedDetail` from an encoder is positioned within the
//! ELEMENT the caller supplied — that method, that target, that field name,
//! that field value — and not within a message, since the message it would have
//! gone into was never produced.

use super::{
  Target, malformed,
  request_line::{parse_method, parse_target},
  status_line::is_reason_byte,
};
use crate::{
  error::{Error, H1Error},
  grammar::{is_token, is_token_byte, validate_field_value},
};

// gate-exempt: super::delimit_line — names the INBOUND rule's single home, contrasted with this OUTBOUND constant; a `const` byte string
// calls nothing.
/// RFC 9112 §2.2's line terminator, and the only one this core writes.
///
/// The outbound counterpart of [`super::delimit_line`], which is the single
/// place the inbound rule lives: one definition per direction, so neither can
/// drift into accepting — or emitting — a bare CR or a bare LF.
pub(crate) const CRLF: &[u8] = b"\r\n";

/// The single SP that separates the fields of both start lines (RFC 9112 §3,
/// §4). Single, never "any amount of whitespace": the leniency the parsers
/// refuse to accept is leniency this side has no business producing.
const SP: &[u8] = b" ";

/// RFC 9112 §5 `field-line = field-name ":" OWS field-value OWS`: the colon and
/// the one OWS byte this core writes after it.
const COLON_SP: &[u8] = b": ";

/// The version every outbound message announces (RFC 9112 §2.3).
///
/// Always [`Version::Http11`](super::Version::Http11). A client of this core
/// speaks 1.1 only, and a server answers 1.1 even to a 1.0 request — §2.3 makes
/// the version a recipient sends its own, not an echo. What the peer's version
/// changes is the FRAMING and connection rules, and `crate::validate` has
/// already applied those by the time a head is encoded.
const OUTBOUND_VERSION: &[u8] = b"HTTP/1.1";

/// An outbound field section, supplied by the caller and visited by the
/// encoders.
///
/// Push style, as in this workspace's HTTP/3 core: a supplier hands each pair
/// to a callback instead of returning an iterator, so a section assembled on
/// the fly can lend `&str` / `&[u8]` it does not own, and no encoder needs a
/// collection to walk.
///
/// Names are `&str` because RFC 9110 §5.6.2 `token`s are ASCII by definition;
/// values are `&[u8]` because `obs-text` (§5.5) is legal field content and need
/// not be UTF-8. That byte-typed value is the one difference from the h3 trait.
///
/// # Contract: `for_each` must be IDEMPOTENT
///
/// A section is walked THREE times on the way out — once by the send side's own
/// reduction (`connection::outbound`'s `declared`, which decides how the message
/// is framed), then once to measure the exact size of the message (which is what
/// makes [`Error::BufferTooSmall`]'s `need` exact and keeps a short buffer from
/// being discovered halfway through a write), then once to write it. A supplier
/// that yields a different section on a later walk — a draining iterator is the
/// easy way to write one — would put a message on the wire that the framing
/// decision does not describe.
///
/// The encoders do not take that on trust, and what they compare is the
/// CONTENT rather than the byte count. Every walk mixes each `(name, value)`
/// pair into a `FieldDigest`, and the digest the framing decision was made
/// over must equal the one each encoder pass produces; a mismatch is
/// [`Error::InvalidState`] (`DRIFTED`) and the message is not sent.
///
/// **Same-length drift is caught too**, which is the point of a digest rather
/// than a length: a supplier that shows `Content-Length: 5` to the reduction and
/// `Content-Length: 6` to both encoder passes produces identical byte counts,
/// and a length-only check would let the FSM commit to a body of 5 octets while
/// the wire announced 6. The digest is over the name and value bytes with their
/// lengths, so no substitution of equal size survives it.
///
/// The check is a backstop, not a licence — a supplier whose output varies has
/// no defined encoding, and this reports that rather than diagnosing which field
/// moved.
///
/// **A drift found in the WRITING pass is the one error path that may leave
/// bytes in the caller's `out`.** Every other refusal — the reduction's, the
/// grammar's, and a drift the measuring pass already exposes — is found before a
/// byte is written. The rule is the same for all of them either way: on `Err`,
/// `out` holds nothing a caller may send.
///
/// # Passing a slice
///
/// Both impls below are on the UNSIZED slice type `[T]`, not on `&[T]`, which
/// is why the encoders take `&(impl Headers + ?Sized)`: an unsized `[T]` cannot
/// become a `&dyn Headers`, since a trait object needs a thin data pointer.
/// A caller therefore passes the slice itself:
///
/// ```text
/// let hdrs: &[(&str, &[u8])] = &[("Host", b"example.com")];
/// encode_request_head("GET", &target, hdrs, &mut out)?;   // `hdrs`, not `&hdrs`
/// ```
///
/// `&hdrs` is a `&&[T]`, which implements nothing here. A supplier of the
/// caller's own type is sized, so that one is passed by reference as usual.
pub trait Headers {
  /// Visits each `(name, value)` pair in order.
  ///
  /// Returning `Err` aborts the encode with that error. The visitor itself
  /// returns `()`, so it cannot stop the walk: an encoder that rejects a field
  /// records the first fault and turns the rest of the walk into a no-op.
  fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), crate::Error>;
}

impl<'a> Headers for [(&'a str, &'a [u8])] {
  fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), Error> {
    for &(name, value) in self {
      f(name, value);
    }
    Ok(())
  }
}

/// The same over `&str` values, for the many fields whose value a caller
/// already holds as text (`Host`, `Sec-WebSocket-Key`, a token list). A
/// distinct type from the slice above, so the two impls cannot overlap.
impl<'a> Headers for [(&'a str, &'a str)] {
  fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), Error> {
    for &(name, value) in self {
      f(name, value.as_bytes());
    }
    Ok(())
  }
}

/// What a supplier that yields a different section on a later walk is told.
/// One message, because there is nothing more to say about it: the encoding of
/// a section that is not the same every time is undefined, and this is the
/// refusal rather than a diagnosis of which field moved.
pub(crate) const DRIFTED: &str =
  "outbound headers changed between the walks that frame and write them";

/// RFC 1950-era FNV-1a's 64-bit offset basis and prime.
///
/// FNV-1a rather than anything stronger, and the choice is a scoping decision:
/// what this defends against is a BUGGY supplier — a draining iterator, a cell
/// read twice, a section rebuilt from mutable state — not an adversary who
/// controls both walks and is choosing collisions. A caller that wanted to lie
/// to this core about its own message can simply state the message it means; the
/// digest exists so that an accident cannot commit the FSM to one framing while
/// the wire carries another. It is allocation-free, `no_std`, and one multiply
/// per byte.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// The 64-bit FNV prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// A running signature of the `(name, value)` pairs a [`Headers`] supplier
/// produced, in order.
///
/// The cross-walk consistency check, and what makes it a check on CONTENT rather
/// than on size: the send side's framing reduction computes one, each encoder
/// pass computes one, and [`two_pass`] refuses a message whose digests disagree.
///
/// Each pair is mixed as `len(name) name len(value) value`, which is an
/// injective encoding of the sequence — so `("AB", "C")` and `("A", "BC")` differ
/// here even though their bytes and their total length do not, and neither can a
/// pair be dropped and another added to compensate.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct FieldDigest(u64);

impl FieldDigest {
  /// The digest of a section with no field lines in it.
  pub(crate) const fn new() -> Self {
    Self(FNV_OFFSET)
  }

  /// Folds one field line into the digest.
  pub(crate) fn mix(&mut self, name: &[u8], value: &[u8]) {
    self.length(name.len());
    self.bytes(name);
    self.length(value.len());
    self.bytes(value);
  }

  /// Folds a run of bytes in.
  fn bytes(&mut self, bytes: &[u8]) {
    for &byte in bytes {
      // XOR then `wrapping_mul`: FNV-1a is defined over a wrapping multiply, and
      // neither operation is one the crate's arithmetic lint wall forbids —
      // there is no overflow to answer, because wrapping IS the algorithm.
      self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
    }
  }

  /// Folds a length in, so that where one element ends and the next begins is
  /// part of what is being signed.
  fn length(&mut self, length: usize) {
    // A `usize` past `u64::MAX` cannot be the length of a slice in memory; the
    // fallback is unreachable and saturates rather than wrapping two different
    // lengths onto one value.
    self.bytes(&u64::try_from(length).unwrap_or(u64::MAX).to_le_bytes());
  }
}

/// Walks a section once and returns its [`FieldDigest`].
///
/// TEST SUPPORT, and gated as such. Every production path already walks the
/// section to decide something — `connection::outbound`'s framing reduction, or
/// `body::encode`'s forbidden-trailer check — and carries the digest out of THAT
/// walk, which is what makes the comparison a cross-walk one. A production
/// caller reaching for this would be adding a walk whose only purpose was to
/// agree with itself.
///
/// What is left needing it is the code that calls an encoder with no decision
/// behind it: this module's own tests, and the `no-panic` forwarder.
#[cfg(any(test, feature = "test-no-panic"))]
pub(crate) fn field_digest<H: Headers + ?Sized>(headers: &H) -> Result<FieldDigest, Error> {
  let mut digest = FieldDigest::new();
  headers.for_each(&mut |name, value| digest.mix(name.as_bytes(), value))?;
  Ok(digest)
}

/// Where one pass of an encoder puts the bytes it produces.
///
/// Two implementations and one caller: an encoder's emit routine is written
/// once against this trait and run twice by [`two_pass`], so the bytes
/// [`Measure`] counts are by construction the bytes [`Writer`] writes. Nothing
/// in an encoder may branch on which sink it holds.
pub(crate) trait Sink {
  /// Appends `bytes` to whatever this sink is accumulating.
  ///
  /// Infallible on purpose. A sink that cannot take the bytes records the fact
  /// and keeps going, so an emit routine has no error path of its own to get
  /// wrong and every output fault is decided in one place ([`two_pass`]).
  fn put(&mut self, bytes: &[u8]);

  /// Folds one caller-supplied field line into this pass's [`FieldDigest`].
  ///
  /// Separate from [`put`](Self::put) because the digest is over what the
  /// SUPPLIER said, not over the bytes a head is made of: the start line, the
  /// colons and the CRLFs are this core's own and are identical on every walk,
  /// while the pairs are the only thing a supplier can change between them.
  fn mix_field(&mut self, name: &[u8], value: &[u8]);
}

/// Pass one: counts the bytes a message needs and writes none of them.
struct Measure {
  /// Bytes counted so far.
  need: usize,
  /// The signature of the field lines this pass was handed.
  digest: FieldDigest,
}

impl Sink for Measure {
  fn mix_field(&mut self, name: &[u8], value: &[u8]) {
    self.digest.mix(name, value);
  }

  fn put(&mut self, bytes: &[u8]) {
    // Saturating rather than checked, and the difference matters only in a case
    // that cannot arise: the lengths summed here belong to slices that all
    // exist in memory at once, so their total is below `usize::MAX` already.
    // Were a pathological supplier ever to drive it there, `usize::MAX` is the
    // fail-CLOSED answer — it exceeds every real buffer, so the call reports
    // `BufferTooSmall` and writes nothing. A wrapping sum is the opposite: it
    // would quote a small `need` for a huge message and then aim the writing
    // pass at a buffer that cannot hold it.
    self.need = self.need.saturating_add(bytes.len());
  }
}

/// Pass two: writes into the caller's slice.
struct Writer<'a> {
  /// The caller's buffer.
  out: &'a mut [u8],
  /// Bytes written so far, which is where the next one goes.
  written: usize,
  /// Set by a `put` that did not fit. Unreachable unless the supplier broke the
  /// [`Headers`] idempotence contract, since [`two_pass`] sized the buffer from
  /// the measuring pass before this one began.
  overflow: bool,
  /// The signature of the field lines this pass was handed.
  digest: FieldDigest,
}

impl Sink for Writer<'_> {
  fn mix_field(&mut self, name: &[u8], value: &[u8]) {
    self.digest.mix(name, value);
  }

  fn put(&mut self, bytes: &[u8]) {
    let end = self.written.saturating_add(bytes.len());
    // The bound is enforced HERE, by `get_mut`, and not by trusting what the
    // measuring pass concluded: this is the last line between a caller's buffer
    // and a supplier that yields more on the second walk than on the first.
    let Some(destination) = self.out.get_mut(self.written..end) else {
      self.overflow = true;
      return;
    };
    // `get_mut` returned exactly `bytes.len()` bytes, so a copy that stops at
    // the shorter of the two stops at neither. Written as a loop rather than
    // `copy_from_slice` to keep the leaf provably panic-free — the crate's
    // `no_panic` harness has to prove it, not merely believe it.
    for (slot, &byte) in destination.iter_mut().zip(bytes) {
      *slot = byte;
    }
    self.written = end;
  }
}

/// Runs `emit` twice against `out`: once to size the message, once to write it.
/// Returns the bytes written.
///
/// `expect` is the [`FieldDigest`] of the section the CALLER's decisions were
/// made over — the framing reduction's walk, or the trailer encoder's own
/// pre-walk. Each pass recomputes it from what the supplier actually yielded,
/// and a pass that disagrees means the message about to go out is not the
/// message this core has committed to.
///
/// The ORDER is the contract. Pass one validates every element, counts the
/// bytes, and signs the field section, so an element the grammar refuses — or a
/// section that has already drifted away from what was framed — stops the call
/// before anything is written; the buffer is then checked against that exact
/// total, so a caller with too little room gets [`Error::BufferTooSmall`] whose
/// `need` is the size of the WHOLE message and an untouched `out`; only then
/// does pass two write.
///
/// A partial message therefore cannot reach `out` — with one exception, and it
/// is the caller's own: a [`Headers`] supplier that breaks its idempotence
/// contract by yielding a different section on the WRITING walk, having agreed
/// on the first two. That is detected (the digest, the byte count, and a `put`
/// that did not fit are all checked) and reported as [`Error::InvalidState`],
/// but bytes written before the divergence are in `out`. The rule for every
/// error path is the same either way: on `Err`, `out` holds nothing a caller may
/// send.
pub(crate) fn two_pass(
  out: &mut [u8],
  expect: FieldDigest,
  emit: impl Fn(&mut dyn Sink) -> Result<(), Error>,
) -> Result<usize, Error> {
  let mut measure = Measure {
    need: 0,
    digest: FieldDigest::new(),
  };
  emit(&mut measure)?;
  // Before the size check, and therefore before any byte can move: a section
  // that no longer matches the one the framing was decided over has nothing to
  // be sized for.
  if measure.digest != expect {
    return Err(Error::InvalidState(DRIFTED));
  }
  let need = measure.need;
  let have = out.len();
  if need > have {
    return Err(Error::BufferTooSmall { need, have });
  }

  let mut writer = Writer {
    out,
    written: 0,
    overflow: false,
    digest: FieldDigest::new(),
  };
  emit(&mut writer)?;
  if writer.overflow || writer.written != need || writer.digest != expect {
    return Err(Error::InvalidState(DRIFTED));
  }
  Ok(writer.written)
}

// gate-exempt: head::validate_field_line — names the INBOUND analogue of this function's own OUTBOUND sharing with `body::encode`; this
// function IS the outbound half, so it is not the inbound function it draws the parallel to.
/// Writes one field section: a `field-line` per pair, in the order supplied,
/// each terminated by CRLF (RFC 9112 §5).
///
/// Shared with `body::encode`, since RFC 9112 §7.1.2 gives a trailer section
/// "the same syntax as the header section" — the outbound half of the sharing
/// `body::chunked` already does with `head::validate_field_line` inbound. The
/// empty line that CLOSES a section is not written here: a head ends with one
/// and so does a trailer section, but a caller assembling either may have more
/// to say first.
pub(crate) fn emit_fields<H: Headers + ?Sized>(
  headers: &H,
  sink: &mut dyn Sink,
) -> Result<(), Error> {
  let mut fault: Option<Error> = None;
  headers.for_each(&mut |name, value| {
    // The visitor cannot stop the walk — it returns `()` — so a rejected field
    // turns the rest of the traversal into a no-op and the FIRST fault is the
    // one the caller hears about.
    if fault.is_some() {
      return;
    }
    if let Err(e) = emit_field_line(name, value, sink) {
      fault = Some(e);
    }
  })?;
  match fault {
    Some(e) => Err(e),
    None => Ok(()),
  }
}

/// Validates and writes one RFC 9112 §5
/// `field-line = field-name ":" OWS field-value OWS`, in the single shape this
/// core sends it: `name ": " value CRLF`.
///
/// The value goes out exactly as it was handed over. OWS around a value is not
/// part of it (RFC 9110 §5.5), so a caller's untrimmed value reaches the peer
/// as the same field — trimming it here would be mangling, and refusing it
/// would invent a rule §5 does not have.
fn emit_field_line(name: &str, value: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
  let name_bytes = name.as_bytes();
  if !is_token(name_bytes) {
    // `token = 1*tchar` (RFC 9110 §5.6.2) fails two ways, and the diagnosis is
    // derived only on the failing path: a byte that is not a tchar, or — the
    // only remaining way — no byte at all.
    return Err(
      match name_bytes.iter().position(|&b| !is_token_byte(b)) {
        Some(at) => malformed(at, "field name is not a token"),
        None => malformed(0, "empty field name"),
      }
      .into(),
    );
  }
  // RFC 9110 §5.5: `field-vchar` / SP / HTAB, `obs-text` included and every CTL
  // out. The CR and the LF of an injected line break die here.
  if let Err(at) = validate_field_value(value) {
    return Err(malformed(at, "control byte in the field value").into());
  }

  // Signed before it is written, and only once the grammar has passed: what the
  // digest covers is the section a caller SUPPLIED, which is the only part of a
  // head that can differ between the walks.
  sink.mix_field(name_bytes, value);
  sink.put(name_bytes);
  sink.put(COLON_SP);
  sink.put(value);
  sink.put(CRLF);
  Ok(())
}

/// Encodes a complete RFC 9112 §3 request head — request-line, field lines, and
/// the empty line that ends them — into `out`, returning the bytes written.
///
/// Validates the method (RFC 9110 §9.1 `token`), the request-target against its
/// own form's grammar (§3.2), and every field line (§5), rejecting rather than
/// repairing. `Error::BufferTooSmall`'s `need` is the exact size of the whole
/// head, and a short `out` is left untouched — see [`two_pass`].
///
/// WHICH form goes with which method — authority-form for CONNECT (§3.2.3),
/// asterisk-form for server-wide OPTIONS (§3.2.4) — is a message-level rule
/// that `crate::validate` owns, exactly as on the receive side. This writes the
/// target it is given, in the form it is given.
pub(crate) fn encode_request_head<H: Headers + ?Sized>(
  method: &str,
  target: &Target<'_>,
  headers: &H,
  expect: FieldDigest,
  out: &mut [u8],
) -> Result<usize, Error> {
  two_pass(out, expect, |sink| {
    // RFC 9112 §3 `request-line = method SP request-target SP HTTP-version
    // CRLF`, validated by the very functions that parse one.
    parse_method(method.as_bytes())?;
    let target_text = check_target(target)?;
    sink.put(method.as_bytes());
    sink.put(SP);
    sink.put(target_text.as_bytes());
    sink.put(SP);
    sink.put(OUTBOUND_VERSION);
    sink.put(CRLF);
    emit_fields(headers, sink)?;
    // RFC 9112 §2.1: the empty line that ends the field section, and with it
    // the head.
    sink.put(CRLF);
    Ok(())
  })
}

/// Encodes a complete RFC 9112 §4 response head — status-line, field lines, and
/// the empty line that ends them — into `out`, returning the bytes written.
///
/// `code` must be one §4 `3DIGIT` can spell (100 through 999); anything else is
/// [`Error::InvalidState`] rather than a `Malformed`, because a `u16` is not
/// bytes and there is no offending byte to point at — the fault is a caller
/// passing a value no status-line can carry, which is API misuse.
///
/// `reason` is written verbatim after the mandatory SP and may be empty (§4
/// makes that SP a MUST "even when the reason-phrase is absent"), but every
/// byte of it must be `HTAB / SP / VCHAR / obs-text`.
pub(crate) fn encode_status_head<H: Headers + ?Sized>(
  code: u16,
  reason: &[u8],
  headers: &H,
  expect: FieldDigest,
  out: &mut [u8],
) -> Result<usize, Error> {
  // Ahead of the two passes: an unrepresentable code is not a question about
  // how much room the message needs.
  let Some(digits) = status_digits(code) else {
    return Err(Error::InvalidState("status code out of range"));
  };

  two_pass(out, expect, |sink| {
    // RFC 9112 §4 `status-line = HTTP-version SP status-code SP
    // [ reason-phrase ]`.
    check_reason(reason)?;
    sink.put(OUTBOUND_VERSION);
    sink.put(SP);
    sink.put(&digits);
    sink.put(SP);
    sink.put(reason);
    sink.put(CRLF);
    emit_fields(headers, sink)?;
    sink.put(CRLF);
    Ok(())
  })
}

/// The text of a request-target, checked against the form the caller declared.
///
/// The check is a round trip: the bytes about to be written are PARSED back by
/// §3.2's own classifier, and the form it reports must be the form that was
/// handed over. That covers both halves of the question in one step — the
/// target obeys its form's grammar, and the form it obeys is the one the sender
/// meant — using the reading every recipient of the message will make of those
/// same bytes rather than a second copy of the grammar to keep in step.
fn check_target<'a>(target: &Target<'a>) -> Result<&'a str, H1Error> {
  let text = match *target {
    Target::Origin { path_and_query } => path_and_query,
    Target::Absolute { uri } => uri,
    Target::Authority { host_port } => host_port,
    // §3.2.4 asterisk-form has no payload to validate: it is this byte.
    Target::Asterisk => "*",
  };
  if parse_target(text.as_bytes(), 0)? != *target {
    // A target that parses as a DIFFERENT form — an `Absolute` holding a bare
    // authority, an `Origin` holding `*` — is not a grammar violation of the
    // bytes; it is a message that would address a different resource than the
    // sender named.
    return Err(malformed(0, "request-target does not match its form"));
  }
  Ok(text)
}

/// RFC 9112 §4 `reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )`, which the
/// status-line makes optional — so an empty phrase passes, and a CRLF inside
/// one never does.
fn check_reason(reason: &[u8]) -> Result<(), H1Error> {
  match reason.iter().position(|&b| !is_reason_byte(b)) {
    Some(at) => Err(malformed(at, "control byte in the reason-phrase")),
    None => Ok(()),
  }
}

/// RFC 9112 §4 `status-code = 3DIGIT`, narrowed to the codes a SENDER may write:
/// the three ASCII digits of `code`, for `code` in 100..=599.
///
/// Two rules, and they belong to different roles. §4's grammar is what makes it
/// three digits — two would leave the status-line a byte short and four would
/// push one into the reason-phrase — while RFC 9110 §15 is what makes the range
/// 100 through 599: it defines exactly five classes and says "values outside
/// that range are invalid", naming 600-999 as codes HTTP does not have.
///
/// The asymmetry with the receive side is the sender/recipient split again, and
/// it is deliberate. A RECIPIENT keeps parsing any `3DIGIT`, because §15 also
/// tells it to treat an unrecognised code as the `x00` of its class and a
/// message it cannot classify is still a message it must frame correctly —
/// refusing to parse one would be inventing a framing fault out of a semantic
/// one. A SENDER has no such excuse: it chooses the number, and this core will
/// not put a code on the wire that no recipient can classify.
fn status_digits(code: u16) -> Option<[u8; 3]> {
  if !(100..=599).contains(&code) {
    return None;
  }
  // Method forms, not `/` and `%`: the crate denies the operators outright
  // (`clippy::integer_division`, `clippy::arithmetic_side_effects`), and these
  // answer the divide-by-zero case instead of trusting a literal divisor.
  let hundreds = code.checked_div(100)?;
  let tens = code.checked_div(10)?.checked_rem(10)?;
  let ones = code.checked_rem(10)?;
  Some([
    ascii_digit(hundreds)?,
    ascii_digit(tens)?,
    ascii_digit(ones)?,
  ])
}

/// One decimal digit as ASCII, or `None` for a value that is not one.
fn ascii_digit(value: u16) -> Option<u8> {
  match u8::try_from(value) {
    Ok(digit @ 0..=9) => Some(b'0'.saturating_add(digit)),
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::head::{Version, request_line::parse_request_line, scan::scan_head};
  use core::cell::Cell;

  /// The target most of these tests are not about.
  const ORIGIN: Target<'static> = Target::Origin {
    path_and_query: "/",
  };

  /// [`super::encode_request_head`] with the expected [`FieldDigest`] taken from
  /// the supplier itself.
  ///
  /// In production that digest comes from the send side's framing reduction,
  /// which walked the section to decide how the message is delimited; these
  /// tests are about the ENCODER and have no such decision to carry, so they
  /// walk once here. The shim shadows the outer name, so every call below reads
  /// as the four-argument encoder it is about.
  ///
  /// Note what this still proves for a DRIFTING supplier: the digest is taken
  /// from walk one and compared against walks two and three, which is exactly
  /// the production shape.
  fn encode_request_head<H: Headers + ?Sized>(
    method: &str,
    target: &Target<'_>,
    headers: &H,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    let expect = field_digest(headers)?;
    super::encode_request_head(method, target, headers, expect, out)
  }

  /// The same for [`super::encode_status_head`].
  fn encode_status_head<H: Headers + ?Sized>(
    code: u16,
    reason: &[u8],
    headers: &H,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    let expect = field_digest(headers)?;
    super::encode_status_head(code, reason, headers, expect, out)
  }

  // The impls live on the UNSIZED slice `[T]`, so a call site passes the `&[T]`
  // itself and never `&hdrs`, which is a `&&[T]` and implements nothing. A
  // `&[T]` does NOT unsize-coerce to `&dyn Headers` — `Unsize<dyn Trait>`
  // requires a SIZED source — which is why the encoders take
  // `&(impl Headers + ?Sized)` instead.
  //
  // RFC 9112 §3 (`method SP request-target SP HTTP-version CRLF`) and §5
  // (`field-line`s, then the empty line that ends the section).
  #[test]
  fn encodes_request_head_exactly() {
    let mut out = [0u8; 256];
    let hdrs: &[(&str, &[u8])] = &[("Host", b"example.com"), ("Upgrade", b"websocket")];
    let n = encode_request_head(
      "GET",
      &Target::Origin {
        path_and_query: "/chat",
      },
      hdrs,
      &mut out,
    )
    .unwrap();
    assert_eq!(
      &out[..n],
      b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n"
    );
  }

  // RFC 9112 §2.1: a head is one message, so a caller that cannot hold all of
  // it is told the whole size rather than handed a prefix of a message.
  #[test]
  fn buffer_too_small_reports_exact_need() {
    let mut tiny = [0u8; 8];
    let hdrs: &[(&str, &[u8])] = &[("Host", b"example.com")];
    let Err(Error::BufferTooSmall { need, have: 8 }) = encode_request_head(
      "GET",
      &Target::Origin {
        path_and_query: "/",
      },
      hdrs,
      &mut tiny,
    ) else {
      panic!()
    };
    assert_eq!(need, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".len());
  }

  // RFC 9110 §5.6.2 (`field-name = token`) and §5.5 (`field-value` is
  // `field-vchar`/SP/HTAB, CTLs excluded): a name with a space or a value with
  // a CRLF in it would be read by the peer as a different message — RFC 9112
  // §11.2's smuggling primitive — so neither is escaped or trimmed into shape.
  #[test]
  fn rejects_invalid_outbound_headers() {
    let mut out = [0u8; 256];
    let bad_name: &[(&str, &[u8])] = &[("Bad Name", b"v")];
    assert!(
      encode_request_head(
        "GET",
        &Target::Origin {
          path_and_query: "/"
        },
        bad_name,
        &mut out
      )
      .is_err()
    );
    let bad_value: &[(&str, &[u8])] = &[("X", b"a\r\nInjected: x")]; // CRLF injection
    assert!(
      encode_request_head(
        "GET",
        &Target::Origin {
          path_and_query: "/"
        },
        bad_value,
        &mut out
      )
      .is_err()
    );
  }

  // RFC 9112 §4: a server sends the SP that separates the status-code from the
  // reason-phrase "even when the reason-phrase is absent", so an empty phrase
  // still ends the line with `SP CRLF`.
  #[test]
  fn encodes_status_head_with_empty_reason() {
    let mut out = [0u8; 64];
    let empty: &[(&str, &[u8])] = &[];
    let n = encode_status_head(101, b"", empty, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 101 \r\n\r\n");
  }

  // RFC 9112 §3.2.1-§3.2.4: all four request-target forms go out in the form
  // the caller chose. Which form a given method may use is a message-level rule
  // (`crate::validate`), not a grammar one, so the encoder writes what it is
  // given.
  #[test]
  fn encodes_every_target_form() {
    let mut out = [0u8; 64];
    let none: &[(&str, &[u8])] = &[];
    let cases: [(&str, Target<'_>, &[u8]); 4] = [
      ("OPTIONS", Target::Asterisk, b"OPTIONS * HTTP/1.1\r\n\r\n"),
      (
        "CONNECT",
        Target::Authority {
          host_port: "example.com:443",
        },
        b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
      ),
      (
        "GET",
        Target::Absolute {
          uri: "http://example.com/p?q",
        },
        b"GET http://example.com/p?q HTTP/1.1\r\n\r\n",
      ),
      (
        "GET",
        Target::Origin {
          path_and_query: "/chat?x=1",
        },
        b"GET /chat?x=1 HTTP/1.1\r\n\r\n",
      ),
    ];
    for (method, target, expected) in cases {
      let n = encode_request_head(method, &target, none, &mut out).unwrap();
      assert_eq!(&out[..n], expected, "{target:?}");
    }
  }

  // RFC 9112 §3.2 + RFC 9110 §9.1: the encoder re-parses the bytes it is about
  // to write and requires the SAME form back, so a target whose text belongs to
  // another form (an `Absolute` holding an authority, an `Origin` holding `*`)
  // is refused instead of going out as that other form — the two peers would
  // otherwise disagree about what resource was addressed.
  #[test]
  fn refuses_targets_and_methods_the_parser_would_refuse() {
    let mut out = [0u8; 64];
    let none: &[(&str, &[u8])] = &[];
    for target in [
      Target::Origin {
        path_and_query: "chat",
      }, // no leading `/`
      Target::Origin {
        path_and_query: "/a b",
      }, // SP inside the target
      Target::Origin {
        path_and_query: "/a#f",
      }, // a fragment is never part of a target
      Target::Origin {
        path_and_query: "*",
      }, // asterisk-form text
      Target::Origin { path_and_query: "" },
      Target::Absolute { uri: "example.com" }, // authority-form text
      Target::Absolute {
        uri: "ftp://example.com/",
      }, // a scheme this core does not serve
      Target::Authority { host_port: "*" },
      Target::Authority {
        host_port: "http://example.com/",
      },
    ] {
      assert!(
        matches!(
          encode_request_head("GET", &target, none, &mut out),
          Err(Error::Protocol(H1Error::Malformed(_)))
        ),
        "{target:?}"
      );
    }
    for method in ["", "GE T", "G{}T", "GET\r\n"] {
      assert!(
        matches!(
          encode_request_head(method, &ORIGIN, none, &mut out),
          Err(Error::Protocol(H1Error::Malformed(_)))
        ),
        "{method:?}"
      );
    }
  }

  // RFC 9112 §2.1 with §11.1: a half-written head is a message a caller must
  // never send, so the size is settled BEFORE any byte moves and a short buffer
  // leaves `out` exactly as it was.
  #[test]
  fn a_short_buffer_leaves_the_output_untouched() {
    let mut out = [0xAAu8; 16];
    let hdrs: &[(&str, &[u8])] = &[("Host", b"example.com")];
    let err = encode_request_head("GET", &ORIGIN, hdrs, &mut out).unwrap_err();
    assert!(matches!(err, Error::BufferTooSmall { .. }));
    assert_eq!(out, [0xAAu8; 16]);
  }

  // RFC 9110 §5.5: `field-vchar` includes `obs-text` (0x80-0xFF), so an
  // outbound value is BYTES and a non-UTF-8 one goes out unchanged; a CTL —
  // NUL, VT, and above all a bare CR or LF — never does.
  #[test]
  fn field_values_carry_obs_text_but_never_control_bytes() {
    let mut out = [0u8; 64];
    let obs: &[(&str, &[u8])] = &[("X", b"caf\xC3\xA9\xFF")];
    let n = encode_request_head("GET", &ORIGIN, obs, &mut out).unwrap();
    assert_eq!(&out[..n], b"GET / HTTP/1.1\r\nX: caf\xC3\xA9\xFF\r\n\r\n");
    for bad in [b"a\x00b".as_slice(), b"a\rb", b"a\nb", b"a\x0Bb", b"a\x7Fb"] {
      let hdrs: &[(&str, &[u8])] = &[("X", bad)];
      // The offset names the offending byte within the VALUE, which is the only
      // input an outbound rejection has to position against.
      let Err(Error::Protocol(H1Error::Malformed(detail))) =
        encode_request_head("GET", &ORIGIN, hdrs, &mut out)
      else {
        panic!("{bad:?}")
      };
      assert_eq!(detail.at(), 1, "{bad:?}");
      assert_eq!(detail.what(), "control byte in the field value");
    }
  }

  // RFC 9110 §5.5 again: an empty field value is legal (`field-value` is
  // `*field-content`), and the encoder writes the line whole rather than
  // dropping a field it considers useless.
  #[test]
  fn an_empty_field_value_still_writes_its_line() {
    let mut out = [0u8; 64];
    let hdrs: &[(&str, &[u8])] = &[("X-Empty", b"")];
    let n = encode_request_head("GET", &ORIGIN, hdrs, &mut out).unwrap();
    assert_eq!(&out[..n], b"GET / HTTP/1.1\r\nX-Empty: \r\n\r\n");
  }

  // RFC 9110 §5.5: a value is bytes either way, so the `&str` impl and the
  // `&[u8]` impl differ only in what the caller happens to hold.
  #[test]
  fn str_valued_and_byte_valued_sections_encode_identically() {
    let mut text = [0u8; 64];
    let mut bytes = [0u8; 64];
    let as_str: &[(&str, &str)] = &[("Host", "example.com"), ("Upgrade", "websocket")];
    let as_bytes: &[(&str, &[u8])] = &[("Host", b"example.com"), ("Upgrade", b"websocket")];
    let n = encode_request_head("GET", &ORIGIN, as_str, &mut text).unwrap();
    let m = encode_request_head("GET", &ORIGIN, as_bytes, &mut bytes).unwrap();
    assert_eq!(n, m);
    assert_eq!(&text[..n], &bytes[..m]);
  }

  // RFC 9112 §4 `status-code = 3DIGIT`: exactly three, so 99 has no status-line
  // to appear in and 1000 would push a digit into the reason-phrase. RFC 9110
  // §15 gives the codes meaning; the grammar takes any three digits.
  #[test]
  fn status_codes_outside_the_sendable_range_are_refused() {
    let mut out = [0u8; 32];
    let none: &[(&str, &[u8])] = &[];
    // Below §4's three digits, above them, and — the sender rule — inside the
    // grammar but outside the five classes RFC 9110 §15 defines. §15 says
    // "values outside that range are invalid", so 600-999 are codes HTTP does
    // not have and this core will not write one.
    for bad in [0u16, 99, 600, 700, 999, 1000, u16::MAX] {
      assert!(
        matches!(
          encode_status_head(bad, b"", none, &mut out),
          Err(Error::InvalidState(_))
        ),
        "{bad}"
      );
    }
    // The boundaries of the range that IS sendable.
    let n = encode_status_head(100, b"Continue", none, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
    let n = encode_status_head(599, b"", none, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 599 \r\n\r\n");
  }

  // The RECIPIENT side keeps §4's grammar and nothing narrower, and the
  // asymmetry is the point: §15 tells a recipient to treat an unrecognised code
  // as the `x00` of its class, so a message it cannot classify is still one it
  // must FRAME correctly. Refusing to parse a 600 would invent a framing fault
  // out of a semantic one.
  #[test]
  fn the_recipient_still_parses_a_code_the_sender_may_not_write() {
    let view = scan_head(b"HTTP/1.1 600 Odd\r\n\r\n").unwrap();
    let status = crate::head::status_line::parse_status_line(view.start_line_bytes()).unwrap();
    assert_eq!(status.code, 600);
    let view = scan_head(b"HTTP/1.1 999 \r\n\r\n").unwrap();
    assert_eq!(
      crate::head::status_line::parse_status_line(view.start_line_bytes())
        .unwrap()
        .code,
      999
    );
  }

  // RFC 9112 §4 `reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )`: SP, HTAB
  // and obs-text are phrase CONTENT, while a CRLF would end the status-line
  // early and turn what follows into fields of a message the sender never wrote
  // (§11.1 response splitting).
  #[test]
  fn reason_phrases_take_text_but_never_a_line_break() {
    let mut out = [0u8; 64];
    let none: &[(&str, &[u8])] = &[];
    let n = encode_status_head(500, b"Erreur\tinterne \xC3\xA9", none, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 500 Erreur\tinterne \xC3\xA9\r\n\r\n");
    for bad in [
      b"OK\r\nX-Injected: y".as_slice(),
      b"OK\r",
      b"OK\n",
      b"Bad\x00",
    ] {
      assert!(
        encode_status_head(200, bad, none, &mut out).is_err(),
        "{bad:?}"
      );
    }
  }

  /// A supplier whose second walk yields a SHORTER section than its first — the
  /// draining-iterator shape the [`Headers`] contract warns about.
  struct Drifting {
    walked: Cell<bool>,
  }

  impl Headers for Drifting {
    fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), Error> {
      if !self.walked.replace(true) {
        f("X-Once", b"1");
      }
      Ok(())
    }
  }

  /// A supplier that refuses to produce a section at all.
  struct Refusing;

  impl Headers for Refusing {
    fn for_each(&self, _f: &mut dyn FnMut(&str, &[u8])) -> Result<(), Error> {
      Err(Error::InvalidState("supplier said no"))
    }
  }

  // The [`Headers`] idempotence contract, backstopped: the head is signed, then
  // measured, then written, so a supplier that changes between the walks would
  // put a head on the wire that is not the one this core framed (RFC 9112 §2.1).
  // Refused, not sent. (A supplier of the caller's own type is sized, so it is
  // passed as `&drifting` — the slice impls are the ones that must not be.)
  //
  // The refusal now lands in the MEASURING pass, so `out` is untouched: the
  // digest of the walk the decision was made over is compared before the size
  // check, and a section that has already changed has nothing to be sized for.
  #[test]
  fn a_supplier_that_changes_between_passes_is_refused() {
    let mut out = [0xAAu8; 64];
    let drifting = Drifting {
      walked: Cell::new(false),
    };
    assert_eq!(
      encode_request_head("GET", &ORIGIN, &drifting, &mut out),
      Err(Error::InvalidState(DRIFTED))
    );
    assert_eq!(out, [0xAAu8; 64]);
  }

  /// A supplier whose walks are the SAME LENGTH and different bytes — the shape
  /// a byte-count check cannot see.
  ///
  /// Walk one states `Content-Length: 5`; every walk after it states
  /// `Content-Length: 6`. Both sections encode to the same number of bytes, so
  /// the pre-digest cross-pass check compared two equal totals and passed.
  struct SameLengthDrift {
    /// Whether the first walk has happened.
    walked: Cell<bool>,
  }

  impl Headers for SameLengthDrift {
    fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), Error> {
      f("Host", b"h");
      if self.walked.replace(true) {
        f("Content-Length", b"6");
      } else {
        f("Content-Length", b"5");
      }
      Ok(())
    }
  }

  // The digest is over CONTENT, which is the whole reason it is a digest: two
  // sections of equal length that say different things about the message are
  // exactly the drift that matters, since what a length can hide is a framing
  // field's VALUE (RFC 9112 §6.3 item 6 — the peer reads the body at the length
  // the wire states, and this core would have committed to another).
  #[test]
  fn a_same_length_drift_is_refused_too() {
    let mut out = [0xAAu8; 64];
    let drifting = SameLengthDrift {
      walked: Cell::new(false),
    };
    assert_eq!(
      encode_request_head("POST", &ORIGIN, &drifting, &mut out),
      Err(Error::InvalidState(DRIFTED))
    );
    assert_eq!(out, [0xAAu8; 64]);
  }

  // What the digest is built to distinguish: the same bytes, split differently
  // between a name and a value, and the same total length. A digest that mixed
  // the bytes without their boundaries would call these two sections equal.
  #[test]
  fn the_digest_separates_a_name_from_its_value() {
    let ab_c: &[(&str, &[u8])] = &[("AB", b"C")];
    let a_bc: &[(&str, &[u8])] = &[("A", b"BC")];
    assert_ne!(
      field_digest(ab_c).unwrap(),
      field_digest(a_bc).unwrap(),
      "a name/value boundary is part of what is signed"
    );
    // And order is part of it too: RFC 9110 §5.3 makes the order of same-named
    // field lines significant, so two orderings are two sections.
    let one_two: &[(&str, &[u8])] = &[("A", b"1"), ("A", b"2")];
    let two_one: &[(&str, &[u8])] = &[("A", b"2"), ("A", b"1")];
    assert_ne!(
      field_digest(one_two).unwrap(),
      field_digest(two_one).unwrap()
    );
    // A section really is equal to itself, so the check is not vacuous.
    assert_eq!(field_digest(ab_c).unwrap(), field_digest(ab_c).unwrap());
    let none: &[(&str, &[u8])] = &[];
    assert_eq!(field_digest(none).unwrap(), FieldDigest::new());
  }

  // A supplier error aborts the encode with that error, and it does so in the
  // measuring pass — so nothing is written, exactly as for a rejected field.
  #[test]
  fn a_supplier_error_aborts_the_encode() {
    let mut out = [0xAAu8; 64];
    assert_eq!(
      encode_request_head("GET", &ORIGIN, &Refusing, &mut out),
      Err(Error::InvalidState("supplier said no"))
    );
    assert_eq!(out, [0xAAu8; 64]);
  }

  // RFC 9112 §2.1: what this core writes, this core reads. The encoded head is
  // scanned back by the head scanner and its start line re-parsed by the §3
  // codec, so the two directions cannot disagree about the message.
  #[test]
  fn an_encoded_head_scans_back_to_the_same_message() {
    let mut out = [0u8; 128];
    let hdrs: &[(&str, &[u8])] = &[("Host", b"example.com"), ("X-Empty", b"")];
    let n = encode_request_head(
      "POST",
      &Target::Origin {
        path_and_query: "/a?b=c",
      },
      hdrs,
      &mut out,
    )
    .unwrap();

    let view = scan_head(&out[..n]).unwrap();
    assert_eq!(view.field_count(), 2);
    assert_eq!(view.header("host"), Some(b"example.com".as_slice()));
    assert_eq!(view.header("x-empty"), Some(b"".as_slice()));

    let request_line = parse_request_line(view.start_line_bytes()).unwrap();
    assert_eq!(request_line.method, "POST");
    assert_eq!(
      request_line.target,
      Target::Origin {
        path_and_query: "/a?b=c"
      }
    );
    assert_eq!(request_line.version, Version::Http11);
  }

  // RFC 9112 §4 with §2.1: the same round trip for a response head, whose
  // status-line the §4 codec reads back with its phrase intact.
  #[test]
  fn an_encoded_status_head_scans_back_to_the_same_message() {
    let mut out = [0u8; 128];
    let hdrs: &[(&str, &str)] = &[("Upgrade", "websocket"), ("Connection", "Upgrade")];
    let n = encode_status_head(101, b"Switching Protocols", hdrs, &mut out).unwrap();

    let view = scan_head(&out[..n]).unwrap();
    assert_eq!(view.field_count(), 2);
    assert_eq!(view.header("upgrade"), Some(b"websocket".as_slice()));

    let status_line = crate::head::status_line::parse_status_line(view.start_line_bytes()).unwrap();
    assert_eq!(status_line.code, 101);
    assert_eq!(status_line.reason, b"Switching Protocols".as_slice());
    assert_eq!(status_line.version, Version::Http11);
  }
}
