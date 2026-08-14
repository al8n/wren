//! RFC 9112 §4 `status-line = HTTP-version SP status-code SP [ reason-phrase ]`.
//!
//! Strict single-SP parsing, as in the request-line: §4 lets a recipient "parse
//! on whitespace-delimited word boundaries" instead, and that leniency is
//! deliberately not taken here — §4 says so itself, since recipients that
//! disagree about where the status-line ends are the response-splitting
//! primitive (§11.1).
//!
//! Both SPs are required, the second one included: §4 makes a server MUST send
//! the space that separates the status-code from the reason-phrase "even when
//! the reason-phrase is absent", so `HTTP/1.1 200\r\n` is malformed rather than
//! a status-line with an empty phrase.

use super::{
  StartLine, malformed, split_before_sp, strip_crlf,
  version::{Version, parse_version},
};
use crate::{error::H1Error, grammar::is_field_vchar};

/// RFC 9112 §4 `status-code = 3DIGIT`: the code is exactly this many bytes.
const CODE_LEN: usize = 3;

/// A parsed RFC 9112 §4 status-line, borrowed from the line it was parsed from.
#[derive(Debug, Copy, Clone)]
pub struct StatusLine<'a> {
  /// The announced HTTP version.
  pub version: Version,
  /// The status code (RFC 9110 §15 defines what each one means).
  ///
  /// Grammar only: `3DIGIT`, so `099` and `999` parse, and `007` parses as `7`.
  /// Whether the code names a class a recipient may act on is a message-level
  /// rule, checked by head validation rather than here.
  pub code: u16,
  /// The reason-phrase, exactly as it arrived: HTAB / SP / VCHAR / obs-text,
  /// never trimmed, possibly empty, and not necessarily UTF-8 — RFC 9112 §4
  /// admits `obs-text`, and a phrase is routinely localized.
  ///
  /// Opaque on purpose: §4 gives the phrase no protocol meaning and says a
  /// client SHOULD ignore its content, so nothing here parses or normalizes it.
  pub reason: &'a [u8],
}

/// Parses one complete status-line, its terminating CRLF included.
///
/// `line` is exactly the bytes up to and including that CRLF. Offsets in the
/// errors are relative to the start of `line`, so a caller scanning a whole
/// head rebases them onto the head.
///
/// Rejects, all `Malformed` at the offset of the offending byte: a version that
/// is not `HTTP/<DIGIT>.<DIGIT>`, a status-code that is not exactly three ASCII
/// digits, a missing SP on either side of the code, a reason-phrase byte that
/// is neither HTAB/SP nor `VCHAR`/`obs-text`, a bare CR or LF inside the line,
/// and a missing CRLF terminator.
///
/// The one exception is the version, which behaves exactly as in the
/// request-line: a well-formed `HTTP/<DIGIT>.<DIGIT>` outside 1.x is
/// `VersionNotSupported` rather than `Malformed`.
// The head scanner delimits this line but deliberately does not parse it:
// response against request is the connection's context, not the scanner's, so
// the connection runs this codec over `HeadView::start_line_bytes`.
pub(crate) fn parse_status_line(line: &[u8]) -> Result<StatusLine<'_>, H1Error> {
  let body = strip_crlf(line, StartLine::Status)?;

  // The version opens the line, so its own offsets are already line offsets.
  let Some((version_bytes, after_version)) = split_before_sp(body) else {
    return Err(malformed(
      body.len(),
      "status-line has no SP after the HTTP-version",
    ));
  };
  let version = parse_version(version_bytes, 0)?;

  let code_at = version_bytes.len().saturating_add(1);
  let (code, reason) = parse_code(after_version, code_at)?;

  // §4 `reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )`, which the
  // status-line makes optional — an empty phrase after the mandatory SP is a
  // complete status-line, not a truncated one.
  let reason_at = code_at.saturating_add(CODE_LEN).saturating_add(1);
  if let Some(offset) = reason.iter().position(|&b| !is_reason_byte(b)) {
    return Err(malformed(
      reason_at.saturating_add(offset),
      "control byte in the reason-phrase",
    ));
  }

  Ok(StatusLine {
    version,
    code,
    reason,
  })
}

/// RFC 9112 §4 `status-code = 3DIGIT` plus the SP that must follow it. Returns
/// the code and the reason-phrase bytes after that SP; `at` is the offset of
/// `bytes` within the line.
fn parse_code(bytes: &[u8], at: usize) -> Result<(u16, &[u8]), H1Error> {
  let Some((digits, rest)) = bytes.split_at_checked(CODE_LEN) else {
    // The line ended inside the code: name the first byte that is not a digit,
    // or the end of the line if what little arrived was all digits.
    let offset = bytes
      .iter()
      .position(|b| !b.is_ascii_digit())
      .unwrap_or(bytes.len());
    return Err(malformed(
      at.saturating_add(offset),
      "status-code is not three digits",
    ));
  };
  if let Some(offset) = digits.iter().position(|b| !b.is_ascii_digit()) {
    return Err(malformed(
      at.saturating_add(offset),
      "status-code is not three digits",
    ));
  }
  // A fourth digit lands here too, and is reported as what it is: a byte where
  // the mandatory SP belongs.
  let Some(reason) = rest.strip_prefix(b" ") else {
    return Err(malformed(
      at.saturating_add(CODE_LEN),
      "expected SP after the status-code",
    ));
  };

  // Three ASCII digits are valid UTF-8 and at most 999, so neither step can
  // fail; both are answered rather than unwrapped, since a parser may not panic
  // on any input at all.
  let Some(code) = core::str::from_utf8(digits)
    .ok()
    .and_then(|digits| digits.parse::<u16>().ok())
  else {
    return Err(malformed(at, "status-code is not a three-digit number"));
  };
  Ok((code, reason))
}

/// RFC 9112 §4 `reason-phrase` content: `HTAB / SP / VCHAR / obs-text`.
///
/// Spelled out rather than borrowing the field-value validator: the byte set
/// coincides with a field value's, but `is_field_vchar` excludes SP and HTAB by
/// design — around a field value those are OWS, inside a phrase they are
/// content — and the two rules live in different grammars.
///
/// Visible to the module so `head::encode` holds an outbound phrase to the same
/// rule: a CRLF this predicate refuses inbound is a response the peer would
/// split in two if it were ever written outbound (§11.1).
pub(super) const fn is_reason_byte(b: u8) -> bool {
  is_field_vchar(b) || b == b' ' || b == b'\t'
}

#[cfg(test)]
mod tests {
  use super::*;

  // RFC 9112 §4: `status-line = HTTP-version SP status-code SP [ reason-phrase ]`
  // — the second SP is sent even when the phrase is absent, and the phrase
  // itself is `1*( HTAB / SP / VCHAR / obs-text )`.
  #[test]
  fn parses_status_lines() {
    let sl = parse_status_line(b"HTTP/1.1 200 OK\r\n").unwrap();
    assert_eq!(
      (sl.version, sl.code, sl.reason),
      (Version::Http11, 200, b"OK".as_slice())
    );
    // Empty reason with the mandatory SP.
    assert_eq!(parse_status_line(b"HTTP/1.1 101 \r\n").unwrap().reason, b"");
    // Reason may contain obs-text and SP/HTAB.
    assert_eq!(
      parse_status_line(b"HTTP/1.0 500 Erreur interne \xC3\xA9\r\n")
        .unwrap()
        .code,
      500
    );
  }

  // RFC 9112 §4: `status-code = 3DIGIT` and both SPs are single, mandatory
  // separators — the "parse on whitespace-delimited word boundaries" MAY is not
  // taken, because disagreeing recipients are the response-splitting primitive
  // (§11.1). RFC 9110 §5.5: a CTL is not `obs-text` and never phrase content.
  #[test]
  fn rejects_malformed_status_lines() {
    for bad in [
      b"HTTP/1.1 200\r\n".as_slice(),    // missing mandatory SP after code
      b"HTTP/1.1 20 OK\r\n",             // 2 digits
      b"HTTP/1.1 2000 OK\r\n",           // 4 digits
      b"HTTP/1.1 20x OK\r\n",            // non-digit
      b"HTTP/1.1  200 OK\r\n",           // double SP
      b"HTTP/1.1 200 Bad\x00Reason\r\n", // CTL in reason
    ] {
      assert!(parse_status_line(bad).is_err(), "{bad:?}");
    }
  }

  // RFC 9110 §6.2 with §15.6.6: a version outside 1.x is well-formed grammar
  // this core does not speak, which is `VersionNotSupported` (505) rather than a
  // malformed status line (400). Moved out of the malformed list above and given
  // its own pin, because `is_err()` there could not tell the two apart — and the
  // difference is the status a driver reports. The request-line codec carries the
  // mirror of this pin.
  #[test]
  fn a_version_outside_1_x_is_unsupported_not_malformed() {
    let unsupported = parse_status_line(b"HTTP/2.0 200 OK\r\n").unwrap_err();
    assert_eq!(unsupported, H1Error::VersionNotSupported);
    assert_eq!(
      unsupported.suggested_status(),
      crate::SuggestedStatus::VersionNotSupported
    );
    // …while a version that is merely a HIGHER MINOR is processed as 1.1
    // (RFC 9110 §6.2's SHOULD), so the refusal above is about the MAJOR.
    assert_eq!(
      parse_status_line(b"HTTP/1.7 200 OK\r\n").unwrap().version,
      Version::Http11
    );
  }

  // RFC 9112 §4 with §2.2 (bare CR/LF is not a terminator): the offset names the
  // offending byte, relative to the start of the line.
  #[test]
  fn error_offsets_point_at_offender() {
    let offset_of = |line: &[u8]| match parse_status_line(line) {
      Err(H1Error::Malformed(d)) => d.at(),
      other => panic!("expected Malformed, got {other:?}"),
    };
    // The SP the code must be followed by, missing at the end of the line.
    assert_eq!(offset_of(b"HTTP/1.1 200\r\n"), 12);
    // A fourth digit occupies that same mandatory-SP position.
    assert_eq!(offset_of(b"HTTP/1.1 2000 OK\r\n"), 12);
    // A short code is reported where its third digit belongs, a non-digit at
    // itself, and a doubled SP at the first byte of the code field.
    assert_eq!(offset_of(b"HTTP/1.1 20 OK\r\n"), 11);
    assert_eq!(offset_of(b"HTTP/1.1 20x OK\r\n"), 11);
    assert_eq!(offset_of(b"HTTP/1.1  200 OK\r\n"), 9);
    // The same two faults with the line ending before the code completes.
    assert_eq!(offset_of(b"HTTP/1.1 20\r\n"), 11);
    assert_eq!(offset_of(b"HTTP/1.1 2x\r\n"), 10);
    // Inside the phrase, and at the terminator.
    assert_eq!(offset_of(b"HTTP/1.1 200 Bad\x00Reason\r\n"), 16);
    assert_eq!(offset_of(b"HTTP/1.1 200 OK\n"), 15);
    assert_eq!(offset_of(b"HTTP/1.1 200 OK"), 15);
    assert_eq!(offset_of(b"HTTP/1.1 200 O\rK\r\n"), 14);
  }

  // RFC 9112 §4 (`3DIGIT`, no value constraint) and RFC 9110 §15 (which class a
  // code belongs to is message semantics): parsing takes any three digits, and
  // a phrase is opaque bytes that are neither trimmed nor decoded.
  #[test]
  fn code_is_grammar_only_and_reason_is_opaque() {
    assert_eq!(parse_status_line(b"HTTP/1.1 999 \r\n").unwrap().code, 999);
    // Leading zeros are digits like any other; the value is what they spell.
    assert_eq!(parse_status_line(b"HTTP/1.1 007 x\r\n").unwrap().code, 7);
    // Interior SP/HTAB and trailing SP all survive verbatim.
    let sl = parse_status_line(b"HTTP/1.1 200 \tNo\tGood \r\n").unwrap();
    assert_eq!(sl.reason, b"\tNo\tGood ".as_slice());
    assert_eq!(
      parse_status_line(b"HTTP/1.0 404 Not Found\r\n")
        .unwrap()
        .version,
      Version::Http10
    );
  }
}
