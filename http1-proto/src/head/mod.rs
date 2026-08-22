//! The message head: the RFC 9112 §2.1 `start-line`, the `field-line`s that
//! follow it, and the scanner that delimits both.
//!
//! One rule underlies everything here and lives in exactly one place
//! (`delimit_line`): a line ends at CRLF and nowhere else (§2.2). A bare CR, a
//! bare LF, and a CR whose LF never arrives are the request-smuggling primitive
//! §11.2 warns about — recipients that disagree about where a line ends — so a
//! line counts as terminated only once both bytes are present, and a lone
//! trailing CR is inconclusive rather than a violation, since its LF may be in
//! the next read.
//!
//! Byte offsets follow the input each function was handed: a start-line codec
//! parses ONE line and reports offsets within that line, while the scanner
//! reports offsets within the whole head block and rebases the grammar
//! validators' value-relative offsets onto it.

use crate::{
  error::{H1Error, MalformedDetail},
  grammar::{is_token_byte, trim_ows, validate_field_value},
};

// `pub(crate)` rather than private: the receive path (`scan`) and the two
// start-line codecs are what `crate::validate` and the connection state machine
// are handed a head through, and both live outside this module; the send path
// (`encode`) is the same in reverse, and `body::encode` reaches its
// field-section machinery the way `body::chunked` reaches `validate_field_line`.
// Their items stay `pub(crate)`, so this widens where a crate-internal name can
// be reached, not what the crate publishes.
pub(crate) mod encode;
pub(crate) mod request_line;
pub(crate) mod scan;
pub(crate) mod status_line;
mod version;
mod view;

pub use encode::Headers;
pub use request_line::{RequestLine, Target};
pub use scan::{MAX_HEAD_BYTES, MAX_HEADERS};
pub use status_line::StatusLine;
pub use version::Version;
pub use view::{FieldsIter, HeadView};

// The receive path as the connection state machine uses it: delimit a head over
// a growing buffer, validate the block once it is whole, and run the start-line
// codec the caller's context picks. Re-exported here so the connection names one
// module rather than three submodules.
//
// `scan::KeyFields` and `scan::MAX_LEADING_EMPTY_LINES` are deliberately NOT in
// this list: nothing outside `head` names either (validation reads the record
// through `HeadView`, and the empty-line bound is enforced inside
// `skip_leading_empty_lines`), and an unused `pub(crate) use` is an
// `unused_imports` warning — which this crate's gate turns into an error. Both
// stay reachable as `head::scan::…`, which is what the tests that pin the bound
// use.
pub(crate) use request_line::parse_request_line;
pub(crate) use scan::{find_head_end, scan_head, skip_leading_empty_lines};
pub(crate) use status_line::parse_status_line;

/// Builds a positioned grammar violation, `at` being an offset within whatever
/// input the caller reports positions against — a line for the start-line
/// codecs, the block for the scanner, the fed slice for a body.
pub(crate) fn malformed(at: usize, what: &'static str) -> H1Error {
  H1Error::Malformed(MalformedDetail::new(at, what))
}

/// Splits at the first SP into the field before it and everything after it.
/// `None` when there is no SP at all.
///
/// Both start lines are SP-delimited and both take single SPs only, so a field
/// that ends at the first SP is the shared shape: a second SP lands at the
/// start of the NEXT field, where it fails that field's grammar and is reported
/// at its own offset.
fn split_before_sp(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
  let sp = bytes.iter().position(|&b| b == b' ')?;
  let (field, rest) = bytes.split_at_checked(sp)?;
  let (_sp, rest) = rest.split_first()?;
  Some((field, rest))
}

/// Where the line that starts at the beginning of a slice ends (RFC 9112 §2.2).
pub(crate) enum LineEnd<'a> {
  /// A CRLF terminated the line: `body` is the line without that CRLF, and
  /// `end` is the offset just past it.
  Crlf {
    /// The line's content, terminator excluded.
    body: &'a [u8],
    /// Offset just past the CRLF — where the next line begins.
    end: usize,
  },
  /// Nothing is proven yet: the slice holds neither CR nor LF, or it ends in a
  /// lone CR whose LF may arrive in the next read.
  Partial,
  /// A bare CR or a bare LF at this offset. Never a line terminator, and — a CR
  /// at the very end of the slice aside — never rescuable by more bytes.
  Bare(usize),
}

/// Delimits the line that starts at the beginning of `rest`.
///
/// The first CR or LF is where that line has to end: RFC 9112 §2.2 admits CRLF
/// and nothing else as a terminator, so an LF reached before any CR is bare,
/// and a CR is a terminator only once the following byte proves it one. A CR at
/// the very end of `rest` proves nothing — its LF may be in the next read — and
/// that single case is what lets an incremental scan run over a buffer that
/// splits a CRLF without condemning it.
///
/// Every line rule in the CRATE goes through here: the two start-line codecs,
/// the head scanner, the view that re-walks a scanned block, and the chunked
/// body's own framing lines (RFC 9112 §7.1), so the terminator invariant has
/// exactly one implementation to audit. A chunked body is delimited by lines
/// the same §2.2 governs, and a second implementation of that rule is exactly
/// the recipient disagreement §11.2 is about.
pub(crate) fn delimit_line(rest: &[u8]) -> LineEnd<'_> {
  let Some(at) = rest.iter().position(|&b| b == b'\r' || b == b'\n') else {
    return LineEnd::Partial;
  };
  // `at` came from a search over `rest`, so the split is always in range;
  // `Partial` is the conservative answer if it somehow were not, since it
  // claims nothing about bytes the function could not read.
  let Some((body, terminator)) = rest.split_at_checked(at) else {
    return LineEnd::Partial;
  };
  match terminator {
    [b'\r'] => LineEnd::Partial,
    [b'\r', b'\n', ..] => LineEnd::Crlf {
      body,
      end: at.saturating_add(2),
    },
    // A bare LF, or a CR the next byte disproved.
    _ => LineEnd::Bare(at),
  }
}

/// Which start line a codec is reading. Selects the wording of the shared
/// terminator diagnostics; the rules themselves are the same for both, since
/// RFC 9112 §2.2 delimits every line of a head the same way.
#[derive(Debug, Copy, Clone)]
enum StartLine {
  /// The §3 `request-line`.
  Request,
  /// The §4 `status-line`.
  Status,
}

impl StartLine {
  /// Diagnostic for a line that never reaches a CRLF.
  const fn unterminated(self) -> &'static str {
    match self {
      Self::Request => "request-line does not end with CRLF",
      Self::Status => "status-line does not end with CRLF",
    }
  }

  /// Diagnostic for a bare CR or LF inside the line.
  const fn bare(self) -> &'static str {
    match self {
      Self::Request => "bare CR or LF inside the request-line",
      Self::Status => "bare CR or LF inside the status-line",
    }
  }

  /// Diagnostic for bytes past the line's terminator.
  const fn trailing(self) -> &'static str {
    match self {
      Self::Request => "trailing bytes after the request-line",
      Self::Status => "trailing bytes after the status-line",
    }
  }
}

/// Strips the mandatory CRLF from the one complete line a start-line codec was
/// handed, returning the line's content.
///
/// The codecs are handed a line the scanner already delimited, so this repeats
/// what the scanner concluded rather than trusting it: a codec called directly
/// — as the tests and any caller holding a line from elsewhere do — enforces
/// RFC 9112 §2.2 for itself, out of the same `delimit_line` the scanner used.
fn strip_crlf(line: &[u8], kind: StartLine) -> Result<&[u8], H1Error> {
  match delimit_line(line) {
    LineEnd::Crlf { body, end } if end == line.len() => Ok(body),
    // A terminator with bytes behind it means the caller passed more than the
    // one line the codec parses.
    LineEnd::Crlf { end, .. } => Err(malformed(end, kind.trailing())),
    // The line was handed over whole, so an unfinished terminator is not a
    // short read here: it is a line that never terminates.
    LineEnd::Partial => Err(malformed(line.len(), kind.unterminated())),
    LineEnd::Bare(at) => Err(malformed(at, kind.bare())),
  }
}

/// A field line split into its parts (RFC 9112 §5:
/// `field-line = field-name ":" OWS field-value OWS`).
///
/// Splitting only: as `split_field` produces it the name is unvalidated bytes,
/// since [`validate_field_line`] is what checks it against `token` and reports
/// which byte broke it.
pub(crate) struct Field<'a> {
  /// The bytes before the colon.
  pub(crate) name: &'a [u8],
  /// The value with the OWS around it removed (RFC 9110 §5.5), which may be
  /// empty — `field-value = *field-content` admits `Host:`.
  pub(crate) value: &'a [u8],
  // gate-exempt: crate::grammar::validate_field_value — names the function
  // that PRODUCES the offset this field stores; the field is plain data, it
  // does not call the function that computed the value it holds.
  /// Offset of `value` within the line, so a caller can rebase a value-relative
  /// offset (what `crate::grammar::validate_field_value` reports) onto the head.
  pub(crate) value_at: usize,
}

/// Splits a field line at its first colon. `None` when the line has no colon at
/// all, which is a field line with no name-value boundary in it.
fn split_field(body: &[u8]) -> Option<Field<'_>> {
  let colon = body.iter().position(|&b| b == b':')?;
  let (name, rest) = body.split_at_checked(colon)?;
  let (_colon, raw) = rest.split_first()?;
  // Where the value begins once §5.6.3 OWS is off the front. `trim_ows` does
  // the trimming; this only measures the front of it, because the span the
  // scanner records and the offsets its errors carry both need the distance.
  let lead = raw
    .iter()
    .position(|&b| b != b' ' && b != b'\t')
    .unwrap_or(raw.len());
  Some(Field {
    name,
    value: trim_ows(raw),
    value_at: colon.saturating_add(1).saturating_add(lead),
  })
}

/// Validates one field line and returns its parts.
///
/// Four rules, and a peer that broke any of them is describing a different
/// field to the next recipient than to this one: a `token` name (RFC 9110
/// §5.6.2) with no whitespace before its colon (RFC 9112 §5.1), a value of
/// `field-vchar`/SP/HTAB once OWS is trimmed (RFC 9110 §5.5, `obs-text`
/// included), and no obs-fold continuation line (RFC 9112 §5.2).
///
/// ONE implementation, and both field sections of a message run through it.
/// RFC 9112 §7.1.2 gives the trailer section "the same syntax as the header
/// section", so it gets the same code: a field a sender moved out of the head
/// and into the trailers must not find a looser parser waiting for it there.
///
/// `at` is where the line begins within whatever input the caller reports
/// offsets against, so every error carries an absolute position there; a caller
/// whose input starts at the line passes 0.
///
/// `first` chooses between the two readings of a line that opens with
/// whitespace. Before a head's FIRST field line that is the whitespace §2.2
/// forbids after the start-line; anywhere else — including everywhere in a
/// trailer section, which has no start-line at all — it is §5.2 obs-fold. Both
/// are rejected; only the diagnosis differs.
pub(crate) fn validate_field_line(
  body: &[u8],
  at: usize,
  first: bool,
) -> Result<Field<'_>, H1Error> {
  if matches!(body.first(), Some(b' ' | b'\t')) {
    return Err(malformed(
      at,
      if first {
        "whitespace between the start-line and the first field line"
      } else {
        "obsolete line folding"
      },
    ));
  }

  let Some(field) = split_field(body) else {
    return Err(malformed(
      at.saturating_add(body.len()),
      "field line has no colon",
    ));
  };

  // RFC 9110 §5.6.2: `token = 1*tchar`, so an empty name is not a degenerate
  // name but a missing one.
  let Some((&last, _)) = field.name.split_last() else {
    return Err(malformed(at, "empty field name"));
  };
  // RFC 9112 §5.1: a server MUST reject whitespace between a field name and its
  // colon — a recipient that trimmed it instead would disagree with one that
  // did not about the field's name. Diagnosed ahead of the token check, which
  // would otherwise report SP and HTAB as ordinary non-token bytes.
  if last == b' ' || last == b'\t' {
    return Err(malformed(
      at.saturating_add(field.name.len()).saturating_sub(1),
      "whitespace between the field name and colon",
    ));
  }
  if let Some(offset) = field.name.iter().position(|&b| !is_token_byte(b)) {
    return Err(malformed(
      at.saturating_add(offset),
      "field name is not a token",
    ));
  }

  // `validate_field_value` reports offsets within the trimmed value it was
  // handed, so they are rebased past the name, the colon, and the OWS.
  if let Err(offset) = validate_field_value(field.value) {
    return Err(malformed(
      at.saturating_add(field.value_at).saturating_add(offset),
      "control byte in the field value",
    ));
  }
  Ok(field)
}
