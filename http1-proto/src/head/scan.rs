//! The head scanner: the bounded search for the end of a head, and the single
//! forward pass that validates the field lines inside it.
//!
//! Two bounds keep a head from being a lever on memory or CPU: `MAX_HEAD_BYTES`
//! caps the block a peer may spend before terminating it, and `MAX_HEADERS`
//! caps how many field lines it may pack into that block. Neither needs an
//! allocator — the scan borrows the caller's buffer and records only what the
//! core reads back later (`KeyFields`), never a field table.
//!
//! Reading a head is two steps, because they answer different questions and run
//! at different times. `find_head_end` answers "has the peer finished sending a
//! head?" over a buffer that is still growing, and is resumable so that
//! repeated feeds stay O(n) in total. `scan_head` answers "is this head
//! well-formed, and what is in it?" over the finished block, in one forward
//! pass.

use super::{LineEnd, delimit_line, malformed, validate_field_line, view::HeadView};
use crate::{
  error::H1Error,
  grammar::{Expectations, eq_ignore_ascii, skip_ows, token_end},
};

/// Bytes a whole head may occupy, its terminating empty line included.
///
/// RFC 9110 §5.4 leaves the size of a field section to the recipient and
/// requires only that exceeding it be answered (RFC 6585 §5: 431). 16 KiB sits
/// above RFC 9112 §3's recommended 8000-octet request-line floor with room for
/// the fields around it, and keeps a head inside a single page.
pub const MAX_HEAD_BYTES: usize = 16384;

/// The RFC 9112 §3 floor: "It is RECOMMENDED that all HTTP senders and
/// recipients support, at a minimum, request-line lengths of 8000 octets."
const RECOMMENDED_REQUEST_LINE_FLOOR: usize = 8000;

// The recommendation as a compile-time fact rather than a comment, evaluated on
// every target the crate is checked against. The request-line is the first thing
// in the block, so the head cap IS what bounds it.
const _: () = assert!(MAX_HEAD_BYTES >= RECOMMENDED_REQUEST_LINE_FLOOR);

/// Field lines a single head may carry (RFC 9110 §5.4).
///
/// The byte cap alone does not bound the work: thousands of one-byte fields fit
/// inside it, and every one of them is a lookup a later consumer pays for.
pub const MAX_HEADERS: usize = 64;

/// Empty lines a server skips before a request-line (RFC 9112 §2.2).
pub(crate) const MAX_LEADING_EMPTY_LINES: usize = 4;

/// Bytes a resumed scan re-reads: the head's CRLFCRLF terminator straddles the
/// watermark by at most its first three bytes.
const RESUME_OVERLAP: usize = 3;

/// RFC 9112 §2.2, and §11.2 for why it is a MUST rather than a preference.
const BARE_CR_OR_LF: &str = "bare CR or LF in the head";

/// Byte range of a field value within the head block, OWS already trimmed off
/// (RFC 9110 §5.5).
///
/// Recorded during the scan for the few values the core reads back, so that
/// validation does not walk the block again to find them. A span costs eight
/// bytes and no allocator, and the block it indexes outlives the view.
#[derive(Debug, Copy, Clone)]
pub(crate) struct FieldSpan {
  /// Offset of the value's first byte within the head block.
  start: u32,
  /// Length of the trimmed value. Zero is a legal value, not a sentinel:
  /// `field-value = *field-content` admits a bare `Host:`.
  len: u32,
}

impl FieldSpan {
  /// Records a span, narrowing head offsets to the `u32` the view stores.
  ///
  /// `None` when they do not fit, which `MAX_HEAD_BYTES` makes impossible for
  /// any block `scan_head` accepted — the conversion is checked rather than
  /// truncating a span onto the wrong bytes if that guard ever moves.
  fn new(start: usize, len: usize) -> Option<Self> {
    Some(Self {
      start: u32::try_from(start).ok()?,
      len: u32::try_from(len).ok()?,
    })
  }

  /// The bytes this span covers, within the head block it was recorded in.
  ///
  /// `None` if `head` is not that block: a span is only meaningful against the
  /// slice it was measured on. Reached through
  /// [`HeadView::key_value`](crate::head::HeadView::key_value), which pairs a
  /// span with the block it was measured on by construction.
  pub(crate) fn value_in<'a>(&self, head: &'a [u8]) -> Option<&'a [u8]> {
    let start = usize::try_from(self.start).ok()?;
    let len = usize::try_from(self.len).ok()?;
    head.get(start..)?.get(..len)
  }

  /// Offset of the value's first byte within the head block, for the errors
  /// message validation reports against a field it read back.
  ///
  /// The block cap keeps every recorded offset well inside `u32`, and every
  /// platform this builds for has a `usize` at least that wide; a platform
  /// where it is not reports the head's start rather than an offset that would
  /// name the wrong byte.
  pub(crate) fn value_at(&self) -> usize {
    usize::try_from(self.start).unwrap_or(0)
  }
}

/// What the single scan records for the fields whose values the core reads back
/// — RFC 9110 §7.2 `Host`, and the RFC 9112 §6 framing fields — plus the token
/// facts carried by the list-typed fields.
///
/// Counts saturate, and the field cap keeps a real head three orders of
/// magnitude below `u8::MAX`, so a duplicate count can never wrap back into a
/// legal-looking 1.
///
/// The token facts fold across EVERY line of their field: RFC 9110 §5.2 makes
/// repeated list-typed fields equivalent to one comma-joined line, so
/// `Connection: keep-alive` followed by `Connection: Upgrade` has to register
/// both. They are recorded version-agnostically — applying HTTP/1.0's
/// ignore-rules for `Upgrade` and `Expect` is validation's job, which needs the
/// facts to be there to ignore.
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct KeyFields {
  /// Value of the first `Host` line (RFC 9110 §7.2).
  pub host: Option<FieldSpan>,
  /// How many `Host` lines arrived; RFC 9112 §3.2 allows exactly one.
  pub host_count: u8,
  /// Value of the first `Content-Length` line (RFC 9110 §8.6). Repeats combine
  /// as one list, which validation walks with
  /// [`HeadView::header_all`](crate::head::HeadView::header_all).
  pub content_length: Option<FieldSpan>,
  /// How many `Content-Length` lines arrived (RFC 9112 §6.3 rejects
  /// disagreeing repeats).
  pub content_length_count: u8,
  /// Value of the first `Transfer-Encoding` line (RFC 9112 §6.1). Repeats
  /// combine as one list, which validation walks with
  /// [`HeadView::header_all`](crate::head::HeadView::header_all).
  pub transfer_encoding: Option<FieldSpan>,
  /// How many `Transfer-Encoding` lines arrived.
  pub transfer_encoding_count: u8,
  /// `Connection: close` on any line (RFC 9112 §9.6).
  pub connection_close: bool,
  /// `Connection: keep-alive` on any line (RFC 9112 §9.3).
  pub connection_keep_alive: bool,
  /// `Connection: upgrade` on any line (RFC 9110 §7.8).
  pub connection_upgrade: bool,
  /// An `Upgrade` field is present (RFC 9110 §7.8).
  pub has_upgrade_field: bool,
  /// RFC 9110 §10.1.1's `Expect`, accumulated across every field line of the
  /// section and NOT yet reduced to a fact.
  ///
  /// The accumulator rather than the two booleans it answers, because the
  /// answers are only sound once the whole combined value has been pushed:
  /// `Expect: 100-continue, @` fails the field's grammar, and a fact committed
  /// when its first member parsed delivered the ask anyway. `validate` derives
  /// both facts from a finished value — see `connection_directives`.
  pub expect: Expectations,
  /// RFC 9110 §7.6.1 `Connection` did not parse, so NO option may be derived
  /// from it — see `fold_connection_options`.
  pub connection_malformed: bool,
}

/// Finds the end of a head — the index just past its terminating CRLFCRLF —
/// within `input`, resumably.
///
/// `from` is the watermark of bytes a previous call already scanned over the
/// same append-only buffer. Only the terminator that straddles that watermark
/// is re-read (three bytes), which is what keeps repeated feeds O(n) in total
/// instead of O(n²) as a buffer grows.
///
/// `Ok(None)` means the terminator is not visible yet: the caller keeps
/// accumulating and stores the new watermark. A lone CR as the LAST byte of
/// `input` is inconclusive — its LF may be in the next read — so it yields
/// `Ok(None)` and never a bare-CR error; a bare CR or LF is only reported once
/// the following byte has disproven it (RFC 9112 §2.2).
///
/// Enforces the byte cap: once `input` has reached `MAX_HEAD_BYTES` with no
/// terminator inside it, no continuation can produce a head that fits, so the
/// scan fails there rather than buffering further. Which failure depends on
/// whether a single CRLF ever arrived — see `cap_error`.
///
/// `input` must begin at the start line: leading empty lines are
/// `skip_leading_empty_lines`' business, and an input that still carries them
/// would present one of them as the head's terminator.
pub(crate) fn find_head_end(input: &[u8], from: usize) -> Result<Option<usize>, H1Error> {
  let limit = input.len().min(MAX_HEAD_BYTES);
  let resume = from.min(input.len()).saturating_sub(RESUME_OVERLAP);
  let (mut at, mut line_start) = resume_point(input, resume);

  // `get` returns None once the cursor passes the cap, which ends the walk the
  // same way an unterminated tail does.
  while let Some(rest) = input.get(at..limit) {
    match delimit_line(rest) {
      LineEnd::Crlf { body, end } => {
        // An empty line ends the head — but only where a line really begins. A
        // resumed scan can start inside one, and the tail of a field line is
        // not an empty line however short it is.
        if line_start && body.is_empty() {
          return Ok(Some(at.saturating_add(end)));
        }
        at = at.saturating_add(end);
        line_start = true;
      }
      LineEnd::Partial => break,
      LineEnd::Bare(offset) => return Err(malformed(at.saturating_add(offset), BARE_CR_OR_LF)),
    }
  }

  if input.len() >= MAX_HEAD_BYTES {
    return Err(cap_error(input.get(..limit).unwrap_or(input)));
  }
  Ok(None)
}

/// Where a resumed scan may start delimiting, and whether that offset begins a
/// line.
///
/// The overlap-adjusted watermark can land anywhere, including on the LF of a
/// CRLF an earlier call already read — where taking the LF at face value would
/// condemn a legal terminator as a bare one — and in the middle of a field
/// line, where the tail it delimits must not be mistaken for the empty line
/// that ends a head. One byte of lookback settles both.
fn resume_point(input: &[u8], resume: usize) -> (usize, bool) {
  let previous = resume.checked_sub(1).and_then(|i| input.get(i)).copied();
  match (previous, input.get(resume).copied()) {
    // The buffer's first byte opens the start line.
    (None, _) => (resume, true),
    // The watermark split a CRLF: the line begins one byte later.
    (Some(b'\r'), Some(b'\n')) => (resume.saturating_add(1), true),
    // A CRLF ended just before the watermark.
    (Some(b'\n'), _) => (resume, true),
    // Mid-line: what this delimits is the tail of a line that began earlier.
    _ => (resume, false),
  }
}

/// Which cap a head that never terminated broke.
///
/// RFC 9112 §3 makes an over-long request-target a MUST-414 and RFC 9110 §5.4
/// with RFC 6585 §5 makes an over-large field section a 431, so the two answers
/// differ and the scanner has to tell them apart. Without a single CRLF in
/// everything received, nothing but the request-line has arrived at all. The
/// re-scan is one pass on a path that ends the connection, not on the parsing
/// path.
fn cap_error(scanned: &[u8]) -> H1Error {
  if scanned.windows(2).any(|pair| pair == b"\r\n") {
    H1Error::HeadTooLarge(MAX_HEAD_BYTES)
  } else {
    H1Error::RequestLineTooLong(MAX_HEAD_BYTES)
  }
}

/// Skips the empty lines a server tolerates before a request-line, returning
/// how many bytes to drop.
///
/// RFC 9112 §2.2: "a server that is expecting to receive and parse a
/// request-line SHOULD ignore at least one empty line (CRLF) received prior to
/// the request-line" — the CRLF an HTTP/1.0 client trailed its last request
/// with is why. The allowance is bounded, because unbounded it is a free
/// keep-alive channel for a peer that never sends a request.
///
/// Only whole CRLF pairs count, so a bare CR or LF is left in place for the
/// scanner to reject where it sits.
pub(crate) fn skip_leading_empty_lines(input: &[u8]) -> Result<usize, H1Error> {
  let mut at = 0usize;
  let mut lines = 0usize;
  while input
    .get(at..)
    .is_some_and(|rest| rest.starts_with(b"\r\n"))
  {
    lines = lines.saturating_add(1);
    if lines > MAX_LEADING_EMPTY_LINES {
      return Err(malformed(at, "too many empty lines before the start-line"));
    }
    at = at.saturating_add(2);
  }
  Ok(at)
}

/// Scans and validates a complete head block, returning the lazy view of it.
///
/// `head` is exactly the block `find_head_end` measured: the start line, the
/// field lines, and the empty line that ends them, both CRLFs of the terminator
/// included. Anything past that empty line is a caller error and is refused
/// rather than ignored.
///
/// One forward pass validates every field line — a `token` name (RFC 9110
/// §5.6.2) with no whitespace before its colon (RFC 9112 §5.1), a value of
/// `field-vchar`/SP/HTAB once OWS is trimmed (RFC 9110 §5.5, `obs-text`
/// included), no obs-fold continuation line (RFC 9112 §5.2), and no whitespace
/// where the first field name belongs (§2.2) — counts the lines against
/// `MAX_HEADERS`, and records `KeyFields`. No field table is built: the view
/// re-walks the block on demand.
///
/// The start line is delimited but NOT parsed. Whether it is a request-line or
/// a status-line is the caller's context, so the caller runs the matching codec
/// over `HeadView::start_line_bytes`.
pub(crate) fn scan_head(head: &[u8]) -> Result<HeadView<'_>, H1Error> {
  // Every offset the view stores is a u32 that the cap makes exact. A block
  // over the cap never came from `find_head_end`; it is refused here rather
  // than silently truncated into one.
  if head.len() > MAX_HEAD_BYTES {
    return Err(H1Error::HeadTooLarge(MAX_HEAD_BYTES));
  }

  let start_line_end = match delimit_line(head) {
    // RFC 9112 §2.1 puts a start-line before the field lines, so the first
    // empty line of a head can never be its first line.
    LineEnd::Crlf { body: [], .. } => {
      return Err(malformed(0, "head begins with an empty line"));
    }
    LineEnd::Crlf { end, .. } => end,
    LineEnd::Partial => return Err(malformed(head.len(), "head has no start-line")),
    LineEnd::Bare(at) => return Err(malformed(at, BARE_CR_OR_LF)),
  };

  let mut at = start_line_end;
  let mut field_count: u16 = 0;
  let mut key = KeyFields::default();

  loop {
    let Some(rest) = head.get(at..) else {
      return Err(malformed(
        head.len(),
        "head does not end with an empty line",
      ));
    };
    let (body, end) = match delimit_line(rest) {
      LineEnd::Crlf { body, end } => (body, end),
      LineEnd::Partial => {
        return Err(malformed(
          head.len(),
          "head does not end with an empty line",
        ));
      }
      LineEnd::Bare(offset) => return Err(malformed(at.saturating_add(offset), BARE_CR_OR_LF)),
    };

    if body.is_empty() {
      let end_of_head = at.saturating_add(end);
      if end_of_head != head.len() {
        return Err(malformed(end_of_head, "trailing bytes after the head"));
      }
      let Ok(start_line_end) = u32::try_from(start_line_end) else {
        return Err(H1Error::HeadTooLarge(MAX_HEAD_BYTES));
      };
      return Ok(HeadView::new(head, start_line_end, field_count, key));
    }

    field_count = field_count.saturating_add(1);
    if usize::from(field_count) > MAX_HEADERS {
      return Err(H1Error::TooManyHeaders(MAX_HEADERS));
    }
    scan_field(body, at, field_count == 1, &mut key)?;
    at = at.saturating_add(end);
  }
}

/// Validates one field line and folds it into `key`. `at` is the offset of the
/// line within the head block, so every offset this reports is absolute there.
///
/// The grammar itself is `super::validate_field_line`, which the body's trailer
/// section shares (RFC 9112 §7.1.2); what is left here is the span recording
/// that only a head needs.
fn scan_field(body: &[u8], at: usize, first: bool, key: &mut KeyFields) -> Result<(), H1Error> {
  let field = validate_field_line(body, at, first)?;

  let value_at = at.saturating_add(field.value_at);
  let Some(span) = FieldSpan::new(value_at, field.value.len()) else {
    return Err(H1Error::HeadTooLarge(MAX_HEAD_BYTES));
  };

  record_key_field(field.name, field.value, span, key);
  Ok(())
}

/// RFC 9110 §7.6.1 `Connection = #connection-option`, where
/// `connection-option = token`, folded into the three facts this core keeps.
///
/// PARSED, not pattern-matched. A member that is not a token means the field is
/// not a `Connection` header at all, and this core may not pick the members it
/// happens to recognise out of a value it could not read: `Connection:
/// upgrade,@` was setting the upgrade fact and could authorise a protocol
/// switch off a field whose real meaning is unknown.
///
/// RFC 9110 §5.2 makes every line one list, so the facts accumulate — and so
/// does `malformed`, since one bad line spoils the value they are all part of.
/// No quoted-string can appear in this grammar, so nothing here spans the join.
fn fold_connection_options(key: &mut KeyFields, value: &[u8]) {
  let mut at = 0usize;
  loop {
    at = skip_ows(value, at);
    let start = at;
    // §5.6.1.2: an empty element contributes nothing.
    if !matches!(value.get(at), None | Some(b',')) {
      let Some(end) = token_end(value, at) else {
        key.connection_malformed = true;
        return;
      };
      at = skip_ows(value, end);
      // Between one option and the next there is a comma and nothing else.
      if !matches!(value.get(at), None | Some(b',')) {
        key.connection_malformed = true;
        return;
      }
      let option = value.get(start..end).unwrap_or_default();
      key.connection_close |= eq_ignore_ascii(option, "close");
      key.connection_keep_alive |= eq_ignore_ascii(option, "keep-alive");
      key.connection_upgrade |= eq_ignore_ascii(option, "upgrade");
    }
    if value.get(at).is_none() {
      return;
    }
    at = at.saturating_add(1);
  }
}

/// Folds one validated field line into the key-field record.
///
/// Names are compared ASCII case-insensitively (RFC 9110 §5.1). Spans keep the
/// FIRST line's value: a repeat is what the counts are for, and the value that
/// decides framing is the one that arrived first.
fn record_key_field(name: &[u8], value: &[u8], span: FieldSpan, key: &mut KeyFields) {
  if eq_ignore_ascii(name, "host") {
    key.host.get_or_insert(span);
    key.host_count = key.host_count.saturating_add(1);
  } else if eq_ignore_ascii(name, "content-length") {
    key.content_length.get_or_insert(span);
    key.content_length_count = key.content_length_count.saturating_add(1);
  } else if eq_ignore_ascii(name, "transfer-encoding") {
    key.transfer_encoding.get_or_insert(span);
    key.transfer_encoding_count = key.transfer_encoding_count.saturating_add(1);
  } else if eq_ignore_ascii(name, "connection") {
    fold_connection_options(key, value);
  } else if eq_ignore_ascii(name, "upgrade") {
    key.has_upgrade_field = true;
  } else if eq_ignore_ascii(name, "expect") {
    key.expect.push(value);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const HEAD: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Raw: caf\xC3\xA9\r\n\r\n";

  // RFC 9112 §2.2: a line ends at CRLF and nowhere else, so a CR whose LF has
  // not arrived proves nothing — an incremental reader that condemned it would
  // reject a message split across two reads.
  #[test]
  fn find_head_end_incremental_and_resumable() {
    // No terminator yet → Ok(None) at every prefix length — INCLUDING prefixes
    // ending in a lone CR (split-CRLF safety).
    for n in 0..HEAD.len() - 1 {
      assert_eq!(find_head_end(&HEAD[..n], 0).unwrap(), None, "prefix {n}");
    }
    assert_eq!(find_head_end(HEAD, 0).unwrap(), Some(HEAD.len()));
    // Resumability: scanning from a prior watermark finds the same boundary.
    assert_eq!(
      find_head_end(HEAD, HEAD.len() / 2).unwrap(),
      Some(HEAD.len())
    );
    // A lone trailing CR is inconclusive even where a bare CR would otherwise
    // be a violation on the NEXT byte:
    assert_eq!(find_head_end(b"GET / HTTP/1.1\r", 0).unwrap(), None);

    // EVERY watermark resumes onto the same boundary — including the ones that
    // land inside a CRLF, where an LF read out of context looks bare, and the
    // ones that land mid-line, where the tail of a field line must not pass for
    // the empty line that ends a head.
    for from in 0..=HEAD.len() {
      assert_eq!(
        find_head_end(HEAD, from).unwrap(),
        Some(HEAD.len()),
        "from {from}"
      );
    }
    // The connection's own loop: feed one byte at a time carrying the watermark
    // forward, and the boundary still arrives exactly once.
    let mut watermark = 0;
    for n in 1..HEAD.len() {
      assert_eq!(
        find_head_end(&HEAD[..n], watermark).unwrap(),
        None,
        "feed {n}"
      );
      watermark = n;
    }
    assert_eq!(find_head_end(HEAD, watermark).unwrap(), Some(HEAD.len()));

    // Pipelining and bodies: the scan stops at the FIRST terminator, so what
    // follows it belongs to the caller and is never read.
    assert_eq!(
      find_head_end(b"GET / HTTP/1.1\r\n\r\nGET /2 HTTP/1.1\r\n\r\n", 0).unwrap(),
      Some(18)
    );
  }

  // RFC 9112 §2.2: "a server that is expecting to receive and parse a
  // request-line SHOULD ignore at least one empty line (CRLF) received prior to
  // the request-line"; RFC 9110 §5.4 leaves every such allowance bounded.
  #[test]
  fn leading_empty_lines_bounded() {
    assert_eq!(skip_leading_empty_lines(b"\r\n\r\nGET").unwrap(), 4);
    let five = b"\r\n\r\n\r\n\r\n\r\nGET";
    assert!(skip_leading_empty_lines(five).is_err());
  }

  // RFC 9110 §7.2 (`Host`), §8.6 (`Content-Length`), RFC 9112 §6.1
  // (`Transfer-Encoding`): the scan records the FIRST value's trimmed span and
  // counts every line, which is what makes a duplicate detectable later.
  #[test]
  fn key_fields_recorded_with_counts() {
    const HOSTS: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\nContent-Length: 3\r\n\r\n";
    let v = scan_head(HOSTS).unwrap();
    assert_eq!(v.key_fields().host_count, 2);
    assert_eq!(v.key_fields().content_length_count, 1);
    // The span covers the first line's OWS-trimmed value, not the repeat.
    assert_eq!(
      v.key_fields().host.and_then(|s| s.value_in(HOSTS)),
      Some(b"a".as_slice())
    );
    assert_eq!(
      v.key_fields()
        .content_length
        .and_then(|s| s.value_in(HOSTS)),
      Some(b"3".as_slice())
    );

    const CHUNKED: &[u8] = b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: \tchunked \r\n\r\n";
    let v = scan_head(CHUNKED).unwrap();
    assert_eq!(v.key_fields().transfer_encoding_count, 1);
    assert_eq!(
      v.key_fields()
        .transfer_encoding
        .and_then(|s| s.value_in(CHUNKED)),
      Some(b"chunked".as_slice())
    );
    // RFC 9110 §5.5: an empty field value is legal (`field-value = *field-content`).
    const EMPTY: &[u8] = b"GET / HTTP/1.1\r\nHost:\r\n\r\n";
    let v = scan_head(EMPTY).unwrap();
    assert_eq!(v.key_fields().host_count, 1);
    assert_eq!(
      v.key_fields().host.and_then(|s| s.value_in(EMPTY)),
      Some(b"".as_slice())
    );
  }

  // RFC 9110 §5.2 list rule across REPEATED lines (behaviour also pinned by
  // websocket-proto's "split Connection lines" tests).
  #[test]
  fn token_facts_fold_across_split_field_lines() {
    let v = scan_head(b"GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").unwrap();
    assert!(v.key_fields().connection_keep_alive);
    assert!(v.key_fields().connection_upgrade); // second line still counts
    assert!(v.key_fields().has_upgrade_field);
    let v2 = scan_head(
      b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\nExpect: 100-continue\r\nExpect: whatever\r\n\r\n",
    )
    .unwrap();
    assert!(v2.key_fields().connection_close);
    assert!(v2.key_fields().expect.expects_continue());
    assert!(v2.key_fields().expect.has_other());
  }

  // RFC 9112 §5.1 (ws before colon), §5.2 (obs-fold), §2.2 (bare CR/LF), §2.2 (ws before first field).
  #[test]
  fn rejects_field_syntax_violations() {
    for bad in [
      b"GET / HTTP/1.1\r\nHost : x\r\n\r\n".as_slice(), // SP before colon
      b"GET / HTTP/1.1\r\nHost\t: x\r\n\r\n",           // HTAB before colon
      b"GET / HTTP/1.1\r\nHost: a\r\n b\r\n\r\n",       // obs-fold
      b"GET / HTTP/1.1\r\n Host: x\r\n\r\n",            // ws before first field
      b"GET / HTTP/1.1\nHost: x\r\n\r\n",               // bare LF line ending
      b"GET / HTTP/1.1\r\nHo\rst: x\r\n\r\n",           // bare CR inside
      b"GET / HTTP/1.1\r\nBad{}Name: x\r\n\r\n",        // non-token name
      b"GET / HTTP/1.1\r\n: x\r\n\r\n",                 // empty name
      b"GET / HTTP/1.1\r\nHost: a\x00b\r\n\r\n",        // CTL in value
    ] {
      assert!(scan_head(bad).is_err(), "{bad:?}");
    }
  }

  // RFC 9112 §5 (`field-line = field-name ":" OWS field-value OWS`) with
  // RFC 9110 §5.5: the offset names the byte that broke the grammar, rebased
  // from the value-relative offset the validator reports onto the head block.
  #[test]
  fn error_offsets_are_absolute_within_the_head() {
    let offset_of = |head: &[u8]| match scan_head(head) {
      Err(H1Error::Malformed(d)) => d.at(),
      other => panic!("expected Malformed, got {other:?}"),
    };
    // The second line begins at 16, its trimmed value 7 bytes later (past
    // `Host:` and two OWS bytes), and the NUL 6 bytes into that value: the
    // validator's value-relative 6 has to come back as 29.
    assert_eq!(
      offset_of(b"GET / HTTP/1.1\r\nHost:  abcdef\x00\r\n\r\n"),
      29
    );
    // The SP between the field name and its colon (§5.1).
    assert_eq!(offset_of(b"GET / HTTP/1.1\r\nHost : x\r\n\r\n"), 20);
    // The bare CR that is not a line terminator (§2.2).
    assert_eq!(offset_of(b"GET / HTTP/1.1\r\nHo\rst: x\r\n\r\n"), 18);
    // The obs-fold continuation line, reported where the line begins (§5.2).
    assert_eq!(offset_of(b"GET / HTTP/1.1\r\nHost: a\r\n b\r\n\r\n"), 25);
  }
}

#[cfg(all(test, any(feature = "std", feature = "alloc", feature = "no-atomic")))]
mod heap_tests {
  use super::*;

  // RFC 9112 §3 (a server MUST answer an over-long request-target with 414) vs
  // RFC 9110 §5.4 with RFC 6585 §5 (an over-large field section is a 431): the
  // two are told apart by whether a single CRLF ever arrived.
  #[test]
  fn head_cap_enforced_with_414_vs_431_distinction() {
    // Fields overflow after a valid request line → HeadTooLarge (431).
    let mut big = std::vec::Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
    while big.len() <= MAX_HEAD_BYTES {
      big.extend_from_slice(b"A: b\r\n");
    }
    assert!(matches!(
      find_head_end(&big, 0),
      Err(H1Error::HeadTooLarge(_))
    ));
    // No CRLF at all within the cap → the request-line itself overflowed → 414.
    let mut line = std::vec::Vec::from(&b"GET /"[..]);
    while line.len() <= MAX_HEAD_BYTES {
      line.push(b'a');
    }
    assert!(matches!(
      find_head_end(&line, 0),
      Err(H1Error::RequestLineTooLong(_))
    ));
    // A lone CR sitting AT the cap is still inconclusive (RFC 9112 §2.2), so
    // the answer is the cap error and not a bare-CR one: the cap is what the
    // peer broke, and the CR may yet have been half of a CRLF.
    let mut cr = std::vec::Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
    cr.resize(MAX_HEAD_BYTES - 1, b'x');
    cr.push(b'\r');
    assert_eq!(cr.len(), MAX_HEAD_BYTES);
    assert!(matches!(
      find_head_end(&cr, 0),
      Err(H1Error::HeadTooLarge(_))
    ));
  }

  // RFC 9112 §3's RECOMMENDED 8000-octet request-line floor. The arithmetic half
  // is the `const _: () = assert!(…)` beside `MAX_HEAD_BYTES`, which holds on
  // every target; this is the behavioural half — a request-line AT the floor is
  // actually scanned, rather than answered with the §3 414 that an over-long one
  // gets.
  #[test]
  fn the_head_cap_clears_the_recommended_request_line_floor() {
    let mut head = std::vec::Vec::from(&b"GET /"[..]);
    // `GET ` + target + ` HTTP/1.1` = exactly the floor, on one line.
    head.resize(RECOMMENDED_REQUEST_LINE_FLOOR - b" HTTP/1.1".len(), b'a');
    head.extend_from_slice(b" HTTP/1.1\r\nHost: h\r\n\r\n");
    let view = scan_head(&head).expect("a request-line at the recommended floor is scannable");
    assert_eq!(view.header("host"), Some(b"h".as_slice()));
  }

  // RFC 9110 §5.4: the cap is on the block the scanner accepts, so a block that
  // never passed `find_head_end` is refused rather than having its offsets
  // narrowed onto the wrong bytes.
  #[test]
  fn scan_refuses_a_block_over_the_byte_cap() {
    let mut over = std::vec::Vec::from(&b"GET / HTTP/1.1\r\nX: "[..]);
    over.resize(MAX_HEAD_BYTES + 1, b'x');
    over.extend_from_slice(b"\r\n\r\n");
    assert!(matches!(scan_head(&over), Err(H1Error::HeadTooLarge(_))));
  }

  // RFC 9110 §5.4: a recipient limits how many field lines it will process, and
  // RFC 6585 §5 answers the excess with 431.
  #[test]
  fn too_many_headers_rejected() {
    let mut h = std::vec::Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
    for i in 0..65 {
      h.extend_from_slice(std::format!("H{i}: v\r\n").as_bytes());
    }
    h.extend_from_slice(b"\r\n");
    assert!(matches!(scan_head(&h), Err(H1Error::TooManyHeaders(64))));

    // Exactly the cap passes: the count is a limit, not a budget one short.
    let mut at_cap = std::vec::Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
    for i in 0..MAX_HEADERS {
      at_cap.extend_from_slice(std::format!("H{i}: v\r\n").as_bytes());
    }
    at_cap.extend_from_slice(b"\r\n");
    assert_eq!(scan_head(&at_cap).unwrap().field_count(), MAX_HEADERS);
  }
}
