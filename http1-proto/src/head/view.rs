//! The lazy view of one scanned head: field access by re-walking the validated
//! block, never by materializing a field table.
//!
//! A head is read far more often than it is scanned, but almost none of it is
//! read twice: a WebSocket handshake looks at a handful of fields and forwards
//! the rest untouched. So the view stores the block, where its start line ends,
//! how many fields it holds, and the key-field record the scan folded — and
//! finds a field by walking the block again. Walking costs a pass over at most
//! `MAX_HEAD_BYTES` of borrowed memory; storing a table would cost every
//! connection a fixed array of name/value slices whether or not it ever reads
//! one, which is the 2 KB-per-connection shape this core exists to avoid.

use super::{
  LineEnd, delimit_line,
  scan::{FieldSpan, KeyFields},
  split_field,
};

// The anti-table budget, checked at module scope so that every `cargo check` on
// every tier enforces it — inside a `#[test]` it would only fire under `cargo
// test` on the tiers that run one. ('_ is not legal in a const item, so
// 'static stands in; the size does not depend on the lifetime.)
const _: () = assert!(core::mem::size_of::<HeadView<'static>>() <= 128);

/// A zero-copy view of one scanned head, borrowed from the block it was scanned
/// out of.
///
/// Field access is lazy: [`headers`](Self::headers) and
/// [`header`](Self::header) re-walk the block, which the scan already proved
/// well-formed, so a field the caller never asks for costs nothing. Names
/// surface as `&str` because a validated field name is a `token` (RFC 9110
/// §5.6.2) and therefore ASCII; values stay `&[u8]`, because `obs-text` (§5.5)
/// is legal field content and need not be UTF-8.
#[derive(Debug, Copy, Clone)]
pub struct HeadView<'a> {
  /// The complete head block: start line, field lines, and the empty line that
  /// ends them, both CRLFs of the terminator included.
  head: &'a [u8],
  /// Offset just past the start line's CRLF — where the field lines begin.
  start_line_end: u32,
  /// Field lines the scan counted, capped at
  /// [`MAX_HEADERS`](crate::head::MAX_HEADERS).
  field_count: u16,
  /// What the scan recorded about the fields the core reads back.
  key: KeyFields,
}

impl<'a> HeadView<'a> {
  /// Wraps a block the scanner has just validated.
  pub(super) const fn new(
    head: &'a [u8],
    start_line_end: u32,
    field_count: u16,
    key: KeyFields,
  ) -> Self {
    Self {
      head,
      start_line_end,
      field_count,
      key,
    }
  }

  /// The field lines in arrival order, as `(name, value)` with the value's OWS
  /// trimmed off (RFC 9110 §5.5).
  ///
  /// Repeated fields are yielded once per line, exactly as they arrived: RFC
  /// 9110 §5.2 gives combining them a meaning only for list-typed fields, and
  /// that is the consumer's rule to apply, not the view's.
  pub fn headers(&self) -> FieldsIter<'a> {
    FieldsIter::new(self.head, self.field_lines_at())
  }

  /// The first value for `name`, compared ASCII case-insensitively (RFC 9110
  /// §5.1). Walks the block, so it is O(head length) per lookup.
  pub fn header(&self, name: &str) -> Option<&'a [u8]> {
    self.header_all(name).next()
  }

  /// Every value for `name` in arrival order, compared ASCII
  /// case-insensitively (RFC 9110 §5.1).
  ///
  /// `Clone`, because a field's cardinality and its content are two questions
  /// over one walk: a consumer that must ask both — "is this field present at
  /// all" and "what are its elements" — re-walks rather than buffering, which
  /// is what a no-alloc reader can afford.
  pub fn header_all<'n>(
    &self,
    name: &'n str,
  ) -> impl Iterator<Item = &'a [u8]> + Clone + use<'a, 'n> {
    self
      .headers()
      .filter_map(move |(field, value)| field.eq_ignore_ascii_case(name).then_some(value))
  }

  /// How many field lines the head carries. Lines, not distinct names: a
  /// repeated field counts once per line.
  pub fn field_count(&self) -> usize {
    usize::from(self.field_count)
  }

  /// What the scan recorded about the fields whose values the core reads back.
  pub(crate) const fn key_fields(&self) -> &KeyFields {
    &self.key
  }

  /// The value a [`key_fields`](Self::key_fields) span covers.
  ///
  /// A span is only meaningful against the block it was measured on, and this
  /// is the pairing that guarantees it: the span comes from this view's own
  /// scan, and the block is this view's own. `None` is therefore unreachable
  /// for a span this view handed out, and callers answer it as a violation
  /// rather than assuming a value.
  pub(crate) fn key_value(&self, span: FieldSpan) -> Option<&'a [u8]> {
    span.value_in(self.head)
  }

  /// The start line, its CRLF included — exactly what the RFC 9112 §3 and §4
  /// codecs parse.
  ///
  /// The scanner delimits this line without parsing it: request against
  /// response is the caller's context, so the caller runs the matching codec.
  pub(crate) fn start_line_bytes(&self) -> &'a [u8] {
    usize::try_from(self.start_line_end)
      .ok()
      .and_then(|end| self.head.get(..end))
      .unwrap_or_default()
  }

  /// Offset the field lines begin at. An offset the platform's `usize` cannot
  /// hold — impossible below the 16 KiB head cap — reads as an empty field
  /// section rather than as some other line.
  fn field_lines_at(&self) -> usize {
    usize::try_from(self.start_line_end).unwrap_or(self.head.len())
  }
}

/// Iterator over a head's field lines, yielding `(name, value)` in arrival
/// order.
///
/// Produced by [`HeadView::headers`]. It re-walks the block instead of reading
/// a table, and the block was validated by the scan, so a line it cannot split
/// ends the iteration rather than being reported: there is no such line in a
/// head the scanner accepted.
#[derive(Debug, Clone)]
pub struct FieldsIter<'a> {
  /// The head block being walked.
  head: &'a [u8],
  /// Offset of the next field line within that block.
  at: usize,
}

impl<'a> FieldsIter<'a> {
  /// Starts a walk at the head's first field line.
  fn new(head: &'a [u8], at: usize) -> Self {
    Self { head, at }
  }
}

impl<'a> Iterator for FieldsIter<'a> {
  type Item = (&'a str, &'a [u8]);

  fn next(&mut self) -> Option<Self::Item> {
    let rest = self.head.get(self.at..)?;
    let LineEnd::Crlf { body, end } = delimit_line(rest) else {
      return None;
    };
    // RFC 9112 §2.1: the empty line closes the field section.
    if body.is_empty() {
      return None;
    }
    let field = split_field(body)?;
    // A validated field name is a token, so it is ASCII and this cannot fail.
    let name = core::str::from_utf8(field.name).ok()?;
    self.at = self.at.saturating_add(end);
    Some((name, field.value))
  }
}

#[cfg(test)]
mod tests {
  use crate::head::{
    request_line::parse_request_line, scan::scan_head, status_line::parse_status_line,
  };

  const HEAD: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Raw: caf\xC3\xA9\r\n\r\n";

  // RFC 9112 §2.1 (`HTTP-message = start-line CRLF *( field-line CRLF ) CRLF
  // [ message-body ]`): the scanner delimits the start line but does not parse
  // it — §3 request-line against §4 status-line is the caller's context — so
  // the view hands the line, its CRLF included, to the caller's codec.
  #[test]
  fn start_line_bytes_feed_the_start_line_codecs() {
    let v = scan_head(HEAD).unwrap();
    assert_eq!(v.start_line_bytes(), b"GET /chat HTTP/1.1\r\n".as_slice());
    assert_eq!(
      parse_request_line(v.start_line_bytes()).unwrap().method,
      "GET"
    );

    let r = scan_head(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n").unwrap();
    assert_eq!(
      r.start_line_bytes(),
      b"HTTP/1.1 101 Switching Protocols\r\n".as_slice()
    );
    assert_eq!(parse_status_line(r.start_line_bytes()).unwrap().code, 101);
    assert_eq!(r.field_count(), 1);
  }

  // RFC 9110 §5.1 (field names are ASCII case-insensitive) and §5.5 (a field
  // value is bytes: `obs-text` is content, not an encoding error).
  #[test]
  fn header_lookup_is_case_insensitive_and_ordered() {
    let v = scan_head(HEAD).unwrap();
    assert_eq!(v.header("HOST"), Some(b"example.com".as_slice()));
    assert_eq!(v.header("x-raw"), Some(b"caf\xC3\xA9".as_slice()));
    assert_eq!(v.header("missing"), None);

    // RFC 9110 §5.2: repeated field lines are ordered, and every one of them is
    // part of the field's value.
    let v = scan_head(b"GET / HTTP/1.1\r\nA: 1\r\nB: x\r\na: 2\r\n\r\n").unwrap();
    let mut all = v.header_all("A");
    assert_eq!(all.next(), Some(b"1".as_slice()));
    assert_eq!(all.next(), Some(b"2".as_slice()));
    assert_eq!(all.next(), None);
    assert_eq!(v.header("a"), Some(b"1".as_slice()));
  }
}

#[cfg(all(test, any(feature = "std", feature = "alloc", feature = "no-atomic")))]
mod heap_tests {
  use crate::head::scan::scan_head;

  const HEAD: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Raw: caf\xC3\xA9\r\n\r\n";

  // RFC 9112 §2.1 with §5: the field lines are read back in arrival order out
  // of the block itself — the view stores no table to read them from.
  #[test]
  fn lazy_view_iterates_in_order_without_table() {
    let v = scan_head(HEAD).unwrap();
    assert_eq!(v.field_count(), 4);
    let names: std::vec::Vec<&str> = v.headers().map(|(n, _)| n).collect();
    assert_eq!(names, ["Host", "Upgrade", "Connection", "X-Raw"]);
    assert_eq!(v.header("HOST"), Some(b"example.com".as_slice())); // case-insensitive
    assert_eq!(v.header("x-raw"), Some(b"caf\xC3\xA9".as_slice())); // obs-text value survives
    assert_eq!(v.header("missing"), None);
  }
}
