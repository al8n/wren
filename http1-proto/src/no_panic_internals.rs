//! Leaf-path forwarders for the `no-panic` link-time test (`tests/no_panic.rs`).
//!
//! Gated behind `test-no-panic`, doc-hidden, and exempt from semver: these
//! `pub` forwarders expose the crate's leaf entry points so the test can wrap
//! them in `#[no_panic]` shims — `find_head_end`, `parse_status_line`,
//! `parse_chunk_size`, `head_digest` and the body budget's four leaves
//! (`overruns`, `charge`, `widen`, `headroom`) — or run them as plain smoke
//! tests, which is what `parse_request_line`, `encode_request_head` and
//! `scan_head` get. The test file records why each of those three cannot be
//! link-checked; the reasons are properties of `no-panic` and of the call
//! trees, not of the code's panic-freedom.
//!
//! No `parse_qvalue` forwarder: the §12.4.2 `qvalue` reader lives in
//! `http-semantics` and is link-checked by that crate's own
//! `tests/no_panic.rs`, through a forwarder of the same shape there. Its
//! absence here is what lets `http_semantics::media::parse_qvalue` be
//! `pub(crate)` rather than `pub`.
//!
//! A `pub use` of a `pub(crate)` item is illegal (E0364/E0365), so these are
//! thin forwarders rather than re-exports. Being `#[inline]` keeps the
//! forwarder itself out of the way; what actually carries the leaf bodies
//! across the crate boundary is the fat LTO the test's documented invocation
//! turns on, since a shim is only provable over code the optimizer can inline
//! into it.
//!
//! Names here are plain code spans rather than intra-doc links on purpose. This
//! doc block is merged with the outer doc on the `lib.rs` declaration and
//! resolved in the crate root's scope, and every target below is `pub(crate)`,
//! which `rustdoc::private_intra_doc_links` refuses under `-D warnings`.

use crate::{Error, H1Error, HeadView, RequestLine, StatusLine, Target};

/// Forwards to `crate::head::find_head_end` — the incremental head-terminator
/// scan.
#[inline]
pub fn find_head_end(input: &[u8], from: usize) -> Result<Option<usize>, H1Error> {
  crate::head::find_head_end(input, from)
}

/// Forwards to `crate::head::parse_request_line` — the RFC 9112 §3
/// request-line codec.
#[inline]
pub fn parse_request_line(line: &[u8]) -> Result<RequestLine<'_>, H1Error> {
  crate::head::parse_request_line(line)
}

/// Forwards to `crate::head::parse_status_line` — the RFC 9112 §4 status-line
/// codec.
#[inline]
pub fn parse_status_line(line: &[u8]) -> Result<StatusLine<'_>, H1Error> {
  crate::head::parse_status_line(line)
}

/// Forwards to `crate::body::chunked::parse_chunk_size` — the RFC 9112 §7.1
/// `chunk-size = 1*HEXDIG` reader, the leaf of the chunk-size line path.
///
/// The line is already delimited here: delimiting is `delimit_line`'s job and
/// the stage that combines the two (`read_size_line`) is a decoder method with
/// state to advance, so the leaf is what a shim can be wrapped around.
#[inline]
pub fn parse_chunk_size(line: &[u8]) -> Result<(u64, usize), H1Error> {
  crate::body::chunked::parse_chunk_size(line)
}

/// Forwards to `crate::head::encode::encode_request_head`, monomorphized over
/// the `[(&str, &[u8])]` field supplier.
///
/// The encoder is generic over `Headers`, and a forwarder cannot be: the
/// instantiation the test exercises is pinned here — the slice impl, which is
/// the one every caller in the crate's own tests uses.
///
/// The expected field-section digest is taken from the supplier itself, as it is
/// in the crate's own encoder tests; in production it travels from the send
/// side's framing reduction, which is what makes it a cross-walk check.
#[inline]
pub fn encode_request_head(
  method: &str,
  target: &Target<'_>,
  headers: &[(&str, &[u8])],
  out: &mut [u8],
) -> Result<usize, Error> {
  let expect = crate::head::encode::field_digest(headers)?;
  crate::head::encode::encode_request_head(method, target, headers, expect, out)
}

/// Forwards to `crate::head::scan_head` — the bounded one-pass field-section
/// scan.
///
/// Smoke only, never link-checked: see the module doc.
#[inline]
pub fn scan_head(head: &[u8]) -> Result<HeadView<'_>, H1Error> {
  crate::head::scan_head(head)
}

/// Forwards to `crate::body::overruns` — the one spelling of the early-exit
/// test a count the peer DECLARED is measured against.
#[inline]
pub fn overruns(declared: u64, headroom: u64) -> bool {
  crate::body::overruns(declared, headroom)
}

/// Forwards to `crate::body::charge` — the checked accumulation that IS the
/// body bound: every payload octet the crate hands over passes through it, so a
/// panic edge here would be one on the path of every message with content.
#[inline]
pub fn charge(received: u64, n: u64, limit: u64) -> Option<u64> {
  crate::body::charge(received, n, limit)
}

/// Forwards to `crate::body::widen` — the saturating conversion that puts a
/// slice length into the budget's unit.
#[inline]
pub fn widen(n: usize) -> u64 {
  crate::body::widen(n)
}

/// Forwards to `crate::body::headroom` — what is left of a limit after what has
/// already been received.
#[inline]
pub fn headroom(received: u64, limit: u64) -> u64 {
  crate::body::headroom(received, limit)
}

/// Forwards to `crate::connection::head_digest` — the FNV-1a fold a connection
/// keeps of the head that armed it, and the crate's one unbounded-length
/// arithmetic loop over borrowed bytes.
///
/// A true leaf: no call tree at all, so unlike `scan_head` it inlines whole
/// into a shim and is LINK-CHECKED rather than smoke-tested. What the check is
/// worth is the loop itself — the XOR and the wrapping multiply over every byte
/// of a block that may be `MAX_HEAD_BYTES` long — since a bounds check or an
/// overflow check surviving there would be a panic edge on a path every upgrade
/// request takes.
#[inline]
pub fn head_digest(block: &[u8]) -> u64 {
  crate::connection::head_digest(block)
}
