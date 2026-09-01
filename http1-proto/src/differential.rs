//! Forwarders that let the workspace's `transfer-coding` differential
//! (`coding-corpus`) feed this crate's RFC 9112 §7 `Transfer-Encoding` reader.
//!
//! Gated behind `differential`, doc-hidden, and exempt from semver. The
//! accumulator that decides how a message is framed is `pub(crate)`, so nothing
//! outside this crate can hand it the same corpus
//! `http_semantics::grammar::parameterised_list` is handed. The only other way
//! in is the outbound send path, where `Content-Length`, `Host`, the method and
//! §5.6.1.1's empty-element rule all decide the same `Err` — so a disagreement
//! about RFC 9110 §10.1.4's `transfer-coding` would arrive as one boolean five
//! other rules also set, and a differential could not say which reader moved.
//!
//! A `pub use` of a `pub(crate)` item is illegal (E0364/E0365), so these are
//! wrappers rather than re-exports. They add NO rule: every method forwards one
//! call, and `Verdict` below is an exhaustive re-spelling of the crate's own
//! classification, so a variant added to that enum stops this file compiling
//! rather than being silently folded onto a row of the differential's record.
//!
//! Names below are plain code spans rather than intra-doc links for the reason
//! `__no_panic_internals` gives: this block is merged with the outer doc on the
//! `lib.rs` declaration and resolved in the crate root's scope, where the
//! crate-private targets are what `rustdoc::private_intra_doc_links` refuses
//! under `-D warnings`.

use crate::validate::{CodingList, Codings};

/// What this crate's RFC 9112 §6.3 item 4 classification says about one
/// `Transfer-Encoding` list.
///
/// An exhaustive re-spelling of the crate-private `Codings`. The `match` in
/// [`TransferCodings::verdict`] is what makes it exhaustive, so a variant added
/// there is a compile error here rather than a row the differential silently
/// merges into another.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Verdict {
  /// Delimited and decodable: one `chunked`, final, unparameterized, alone.
  Chunked,
  /// Delimited by a final `chunked`, with a coding beneath it this core cannot
  /// decode. The reason names the coding rule.
  ChunkedUndecodable(&'static str),
  /// Neither delimited nor decodable. The reason names the coding rule.
  Undecodable(&'static str),
  /// The list does not frame the body. The reason names the rule that refused
  /// it, which is what the differential records.
  NotFramed(&'static str),
}

/// One `Transfer-Encoding` list, accumulated across the field lines RFC 9110
/// §5.2 folds into it.
///
/// This is the reader that decides how `http1-proto` frames a message, wrapped
/// so a test outside the crate can push field lines into it and read the three
/// answers back.
#[derive(Debug)]
pub struct TransferCodings(CodingList);

impl Default for TransferCodings {
  fn default() -> Self {
    Self::new()
  }
}

impl TransferCodings {
  /// An empty list — no `Transfer-Encoding` field at all.
  #[inline]
  #[must_use]
  pub const fn new() -> Self {
    Self(CodingList::new())
  }

  /// Folds one `Transfer-Encoding` field line's value into the list.
  #[inline]
  pub fn push(&mut self, value: &[u8]) {
    self.0.push(value);
  }

  /// Whether the whole combined value parsed as RFC 9112 §7's
  /// `#transfer-coding`, asked apart from what the codings mean.
  #[inline]
  #[must_use]
  pub const fn parsed(&self) -> bool {
    self.0.parsed()
  }

  /// Whether the field is present and some element of the combined value is
  /// empty — RFC 9110 §5.6.1.1's prohibition on a sender.
  #[inline]
  #[must_use]
  pub const fn empty_element(&self) -> bool {
    self.0.empty_element()
  }

  /// The classification of the folded list.
  #[inline]
  #[must_use]
  pub fn verdict(&self) -> Verdict {
    match self.0.verdict() {
      Codings::Chunked => Verdict::Chunked,
      Codings::ChunkedUndecodable(why) => Verdict::ChunkedUndecodable(why),
      Codings::Undecodable(why) => Verdict::Undecodable(why),
      Codings::NotFramed(why) => Verdict::NotFramed(why),
    }
  }
}
