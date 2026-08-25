//! Leaf-path forwarders for the `no-panic` link-time test (`tests/no_panic.rs`).
//!
//! Gated behind `test-no-panic`, doc-hidden, and exempt from semver: this `pub`
//! forwarder exposes the one leaf entry point the test needs that the crate
//! does not otherwise publish — the RFC 9110 §12.4.2 `qvalue` reader. The other
//! four link-checked leaves — `grammar::parameterised_list`,
//! `media::weight_for`, `date::parse_http_date` and `date::format_imf_fixdate`
//! — are already `pub` and are called directly.
//!
//! A `pub use` of a `pub(crate)` item is illegal (E0364/E0365), so this is a
//! thin forwarder rather than a re-export. Being `#[inline]` keeps the
//! forwarder itself out of the way; what carries the leaf body across the crate
//! boundary into the test binary is the fat LTO the test's documented
//! invocation turns on, since a shim is only provable over code the optimizer
//! can inline into it.
//!
//! The forwarder is what lets `media::parse_qvalue` stay `pub(crate)`. While the
//! shim lived in `http1-proto`'s test the function had to be `pub` — a crate
//! boundary admits no narrower visibility — so a reader of this crate's public
//! API met a `qvalue` reader that exists to serve another crate's test.
//!
//! Names here are plain code spans rather than intra-doc links on purpose. This
//! doc block is merged with the outer doc on the `lib.rs` declaration and
//! resolved in the crate root's scope, and `media::parse_qvalue` is
//! `pub(crate)`, which `rustdoc::private_intra_doc_links` refuses under
//! `-D warnings`.

/// Forwards to `crate::media::parse_qvalue` — the RFC 9110 §12.4.2 `qvalue`
/// reader, whose digit accumulation is the media module's only CHECKED one.
///
/// Not the whole of its arithmetic: `matched_instances` and `weight_for` both
/// carry saturating arithmetic of their own, which the `weight_for` shim
/// covers.
#[inline]
pub fn parse_qvalue(v: &[u8]) -> Option<crate::media::Weight> {
  crate::media::parse_qvalue(v)
}
