//! Leaf-path forwarders for the `no-panic` link-time test (`tests/no_panic.rs`).
//!
//! Gated behind `test-no-panic`, doc-hidden, and exempt from semver: these
//! `pub` forwarders expose the leaf entry points the test needs that the crate
//! does not otherwise publish — the RFC 9110 §12.4.2 `qvalue` reader, and §11.2's
//! two authentication leaves, `auth::auth_param` and `auth::token68_end`. Every
//! other link-checked leaf is already `pub` and is called directly.
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
//! API met a `qvalue` reader that exists to serve another crate's test. The two
//! authentication leaves are `pub(crate)` for the same reason and no other:
//! `auth::auth_param` and `auth::token68_end` have no caller but the walks
//! above them, and neither is an entry point this crate offers.
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

/// Forwards to `crate::auth::auth_param` — RFC 9110 §11.2's
/// `auth-param = token BWS "=" BWS ( token / quoted-string )`, read over one
/// list element with the list's own `OWS` already off both ends.
///
/// `tail` is `crate::auth::ValueTail` spelled as a `u8` at this boundary. That
/// enum answers what RFC 9110 §5.2's field-line join did with a quoted value
/// the element leaves open, it is `pub(crate)` like the function itself, and a
/// test crate cannot name it — so its three states cross as `1` for
/// `Continues`, `2` for `Trails` and anything else for `Ends`, and the shim
/// drives all three. A `bool` carried the two states this had before `Trails`
/// separated a value that closed across the join from one that closed and then
/// ran on past its close.
#[inline]
pub fn auth_param(
  element: &[u8],
  tail: u8,
) -> Result<crate::auth::AuthParam<'_>, crate::auth::AuthError> {
  crate::auth::auth_param(
    element,
    match tail {
      1 => crate::auth::ValueTail::Continues,
      2 => crate::auth::ValueTail::Trails,
      _ => crate::auth::ValueTail::Ends,
    },
  )
}

/// Forwards to `crate::auth::token68_end` — the RUN behind RFC 9110 §11.2's
/// `token68`: two loops, the alphabet's and the `=` pad's, with no way back to
/// the first.
///
/// Not the READING: whether the run its answer names is taken as a `token68`
/// at all is `crate::auth::token68`'s question, and that function is reached
/// through `credentials` and `challenges`, whose own shims cover it.
// gate-exempt: crate::auth::token68 — named for contrast, and the contrast is
// the point: this forwards to the RUN. The reading built on it is a different
// function with no forwarder, reached only through the two entry points whose
// shims inline it.
#[inline]
pub fn token68_end(value: &[u8], at: usize) -> Option<usize> {
  crate::auth::token68_end(value, at)
}
