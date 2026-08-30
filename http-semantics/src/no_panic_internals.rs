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
/// `tail` is the `ValueTail` below, and the shim drives all three of its
/// states. A `bool` carried the two this had before `Trails` separated a value
/// that closed across RFC 9110 §5.2's join from one that closed and then ran on
/// past its close.
#[inline]
pub fn auth_param(
  element: &[u8],
  tail: ValueTail,
) -> Result<crate::auth::AuthParam<'_>, crate::auth::AuthError> {
  crate::auth::auth_param(element, tail.inner())
}

/// What RFC 9110 §5.2's field-line join did with a quoted value an element
/// leaves open, spelled so a test crate can name it.
///
/// `crate::auth::ValueTail` is the enum the walks pass and it is `pub(crate)`
/// like the function it feeds, so a test crate cannot name it. This mirrors its
/// three states, and mirrors them as an ENUM: the `u8` this replaced put values
/// at the boundary that named no state at all and needed a fallback arm to
/// swallow them, which is three states and a hole where the type should be.
///
/// `inner` is the whole of the crossing, and `From` is its inverse. That
/// conversion matches exhaustively over the CRATE-PRIVATE enum, so a state
/// added there stops this build rather than reaching the shim as one of the
/// states already here;
/// `every_value_tail_crosses_the_forwarder_as_itself` is where the two are
/// checked to be the same three.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ValueTail {
  /// Nothing was open where the element's line ended, or what was open never
  /// closed on any later one.
  Ends,
  /// It closed on a later field line and the element ended there.
  Continues,
  /// It closed on a later field line and the element did NOT end there.
  Trails,
}

impl ValueTail {
  /// The crate-private state this one mirrors.
  const fn inner(self) -> crate::auth::ValueTail {
    match self {
      Self::Ends => crate::auth::ValueTail::Ends,
      Self::Continues => crate::auth::ValueTail::Continues,
      Self::Trails => crate::auth::ValueTail::Trails,
    }
  }
}

impl From<crate::auth::ValueTail> for ValueTail {
  fn from(tail: crate::auth::ValueTail) -> Self {
    match tail {
      crate::auth::ValueTail::Ends => Self::Ends,
      crate::auth::ValueTail::Continues => Self::Continues,
      crate::auth::ValueTail::Trails => Self::Trails,
    }
  }
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
