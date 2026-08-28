//! The status vocabulary every crate in this workspace shares.
//!
//! Membership is about the **vocabulary's home**, not about which crate produces
//! each code: a status belongs here when it names a code some crate in this
//! workspace produces from a rule RFC 9110, or a specification RFC 9110 builds
//! on, states. It is not a catalogue of RFC 9110 §15. The one exception is
//! [`Status::FieldsTooLarge`], whose rule is RFC 6585 §5 — RFC 9110 §19.2 lists
//! RFC 6585 as an informative reference, not a specification it builds on —
//! and it stays because `http1-proto` produces it and RFC 9110 §15 has no
//! equivalent code.
//!
//! This type was `http1-proto`'s `SuggestedStatus`, named for what a failed parse
//! suggests. That name could not hold [`Status::Ok`] or [`Status::PartialContent`]
//! without reading as a category error, and RFC 9110 §13.2.2's algorithm produces
//! both — which is why the move renamed it. `http1-proto` re-exports it under the
//! old name, so no call site changed.

/// A status code this workspace produces from a rule RFC 9110 states, with one
/// exception the module doc names: [`Status::FieldsTooLarge`].
///
/// `#[non_exhaustive]`: new rules bring new codes, and a caller matching on this
/// must keep a fallback arm.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Status {
  /// 200 (OK). RFC 9110 §13.2.2 step 5 reaches it by ignoring a `Range`, and
  /// §14.2 reaches it by ignoring one for a unit the recipient does not
  /// understand.
  Ok,
  /// 206 (Partial Content). RFC 9110 §14.2's SHOULD, when every precondition is
  /// true and the ranges-specifier is satisfiable in a supported unit.
  PartialContent,
  /// 304 (Not Modified). RFC 9110 §13.2.2 steps 3 and 4.
  NotModified,
  // `Status`'s variants are declared in ascending code order, from `Ok` (200)
  // through `VersionNotSupported` (505).
  /// `400 Bad Request` (RFC 9110 §15.5.1).
  BadRequest,
  /// 412 (Precondition Failed). RFC 9110 §13.2.2 steps 1, 2 and 3 — a MAY at the
  /// first two and a MUST at the third.
  PreconditionFailed,
  /// `413 Content Too Large` (RFC 9110 §15.5.14): the content is larger than
  /// this end is willing to process.
  ContentTooLarge,
  /// `414 URI Too Long` (RFC 9110 §15.5.15). RFC 9112 §3 makes this the MUST
  /// answer for a request-target longer than the server will parse.
  UriTooLong,
  /// 416 (Range Not Satisfiable). RFC 9110 §14.2's SHOULD, when the
  /// ranges-specifier is valid and either unsatisfiable or in a unit not
  /// supported for the target resource.
  RangeNotSatisfiable,
  /// `431 Request Header Fields Too Large` (RFC 6585 §5 — not an RFC 9110
  /// code).
  FieldsTooLarge,
  /// `501 Not Implemented` (RFC 9110 §15.6.2).
  NotImplemented,
  /// `505 HTTP Version Not Supported` (RFC 9110 §15.6.6).
  VersionNotSupported,
}

impl Status {
  /// The three-digit code this status names.
  #[inline(always)]
  pub const fn code(self) -> u16 {
    match self {
      Self::Ok => 200,
      Self::PartialContent => 206,
      Self::NotModified => 304,
      Self::BadRequest => 400,
      Self::PreconditionFailed => 412,
      Self::ContentTooLarge => 413,
      Self::UriTooLong => 414,
      Self::RangeNotSatisfiable => 416,
      Self::FieldsTooLarge => 431,
      Self::NotImplemented => 501,
      Self::VersionNotSupported => 505,
    }
  }

  /// The RFC 9110 §15 reason phrase for this status (RFC 6585 §5 for 431).
  ///
  /// Exists to retire a defect class rather than for convenience. A driver that
  /// maps a suggested status through `match code { Some(414) => …, _ => … }`
  /// silently degrades every variant added afterwards; with this the mapping is
  /// `(s.code(), s.reason())` and no variant can degrade. The phrase is
  /// advisory either way — RFC 9112 §4 makes `reason-phrase` optional and
  /// unexamined by the client.
  #[inline(always)]
  pub const fn reason(self) -> &'static str {
    match self {
      Self::Ok => "OK",
      Self::PartialContent => "Partial Content",
      Self::NotModified => "Not Modified",
      Self::BadRequest => "Bad Request",
      Self::PreconditionFailed => "Precondition Failed",
      Self::ContentTooLarge => "Content Too Large",
      Self::UriTooLong => "URI Too Long",
      Self::RangeNotSatisfiable => "Range Not Satisfiable",
      Self::FieldsTooLarge => "Request Header Fields Too Large",
      Self::NotImplemented => "Not Implemented",
      Self::VersionNotSupported => "HTTP Version Not Supported",
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // RFC 9110 §15: the code each variant names. This test is the only place the
  // numbers appear, so a variant added without its code is a compile error here
  // rather than a silent gap.
  #[test]
  fn every_variant_names_its_code() {
    for (status, code) in [
      (Status::Ok, 200u16),
      (Status::PartialContent, 206),
      (Status::NotModified, 304),
      (Status::BadRequest, 400),
      (Status::PreconditionFailed, 412),
      (Status::ContentTooLarge, 413),
      (Status::UriTooLong, 414),
      (Status::RangeNotSatisfiable, 416),
      (Status::FieldsTooLarge, 431),
      (Status::NotImplemented, 501),
      (Status::VersionNotSupported, 505),
    ] {
      assert_eq!(status.code(), code, "{status:?}");
    }
  }

  #[test]
  fn the_two_successes_are_not_errors() {
    // `Status` replaced `SuggestedStatus`, whose name could not hold a success.
    // Nothing in the type distinguishes them, and that is the point — the
    // rename is what makes 200 and 206 ordinary members.
    assert_eq!(Status::Ok.code(), 200);
    assert_eq!(Status::PartialContent.code(), 206);
  }
}
