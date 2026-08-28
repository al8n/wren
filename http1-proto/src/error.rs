//! Error taxonomy: byte-offset grammar detail, the advisory response status a
//! server driver should answer a violation with, and the protocol / caller-side
//! error split.

use derive_more::Display;

use crate::event::ExchangeId;

/// Detail payload: where and why a protocol element failed grammar.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[display("malformed head at byte {at}: {what}")]
pub struct MalformedDetail {
  at: usize,
  what: &'static str,
}

impl MalformedDetail {
  /// Creates a detail from the offending byte offset and a static description.
  ///
  /// Crate-private so a detail can only ever come from a real parse position.
  #[inline(always)]
  pub(crate) const fn new(at: usize, what: &'static str) -> Self {
    Self { at, what }
  }

  /// Byte offset of the offending input.
  #[inline(always)]
  pub const fn at(&self) -> usize {
    self.at
  }

  /// Static description of the violation.
  #[inline(always)]
  pub const fn what(&self) -> &'static str {
    self.what
  }
}

/// The status vocabulary, under the name this crate has always used.
///
/// The type lives in `http-semantics` as `Status`, because RFC 9110's rules are
/// version-independent and every HTTP version's crate needs the same codes. The
/// alias keeps every call site here unchanged.
pub use http_semantics::status::Status as SuggestedStatus;

/// A LOCAL policy limit refused a message the peer framed correctly.
///
/// Deliberately NOT an [`H1Error`]: nothing on the wire broke a rule, so this
/// is not a violation, the connection does NOT enter its failed state, and
/// [`send_error_response`](crate::Connection::send_error_response) stays
/// unreachable. RFC 9110 §15.5.14 names this as a double MAY — "The server MAY
/// terminate the request, if the protocol version in use allows it; otherwise,
/// the server MAY close the connection" — and this core takes the second
/// branch, because HTTP/1.1 has no way to terminate one request without the
/// connection.
///
/// What a refused connection still owes: on a SERVER, exactly one final
/// response, and it must state the `close` connection option (RFC 9110 §10.1.1
/// makes stating it a SHOULD, and RFC 9112 §9.3 makes closing the branch this
/// end has taken). On a CLIENT there is nothing to write; the prefix of the
/// body already handed over is not the representation, since RFC 9112 §8
/// requires an incomplete response to be recorded as incomplete, and this one
/// ends in an error rather than in a completion.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
  /// The message's content exceeded the limit in force for it.
  #[error("inbound body exceeds the {limit}-octet limit in force for this message")]
  BodyTooLarge {
    /// The exchange whose body was refused.
    exchange: ExchangeId,
    /// The LIMIT that refused it, not the observed size — the observed size is
    /// unbounded and unknowable, since the peer may never stop. The same choice
    /// [`H1Error::HeadTooLarge`] already makes.
    limit: u64,
  },
  /// The message spent more on RFC 9112 §7.1 chunk-size lines than the budget
  /// in force for it.
  ///
  /// FRAMING, not content, and the two are bounded separately because a payload
  /// ceiling cannot see this one: a chunk-size line may announce a single octet
  /// and spend hundreds, so a body inside its content limit can still make this
  /// end parse an unbounded number of framing octets. What RFC 9112 §7.1.1 asks
  /// a server to limit is ONE part of that line — "the total length of chunk
  /// extensions received in a request", "in the same way that it applies length
  /// limitations and timeouts for other parts of a message" — and this budget
  /// charges the WHOLE line, a stricter generalization of that ask, because the
  /// padding line it exists to catch spends its octets on digits and leaves
  /// §7.1.1 nothing to govern. Local policy either way, under RFC 9110 §15.5's
  /// 4xx class; nothing on the wire broke a rule, so this is a refusal like its
  /// sibling and not a violation.
  #[error("inbound body exceeds the {limit}-octet chunk-framing budget in force for this message")]
  ChunkFramingTooLarge {
    /// The exchange whose body was refused.
    exchange: ExchangeId,
    /// The BUDGET that refused it, in chunk-size-line octets — digits,
    /// extension and the CRLF that ends the line. Not the observed total, for
    /// the reason its sibling gives.
    limit: u64,
  },
}

impl Refusal {
  /// The response status a server driver is advised to answer this refusal
  /// with.
  #[inline(always)]
  pub const fn suggested_status(self) -> SuggestedStatus {
    match self {
      Self::BodyTooLarge { .. } => SuggestedStatus::ContentTooLarge,
      // RFC 9112 §7.1.1 asks the server to "generate an appropriate 4xx (Client
      // Error) response if that amount is exceeded" — a 4xx, and not 413, whose
      // name (RFC 9110 §15.5.14, "Content Too Large") is about content this
      // message may be well inside. The generic 400 is the appropriate one: no
      // status names over-large framing.
      Self::ChunkFramingTooLarge { .. } => SuggestedStatus::BadRequest,
    }
  }
}

/// Protocol violations: the wire data broke an RFC 9110 / RFC 9112 rule.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum H1Error {
  /// No CRLF at all within the cap: the request-line itself overflowed.
  #[error("request-line exceeds {0} bytes without terminating")]
  RequestLineTooLong(usize),
  /// No terminating blank line within the head byte cap.
  #[error("head exceeds {0} bytes without terminating")]
  HeadTooLarge(usize),
  /// More header fields in the head than the field-count cap.
  #[error("head has more than {0} header fields")]
  TooManyHeaders(usize),
  /// Grammar violation at a known byte offset.
  #[error("{0}")]
  Malformed(MalformedDetail),
  /// The message announced an HTTP version this core does not speak (HTTP/2.0,
  /// HTTP/0.9, …).
  #[error("unsupported HTTP version")]
  VersionNotSupported,
  /// A message framing rule was broken (RFC 9112 §6.1 / §6.2 / §6.3).
  ///
  /// Two kinds of fault, one variant. Some are genuinely CONFLICTING framings —
  /// both `Transfer-Encoding` and `Content-Length`, duplicate `Content-Length`
  /// values that disagree — and some are single-sided: `chunked` that is not the
  /// final coding of a request, a handshake message announcing content, a
  /// message truncated by a close before its framing said it ended, a takeover
  /// the connection's mode cannot perform. The `Display` text therefore reads
  /// "message framing violated", which covers both; "conflicting" was true of
  /// only the first kind. The payload names the rule.
  ///
  /// A separate `Incomplete` variant for the truncation faults was considered
  /// and DECLINED: a message the peer stopped mid-sentence has broken a framing
  /// rule like any other — RFC 9112 §6.3 item 6 makes a close before the
  /// announced octets an incomplete message — and what a recipient does about it
  /// (report the [`suggested_status`](Self::suggested_status), close the
  /// connection) is what it does about every other entry here. Splitting the
  /// variant would put a distinction in the type system that no caller branches
  /// on. This enum is `#[non_exhaustive]`, so adding one remains available if a
  /// caller ever needs to.
  #[error("message framing violated: {0}")]
  Framing(&'static str),
  /// A transfer coding other than `chunked` was requested (RFC 9112 §7).
  #[error("unsupported transfer coding: {0}")]
  UnsupportedCoding(&'static str),
}

impl H1Error {
  /// The response status a server driver is advised to answer this violation
  /// with.
  #[inline(always)]
  pub const fn suggested_status(&self) -> SuggestedStatus {
    match self {
      Self::RequestLineTooLong(_) => SuggestedStatus::UriTooLong,
      Self::HeadTooLarge(_) | Self::TooManyHeaders(_) => SuggestedStatus::FieldsTooLarge,
      Self::Malformed(_) | Self::Framing(_) => SuggestedStatus::BadRequest,
      Self::VersionNotSupported => SuggestedStatus::VersionNotSupported,
      Self::UnsupportedCoding(_) => SuggestedStatus::NotImplemented,
    }
  }
}

/// API misuse and resource errors: caller-side faults, not wire-side ones.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
  /// The caller-supplied output slice was smaller than the call needed.
  #[error("output buffer too small: need {need}, have {have}")]
  BufferTooSmall {
    /// Bytes the call needed to write.
    need: usize,
    /// Bytes the destination had available.
    have: usize,
  },
  /// The operation is not valid for the connection's current state.
  #[error("operation invalid in current connection state: {0}")]
  InvalidState(&'static str),
  /// A protocol violation on the wire.
  #[error(transparent)]
  Protocol(#[from] H1Error),
  /// This end's own POLICY refused a well-formed message.
  ///
  /// NOT terminal, and that is the difference from
  /// [`Protocol`](Self::Protocol): the connection has not failed, a server
  /// still owes exactly one response, and that response must state `close`.
  #[error(transparent)]
  Refused(#[from] Refusal),
}

impl Error {
  /// The response status a server driver is advised to answer with. Delegates
  /// through [`Protocol`](Self::Protocol); `None` for caller-side errors, which
  /// no peer caused and no response addresses.
  ///
  /// ADVISORY, and on a CLIENT connection purely DIAGNOSTIC: a client has no
  /// response to send, so nothing it reads here will ever reach the wire. The
  /// code still names what the peer did — a 505 out of a client means the
  /// response stated a version this core does not speak — which is a log line
  /// and a metric, not an instruction. Only a server encodes one, through
  /// [`send_error_response`](crate::Connection::send_error_response) or Tunnel's
  /// [`reject`](crate::Connection::reject), and even there it is a suggestion:
  /// the driver is free to answer differently or to close without answering.
  #[inline(always)]
  pub const fn suggested_status(&self) -> Option<SuggestedStatus> {
    match self {
      Self::Protocol(e) => Some(e.suggested_status()),
      Self::Refused(r) => Some(r.suggested_status()),
      Self::BufferTooSmall { .. } | Self::InvalidState(_) => None,
    }
  }
}

#[cfg(all(test, any(feature = "std", feature = "alloc", feature = "no-atomic")))]
mod tests {
  use super::*;

  // RFC 9112 §2.2: bare CR is not a line terminator; the offset locates it.
  #[test]
  fn malformed_detail_reports_position() {
    let e = H1Error::Malformed(MalformedDetail::new(7, "bare CR"));
    assert_eq!(e.suggested_status(), SuggestedStatus::BadRequest);
    assert_eq!(std::format!("{e}"), "malformed head at byte 7: bare CR");
  }

  // RFC 9110 §15.5.1 (400), §15.5.15 (414), §15.6.2 (501); RFC 6585 §5 (431).
  #[test]
  fn suggested_status_codes() {
    assert_eq!(SuggestedStatus::BadRequest.code(), 400);
    assert_eq!(SuggestedStatus::UriTooLong.code(), 414);
    assert_eq!(SuggestedStatus::FieldsTooLarge.code(), 431);
    assert_eq!(SuggestedStatus::NotImplemented.code(), 501);
  }

  // RFC 9112 §3 (MUST answer an over-long request-target with 414); RFC 6585 §5
  // (431 for an over-large field section).
  #[test]
  fn head_too_large_maps_to_431_and_request_line_to_414() {
    assert_eq!(
      H1Error::HeadTooLarge(16384).suggested_status(),
      SuggestedStatus::FieldsTooLarge
    );
    assert_eq!(
      H1Error::RequestLineTooLong(16384).suggested_status(),
      SuggestedStatus::UriTooLong
    );
  }

  // RFC 9112 §7.1 (unsupported transfer coding → 501 per RFC 9110 §15.6.2);
  // RFC 9110 §15.6.6 (505 for an unsupported HTTP version).
  #[test]
  fn unsupported_coding_maps_to_501_and_version_to_505() {
    assert_eq!(
      H1Error::UnsupportedCoding("gzip").suggested_status(),
      SuggestedStatus::NotImplemented
    );
    assert_eq!(
      H1Error::VersionNotSupported.suggested_status(),
      SuggestedStatus::VersionNotSupported
    );
    assert_eq!(SuggestedStatus::VersionNotSupported.code(), 505);
  }

  // RFC 6585 §5: a field count over the cap is a 431; caller-side misuse has no
  // wire status at all.
  #[test]
  fn h1_error_converts_into_error_and_delegates_suggestion() {
    let e: Error = H1Error::TooManyHeaders(64).into();
    assert!(matches!(e, Error::Protocol(H1Error::TooManyHeaders(64))));
    assert_eq!(e.suggested_status(), Some(SuggestedStatus::FieldsTooLarge));
    assert_eq!(Error::InvalidState("x").suggested_status(), None);
  }
}
