//! Semantic validation of a scanned head: the role-aware rules a well-formed
//! head still has to satisfy, and the RFC 9112 §6.3 decision about where the
//! message body ends.
//!
//! The scan answers a syntactic question — is every line well-formed, and what
//! did it contain? This module answers the questions that need the start line
//! the scanner deliberately did not parse: a request must carry exactly one
//! `Host`, pair its target form with its method, and be framed by `chunked` or
//! by `Content-Length` or not at all; a response is framed by the status it
//! carries and the request it answers before any field of its own is read.
//!
//! §6.3 is a list IN ORDER OF PRECEDENCE, and it is applied as one. A 204 is
//! bodiless because item 1 says so, not because a `Content-Length` was read and
//! then overridden. That ordering is the security property: a recipient that
//! reads the framing fields first and applies the status rule afterwards is how
//! a body nobody expects gets attributed to the next message on the connection
//! (§11.1 response splitting, §11.2 request smuggling).
//!
//! Nothing here re-reads a byte the scan already recorded. The framing fields
//! arrive as `KeyFields` spans, and only a field the peer REPEATED sends
//! validation back over the block through `HeadView::header_all` — a span
//! covers the first line alone, and the second line is exactly the smuggling
//! case.

use crate::{
  error::{H1Error, MalformedDetail},
  grammar::{
    QuotedScan, eq_ignore_ascii, is_valid_authority, list_elements, scan_quoted,
    scan_quoted_after_join, skip_ows, token_end,
  },
  head::{HeadView, RequestLine, StatusLine, Target, Version},
};

/// How the message body is delimited. RFC 9112 §6.3, branch for branch.
///
/// Deliberately NOT `#[non_exhaustive]`, unlike [`Item`](crate::Item) and the
/// tunnel outcomes: §6.3's list is what closes this set, so a fifth delimitation
/// would be a change to HTTP/1.1 rather than to this crate. The receive-side
/// twin of [`BodyPlan`](crate::BodyPlan), which says the same thing for the same
/// reason.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BodyFraming {
  /// No body is present: the message ends at the empty line that closed its
  /// head. Item 1 (a bodiless status or a HEAD response), item 2 (a CONNECT
  /// 2xx, where the connection becomes a tunnel), and item 7 (a request with no
  /// framing at all) all land here.
  None,
  /// Exactly this many octets follow the head (item 6). A recipient that sees
  /// the connection close first MUST treat the message as incomplete.
  ContentLength(u64),
  /// The chunked transfer coding delimits the body (item 4, §7.1): the body
  /// ends at the zero-size chunk and the trailer section that may follow it.
  ///
  /// This describes DELIMITATION only: on a response the chunk-decoded octets
  /// may still carry a transfer coding this core did not decode, since item 4
  /// ¶1 frames a body by its final coding whatever sits beneath it.
  Chunked,
  /// The body ends when the peer closes the connection (item 8).
  ///
  /// Responses only. A request is never close-delimited — §6.3's note is
  /// explicit that the absence of both framing fields means a request ends at
  /// its head — so a request that reaches this state would be a recipient
  /// waiting forever for a client that is waiting for its response.
  ReadToClose,
}

/// Connection-delta directives extracted from a validated head.
///
/// Facts about THIS message, in the version-aware form the connection layer
/// acts on: the scan records the underlying tokens version-agnostically, and
/// the HTTP/1.0 MUST-ignores (RFC 9110 §7.8 for `Upgrade`, §10.1.1 for
/// `Expect`) are applied here, where the start line is known.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct HeadDirectives {
  /// The connection does not survive this message: `Connection: close`
  /// (RFC 9112 §9.6), or an HTTP/1.0 message that did not ask to persist (§9.3
  /// makes 1.1 persistent by default and 1.0 not).
  ///
  /// [`ends_persistence`] is where both halves are decided, and it is what Tunnel
  /// mode calls as well. The 1.0-asked-to-persist case has no field of its own:
  /// it is exactly `is_http_10(version) && !close`, so a second flag saying it
  /// would be a derived fact with no consumer — which is what it was.
  pub close: bool,
  /// The message offers a protocol upgrade: `Connection` lists `upgrade` AND an
  /// `Upgrade` field is present (RFC 9110 §7.8 requires both). False on an
  /// HTTP/1.0 request, whose `Upgrade` a server MUST ignore.
  pub has_upgrade: bool,
  /// `Expect: 100-continue` (RFC 9110 §10.1.1). Requests only, and false on an
  /// HTTP/1.0 request, whose expectation a server MUST ignore.
  pub expect_continue: bool,
  /// An expectation other than `100-continue`, which §10.1.1 lets a server
  /// answer with 417. Surfaced rather than rejected: 417 is the semantic
  /// layer's MAY, not a framing fault, so nothing here suggests it.
  pub has_other_expect: bool,
}

/// Validates a REQUEST head's semantics, returning its body framing and the
/// connection directives it carries.
///
/// Enforced, in this order:
///
/// - RFC 9112 §3.2.3/§3.2.4 target-method pairing: the authority-form is
///   CONNECT's and only CONNECT's, and the asterisk-form is the server-wide
///   OPTIONS request's.
/// - §3.2 `Host`: exactly one field line on HTTP/1.1, with a value that is
///   either a valid authority or EMPTY. An empty value is legal and is
///   short-circuited before the authority grammar — a client whose target URI
///   has no authority component MUST send `Host` with an empty field value, so
///   refusing it would refuse a conformant request. The three §3.2 MUSTs keep
///   their own scopes: a MISSING `Host` is a fault of an "HTTP/1.1 request
///   message", so a 1.0 request without one validates, while a REPEATED or
///   INVALID one is a fault of "any request message" and is rejected whatever
///   the version.
/// - §6.1 framing: an HTTP/1.0 request carrying `Transfer-Encoding` has faulty
///   framing; `Transfer-Encoding` together with `Content-Length` is a
///   [`Framing`](crate::error::H1Error::Framing) error (§6.3 item 3 — the
///   server MUST also close the connection after responding, §6.1); a
///   `Transfer-Encoding` that carries `chunked` anywhere but as its single,
///   final, unparameterized coding (§7.1 defines no parameters for it), and one
///   that lists no coding at all, are `Framing` errors, which §6.3 item 4's
///   request half makes a MUST-400; a list carrying a coding this core cannot
///   decode, with no misplaced `chunked` to diagnose ahead of it, is
///   [`UnsupportedCoding`](crate::error::H1Error::UnsupportedCoding), which
///   §6.1 answers with 501 — so `chunked, gzip` is a 400, while `gzip, chunked`
///   and a bare `gzip` are 501s. Coding names compare ASCII case-insensitively
///   (§7), and a `Transfer-Encoding` spread over several field lines folds into
///   one list first (RFC 9110 §5.2) — `chunked` on one line and `gzip` on the
///   next is `chunked, gzip`, a chunked that no longer frames anything.
/// - §6.3 items 5-6 `Content-Length`: every value of every line must parse and
///   they must all agree, which is item 5's exception taken (a comma-repeated
///   list of one identical value is processed as that single value); anything
///   else is unrecoverable.
/// - §6.3 item 7: with neither framing field, a request has NO body. A request
///   is never close-delimited.
///
/// Version guards: RFC 9110 §7.8 and §10.1.1 make a server's ignoring of
/// `Upgrade` and of a 100-continue expectation in an HTTP/1.0 request MUSTs, so
/// `has_upgrade` and `expect_continue` come out false there however the fields
/// arrived.
pub(crate) fn validate_request(
  rl: &RequestLine<'_>,
  v: &HeadView<'_>,
) -> Result<(BodyFraming, HeadDirectives), H1Error> {
  check_target_method(rl)?;
  check_host(rl.version, v)?;
  let framing = request_framing(rl.version, v)?;

  let mut directives = connection_directives(rl.version, v);
  if !is_http_10(rl.version) {
    // DERIVED here, from a value the scan has finished accumulating — the
    // accumulator carries provisional facts and the malformed verdict across
    // every field line and across §5.2's join, and this is the first point at
    // which the whole combined value is known to be complete.
    let expect = v.key_fields().expect;
    directives.expect_continue = expect.expects_continue();
    directives.has_other_expect = expect.has_other();
  }
  Ok((framing, directives))
}

/// Validates a RESPONSE head against the request context it answers, returning
/// its body framing and the connection directives it carries.
///
/// `req_method_head` and `req_connect` say whether the request this answers
/// used the HEAD or the CONNECT method; both change the framing regardless of
/// what the response itself carries, which is why they are parameters rather
/// than something a response could be read for.
///
/// RFC 9112 §6.3 is applied AS THE ORDERED LIST IT IS:
///
/// 1. A 1xx, 204, or 304 status, and any response to HEAD, is bodiless
///    ([`BodyFraming::None`]) — "regardless of the header fields present in the
///    message". A `Transfer-Encoding` on a 1xx or 204 is a sender violation of
///    §6.1, not a recipient framing error, and it does not change the answer.
/// 2. A 2xx to CONNECT is bodiless: the connection becomes a tunnel after the
///    head, and a client MUST IGNORE any `Content-Length` or
///    `Transfer-Encoding` it received in such a message.
/// 3. Only now are the fields read, and a message carrying BOTH is a framing
///    error (item 3). The item is written over "a message", not over a request:
///    "Such a message might indicate an attempt to perform request smuggling
///    (Section 11.2) or response splitting (Section 11.1) and ought to be
///    handled as an error" — and §11.1 is the RESPONSE half of that pair, so
///    taking the error branch on a request and the override branch on a response
///    would leave this end forwarding the exact message the item names. The
///    rejection is therefore role-agnostic, and the connection latches: two
///    recipients reading one message by different fields is the disagreement
///    both sections are about.
/// 4. A `Transfer-Encoding` whose FINAL coding is `chunked` delimits the body
///    as [`BodyFraming::Chunked`] (item 4 ¶1) — even when a coding beneath it
///    is one this core cannot decode. DELIMITATION and DECODING are separate
///    questions and item 4 ¶1 answers only the first: where a body ends is a
///    property of the outermost coding, so `gzip, chunked` ends exactly where
///    its chunked stream ends, and unwrapping the gzip underneath is a layer
///    above this core rather than a reason to misframe the message. Every other
///    list — `chunked` not final, absent, applied more than once (§6.1), or
///    carrying parameters (§7.1) — is [`BodyFraming::ReadToClose`] (item 4 ¶2)
///    and NOT an error: a response the recipient cannot delimit by chunked is
///    close-delimited, never rejected.
/// 5. With no `Transfer-Encoding`, `Content-Length` frames the body under the
///    same all-values-must-agree rule as a request (items 5-6).
/// 6. Otherwise the body ends when the connection closes (item 8).
///
/// TWO rejections, and both say the same thing about the connection rather than
/// about the body: this message's framing cannot be trusted, so nothing after it
/// can be either.
///
/// - §6.1's, refused ahead of the list: a response from an HTTP/1.0 peer
///   carrying `Transfer-Encoding` MUST be treated as faulty framing "even if a
///   Content-Length is present".
/// - §6.3 item 3's, at step 3 above: both framing fields on a response items 1-2
///   did not already make bodiless. The request path refuses the same pair with
///   the same constant.
///
/// A 101 never reaches here: the connection layer refuses a 101 on a General
/// connection before validation runs. It is nonetheless answered like every
/// other 1xx, so this function is total over the status space rather than
/// relying on that guarantee.
///
/// On the status suggestions this may return: a client has no response to send,
/// so [`SuggestedStatus`](crate::error::SuggestedStatus) is diagnostic here —
/// only a server ever encodes one. In particular a version fault reaching a
/// client keeps propagating as `VersionNotSupported` (505) unchanged, which
/// names what the peer did, not something the client will transmit.
pub(crate) fn validate_response(
  sl: &StatusLine<'_>,
  v: &HeadView<'_>,
  req_method_head: bool,
  req_connect: bool,
) -> Result<(BodyFraming, HeadDirectives), H1Error> {
  // Every condemnation of the head, first and in one place — see
  // `check_response_head`. What is left below is the CHOICE of framing, which
  // only a mode that frames bodies has to make.
  check_response_head(sl, v, req_method_head, req_connect)?;

  let key = v.key_fields();
  let framing = if bodiless_response(sl.code, req_method_head, req_connect) {
    // Items 1-2, before any framing field is consulted.
    BodyFraming::None
  } else if key.transfer_encoding_count > 0 {
    // Item 4, which asks only whether the list DELIMITS the body — not whether
    // this core can decode what the delimited octets carry. The pair item 3
    // condemns was refused above, so a `Content-Length` cannot be here too.
    if codings(v).delimits() {
      BodyFraming::Chunked
    } else {
      BodyFraming::ReadToClose
    }
  } else if key.content_length_count > 0 {
    // Items 5-6. `check_response_head` already proved this parses and agrees, so
    // the `?` here cannot fire; it is written as the same call rather than an
    // unwrap so the two can never read the field differently.
    BodyFraming::ContentLength(content_length(v)?)
  } else {
    BodyFraming::ReadToClose
  };

  // `Expect` is a request field (RFC 9110 §10.1.1), so its two directives stay
  // false here however a response spelled it.
  Ok((framing, connection_directives(sl.version, v)))
}

/// RFC 9112 §6.3 items 1-2: the statuses whose response is bodiless "regardless
/// of the header fields present in the message".
///
/// Shared by the fault check and the framing decision, and by both modes,
/// because it is what makes the difference between a field a recipient IGNORES
/// and one that condemns the message.
pub(crate) const fn bodiless_response(code: u16, req_method_head: bool, req_connect: bool) -> bool {
  req_method_head
    || matches!(code, 100..=199 | 204 | 304)
    || (req_connect && matches!(code, 200..=299))
}

/// Every condemnation of a RESPONSE head that is a property of the HEAD ITSELF,
/// whatever the mode reading it intends to do with the message.
///
/// # The partition
///
/// A response head raises two different kinds of question, and only one of them
/// is General mode's:
///
/// - **Faults of the head** — the message cannot be trusted at all, so no
///   recipient may go on using the connection under it. These are here, and both
///   modes apply them: a head condemned in one mode and accepted in the other is
///   two recipients disagreeing about the same bytes, which is what RFC 9112
///   §11.1 is.
/// - **The framing CHOICE** — which of §6.3's delimitations applies, and hence
///   where the body ends. That is [`validate_response`]'s alone, because Tunnel
///   mode frames no bodies: every message it reads is its head.
///
/// The order is §6.3's own, and items 1-2 are what scope the rest: they answer
/// "regardless of the header fields present in the message", so a field they
/// tell a recipient to IGNORE cannot also condemn it. §6.1's rule sits ahead of
/// the whole list, because it is not a body-length question — it is a statement
/// that this message's framing, and the connection under it, cannot be trusted.
pub(crate) fn check_response_head(
  sl: &StatusLine<'_>,
  v: &HeadView<'_>,
  req_method_head: bool,
  req_connect: bool,
) -> Result<(), H1Error> {
  let key = v.key_fields();
  let has_te = key.transfer_encoding_count > 0;
  let has_cl = key.content_length_count > 0;

  // §6.1: a message from an HTTP/1.0 peer carrying `Transfer-Encoding` MUST be
  // treated as having faulty framing "even if a Content-Length is present".
  // Ahead of §6.3's list, and ahead of items 1-2 with it.
  if has_te && is_http_10(sl.version) {
    return Err(H1Error::Framing(HTTP_10_WITH_TRANSFER_ENCODING));
  }
  // Items 1-2: bodiless whatever the fields say, so the fields below are ones a
  // recipient ignores rather than ones that condemn the message.
  if bodiless_response(sl.code, req_method_head, req_connect) {
    return Ok(());
  }
  // Item 3, whose request twin is in `request_framing`: one rule, one constant,
  // and neither direction resolves the pair by ignoring a field.
  if has_te && has_cl {
    return Err(H1Error::Framing(TE_WITH_CONTENT_LENGTH));
  }
  // Items 5-6: every value of every line must parse and they must all agree. A
  // length this recipient cannot read is one the next recipient may read
  // differently (§11.1).
  if has_cl {
    content_length(v)?;
  }
  Ok(())
}

/// Checked decimal parse of ONE `Content-Length` value: RFC 9110 §8.6 spells it
/// `1*DIGIT`, and nothing else is accepted.
///
/// No sign, no whitespace, no other base, and no value past `u64::MAX`, since a
/// wrapped length would frame the body at the wrong offset. Leading zeros are
/// digits like any other (`007` is 7).
///
/// The caller splits a comma-separated value into its elements first: this
/// parses a single value, and item 5's identical-list rule is applied around
/// it. A [`HeadView`] does exactly that with the public companions
/// [`grammar::list_elements`](crate::grammar::list_elements) and
/// [`grammar::trim_ows`](crate::grammar::trim_ows), which a caller composes
/// the same way.
///
/// # Errors
///
/// [`H1Error::Framing`] when the value is not `1*DIGIT`, or when it exceeds
/// `u64::MAX` — an overflow is a framing error rather than a wrapped length.
pub fn parse_content_length(v: &[u8]) -> Result<u64, H1Error> {
  if v.is_empty() || !v.iter().all(|b| b.is_ascii_digit()) {
    return Err(H1Error::Framing("Content-Length is not 1*DIGIT"));
  }
  // All-ASCII-digits, so the borrow cannot fail and the parse can only fail by
  // overflowing the u64 the core frames with.
  core::str::from_utf8(v)
    .ok()
    .and_then(|digits| digits.parse::<u64>().ok())
    .ok_or(H1Error::Framing("Content-Length exceeds u64"))
}

/// RFC 9112 §6.1: chunked postdates HTTP/1.0, and a message from a 1.0 peer
/// carrying `Transfer-Encoding` MUST be treated as having faulty framing.
const HTTP_10_WITH_TRANSFER_ENCODING: &str = "HTTP/1.0 message carries Transfer-Encoding";

/// RFC 9112 §7.1 is the only transfer coding this core implements; §6.1 answers
/// a request carrying any other with 501.
const ONLY_CHUNKED: &str = "this core decodes only chunked";

/// RFC 9112 §7's `transfer-coding` grammar, not satisfied — an element that is
/// not `token *( OWS ";" OWS transfer-parameter )`, a parameter without its
/// value, an unterminated quoted-string, or a byte between two codings that is
/// not a comma.
const MALFORMED_CODING_LIST: &str = "Transfer-Encoding is not a transfer-coding list";

/// RFC 9112 §6.3 item 3: a message carrying both framing fields "ought to be
/// handled as an error", and §6.1 makes closing the connection afterwards a
/// MUST — the two fields disagreeing is the smuggling primitive itself.
///
/// ONE constant for both directions, because item 3 is ONE rule: it is written
/// over "a message", and it names §11.2 request smuggling and §11.1 response
/// splitting in the same breath. A recipient that rejected the pair on a request
/// and quietly resolved it on a response would be the second of the two
/// disagreeing recipients those sections define — the response half is the one
/// whose body gets attributed to the message behind it.
const TE_WITH_CONTENT_LENGTH: &str = "both Transfer-Encoding and Content-Length";

/// Builds a positioned semantic violation. `at` is an offset within the head
/// block, which is what every offset the scan recorded is measured in.
fn malformed(at: usize, what: &'static str) -> H1Error {
  H1Error::Malformed(MalformedDetail::new(at, what))
}

/// Whether the message announced HTTP/1.0, which several MUSTs turn on.
fn is_http_10(version: Version) -> bool {
  matches!(version, Version::Http10)
}

/// RFC 9112 §3.2.3 and §3.2.4: the authority-form belongs to CONNECT and to no
/// other method, and the asterisk-form to a server-wide OPTIONS request.
///
/// The offsets point at the request-target's first byte. A request-line starts
/// at byte 0 of the head and its target starts one SP past the method, so that
/// offset is arithmetic over what the codec already returned — the line is not
/// parsed a second time.
fn check_target_method(rl: &RequestLine<'_>) -> Result<(), H1Error> {
  match target_method_fault(rl.method, &rl.target) {
    Some(what) => Err(malformed(rl.method.len().saturating_add(1), what)),
    None => Ok(()),
  }
}

/// The §3.2.3/§3.2.4 pairing as a PREDICATE over the two things it is about: the
/// method and the target form. `None` when they go together.
///
/// Split out from [`check_target_method`] so the SEND side asks the identical
/// question of a caller's arguments, with the identical wording, rather than
/// with a second copy of the rule — a request this core writes and refuses to
/// read is a message it has no business putting on a connection. The receive
/// side positions the answer within a head; the send side has no head to
/// position it in, since the message it would have gone into was never produced.
pub(crate) fn target_method_fault(method: &str, target: &Target<'_>) -> Option<&'static str> {
  let authority = matches!(*target, Target::Authority { .. });
  // RFC 9110 §9.1 makes a method a case-SENSITIVE token, so this is exact
  // equality and `connect` is not CONNECT.
  let connect = method == "CONNECT";
  if connect != authority {
    return Some(if connect {
      "CONNECT request-target is not in the authority-form"
    } else {
      "authority-form request-target from a method other than CONNECT"
    });
  }
  if matches!(*target, Target::Asterisk) && method != "OPTIONS" {
    return Some("asterisk-form request-target from a method other than OPTIONS");
  }
  None
}

/// RFC 9112 §3.2's `Host` VALUE rule: a valid authority (RFC 3986 §3.2.2, no
/// userinfo per RFC 9110 §7.2) or EMPTY.
///
/// The empty case is checked first and accepted: a client whose target URI has
/// no authority component MUST send `Host` with an empty field value, and the
/// authority grammar is non-empty-strict, so testing it first would refuse a
/// conformant request.
///
/// `pub(crate)` for the same reason the pairing above is: the send side holds
/// its callers to the rule this side holds a peer to, out of one implementation.
/// The value handed here must already be OWS-trimmed (RFC 9110 §5.5 makes the
/// whitespace no part of the value) — the scan trims what it records, and the
/// send side trims what a caller supplied, because that is what the recipient
/// will read.
pub(crate) fn host_value_is_valid(value: &[u8]) -> bool {
  value.is_empty() || core::str::from_utf8(value).is_ok_and(is_valid_authority)
}

/// RFC 9112 §3.2: at most one `Host` field line, whose value is a valid
/// authority (RFC 3986 §3.2.2, no userinfo per RFC 9110 §7.2) or empty — and
/// exactly one on HTTP/1.1.
///
/// The three §3.2 MUSTs are scoped differently, and the scoping is enforced
/// rather than flattened. A MISSING `Host` is a 400 for "any HTTP/1.1 request
/// message"; `Host` is an HTTP/1.1 addition, and a 1.0 request without one is
/// legal, so it validates. A REPEATED or INVALID `Host` is a 400 for "any
/// request message", version unqualified — so a 1.0 request that does send one
/// is held to both.
///
/// The empty value is checked FIRST and accepted: a client whose target URI has
/// no authority component MUST send `Host` with an empty field value, and the
/// authority grammar is non-empty-strict, so testing it first would reject a
/// conformant request. Only a NON-empty value is put to the grammar.
fn check_host(version: Version, v: &HeadView<'_>) -> Result<(), H1Error> {
  let key = v.key_fields();
  let Some(span) = key.host else {
    if is_http_10(version) {
      return Ok(());
    }
    // Where the missing field belongs: the first byte past the request-line is
    // where the field section starts.
    return Err(malformed(
      v.start_line_bytes().len(),
      "HTTP/1.1 request has no Host field",
    ));
  };
  // Both faults are reported at the FIRST `Host` line's value — the field the
  // fault is about.
  if key.host_count > 1 {
    return Err(malformed(span.value_at(), "more than one Host field line"));
  }
  // A span that does not resolve cannot happen for a view over the block it was
  // scanned from; it is answered as an invalid value rather than as the empty
  // one, which is the legal case.
  let Some(value) = v.key_value(span) else {
    return Err(malformed(span.value_at(), "invalid Host field value"));
  };
  if !host_value_is_valid(value) {
    return Err(malformed(span.value_at(), "invalid Host field value"));
  }
  Ok(())
}

/// The RFC 9112 §6.3 framing decision for a request: items 3-4 (`chunked`),
/// items 5-6 (`Content-Length`), then item 7 (no body).
fn request_framing(version: Version, v: &HeadView<'_>) -> Result<BodyFraming, H1Error> {
  let key = v.key_fields();
  let has_te = key.transfer_encoding_count > 0;
  let has_cl = key.content_length_count > 0;

  if has_te {
    if is_http_10(version) {
      return Err(H1Error::Framing(HTTP_10_WITH_TRANSFER_ENCODING));
    }
    // §6.3 item 3, whose response twin is in `validate_response`: one rule, one
    // constant, and neither direction resolves the pair by ignoring a field.
    if has_cl {
      return Err(H1Error::Framing(TE_WITH_CONTENT_LENGTH));
    }
    return match codings(v) {
      Codings::Chunked => Ok(BodyFraming::Chunked),
      Codings::NotFramed(what) => Err(H1Error::Framing(what)),
      Codings::ChunkedUndecodable(what) | Codings::Undecodable(what) => {
        Err(H1Error::UnsupportedCoding(what))
      }
    };
  }
  if has_cl {
    return Ok(BodyFraming::ContentLength(content_length(v)?));
  }
  // Item 7, and the note under item 8: a request is never close-delimited.
  Ok(BodyFraming::None)
}

/// Whether this message ends the connection's persistence — the ONE question
/// both modes ask, answered in one place.
///
/// RFC 9112 §9.6's `close` connection option is the explicit half. §9.3 is the
/// other, and it is the one a raw reading of the field loses: "HTTP/1.1 defaults
/// to the use of persistent connections", while an HTTP/1.0 message is
/// non-persistent unless it says otherwise. §9.3's decision list reaches
/// persistence for a 1.0 message on one branch only: "If the received protocol
/// is HTTP/1.0, the `keep-alive` connection option is present, either the
/// recipient is not a proxy or the message is a response, and the recipient
/// wishes to honor the HTTP/1.0 `keep-alive` mechanism, the connection will
/// persist after the current response". Off that branch the list ends where
/// every other one does: "The connection will close after the current response".
/// So a 1.0 message WITHOUT that option ends persistence just as surely as an
/// explicit `close` does.
///
/// `pub(crate)` because Tunnel mode asks it too. Re-deriving the answer from
/// `KeyFields::connection_close` alone loses the version half, which leaves an
/// `HTTP/1.0 100` looking like a handshake still in flight. One rule, one
/// predicate, both modes.
pub(crate) fn ends_persistence(version: Version, v: &HeadView<'_>) -> bool {
  let key = v.key_fields();
  // A `Connection` this recipient could not parse ends persistence, and that is
  // the conservative reading rather than a new error class. We cannot know what
  // the peer asked for, and this crate already answers that question the same
  // way elsewhere: RFC 9112 §6.3 item 4 ¶2 makes a response whose chunked
  // declaration cannot be trusted close-delimited rather than trusted. An
  // untrustworthy connection-control field gets the same treatment — the
  // connection ends after this message instead of being reused on a guess.
  key.connection_malformed
    || key.connection_close
    || (is_http_10(version) && !key.connection_keep_alive)
}

/// The version-aware connection facts both roles share.
fn connection_directives(version: Version, v: &HeadView<'_>) -> HeadDirectives {
  let key = v.key_fields();
  let ten = is_http_10(version);
  HeadDirectives {
    close: ends_persistence(version, v),
    // RFC 9110 §7.8: a sender of `Upgrade` MUST also send the `upgrade`
    // connection option, and a server MUST ignore an `Upgrade` field in an
    // HTTP/1.0 request.
    // …and no option is derived from a value that did not parse, so a
    // `Connection: upgrade,@` cannot authorise a protocol switch off a field
    // whose real meaning is unknown.
    has_upgrade: !ten
      && !key.connection_malformed
      && key.connection_upgrade
      && key.has_upgrade_field,
    expect_continue: false,
    has_other_expect: false,
  }
}

/// The verdict on a message's `Transfer-Encoding`, its field lines folded into
/// the single list RFC 9110 §5.2 makes them.
///
/// Two independent questions, which RFC 9112 §6.3 item 4 keeps apart and so
/// does this: does the list DELIMIT the body (is `chunked` its final coding?),
/// and can this core DECODE what that delimitation contains? A response only
/// ever needs the first — it has to know where the message ends — while a
/// request needs both, because a server that cannot decode what it was sent
/// answers rather than processes.
///
/// `pub(crate)` because the SEND side asks the same question of a caller's
/// declared list ([`CodingList`]) and must not ask it with a second
/// implementation. It reads the answer more strictly: a sender knows which
/// codings it actually applied, so only [`Codings::Chunked`] describes a message
/// this core is willing to write.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Codings {
  /// Delimited and decodable: one `chunked`, final, unparameterized, alone.
  Chunked,
  /// Delimited by a final `chunked`, but a coding beneath it is one this core
  /// cannot decode. The body still ends where the chunked stream ends (item 4
  /// ¶1); a REQUEST is nonetheless answered 501 (§6.1), since a server that
  /// cannot decode the content has nothing to process.
  ChunkedUndecodable(&'static str),
  /// Neither delimited nor decodable: the list names no `chunked` at all, only
  /// codings this core does not implement — §6.1's SHOULD-501 for a request.
  Undecodable(&'static str),
  /// Not delimited: a `chunked` the message carries does not frame it — it is
  /// not the final coding, it is applied more than once (§6.1 forbids that), or
  /// it carries parameters (§7.1 defines none and makes their presence an
  /// error) — or the field lists no coding at all. Item 4's request half makes
  /// this a MUST-400.
  NotFramed(&'static str),
}

impl Codings {
  /// Whether the list delimits the message body by the chunked coding — item 4
  /// ¶1's question, and the only one a response has to answer.
  const fn delimits(self) -> bool {
    matches!(self, Self::Chunked | Self::ChunkedUndecodable(_))
  }
}

/// Classifies a message's `Transfer-Encoding`, reading the repeated field lines
/// only when the peer actually sent more than one.
fn codings(v: &HeadView<'_>) -> Codings {
  let key = v.key_fields();
  if key.transfer_encoding_count > 1 {
    classify_codings(v.header_all("transfer-encoding"))
  } else {
    classify_codings(
      key
        .transfer_encoding
        .and_then(|s| v.key_value(s))
        .into_iter(),
    )
  }
}

/// One `Transfer-Encoding` list, accumulated across the field lines RFC 9110
/// §5.2 folds into it.
///
/// A list rather than a function because the two directions are handed their
/// values differently and must not read them differently: the receive side PULLS
/// them out of a scanned head, while the send side is PUSHED them one at a time
/// by a caller's `Headers` supplier and has no iterator to offer. Both feed this,
/// so the element rules — and the order the verdicts are decided in — exist once.
#[derive(Debug)]
pub(crate) struct CodingList {
  /// How many `chunked` codings the list names.
  chunked: u8,
  /// Whether the coding seen LAST is `chunked` (item 4 ¶1's delimitation
  /// question).
  final_is_chunked: bool,
  /// Whether the list names any coding at all.
  any: bool,
  /// Whether it names a coding this core does not implement.
  undecodable: bool,
  /// Whether a `chunked` carried parameters. Sticky rather than an early return,
  /// which is the one shape difference from a single-pass function — and none in
  /// the verdict, since it is the first thing [`verdict`](Self::verdict) checks.
  parameterized_chunked: bool,
  /// A coding whose quoted parameter value was still open when a field line
  /// ended, waiting for RFC 9110 §5.2's join to continue it.
  ///
  /// Its facts travel with it because they were derived from a NAME that is on
  /// the earlier line: a token never spans the join — the comma §5.2 inserts is
  /// a delimiter everywhere except inside a quoted-string — so only the string
  /// itself, and the element it belongs to, can be in flight at a boundary.
  open: Option<OpenCoding>,
  /// SENDER side only: some element of the COMBINED value is empty (RFC 9110
  /// §5.6.1.1). A recipient reads §5.6.1.2 and ignores them, which is what
  /// `push` does with them.
  saw_empty: bool,
  /// The parse is positioned where an element must appear: at the start, and
  /// after every separator comma. Still true when the LAST line ends means a
  /// trailing empty element.
  expecting: bool,
  /// Some field line was pushed, so the field is PRESENT — which is a different
  /// question from whether it named a coding.
  present: bool,
  /// Some field line is not a well-formed RFC 9112 §7 transfer-coding list.
  ///
  /// The strongest verdict there is, and it outranks everything below: a list
  /// this recipient cannot parse is one the next recipient may parse
  /// DIFFERENTLY, so no coding may be concluded from it — least of all a
  /// `chunked` that would frame the body.
  malformed: bool,
}

impl CodingList {
  /// An empty list — no `Transfer-Encoding` field at all.
  pub(crate) const fn new() -> Self {
    Self {
      chunked: 0,
      final_is_chunked: false,
      any: false,
      undecodable: false,
      parameterized_chunked: false,
      open: None,
      malformed: false,
      saw_empty: false,
      // `#element` starts where an element may appear, so a value that is
      // entirely empty ends there too.
      expecting: true,
      present: false,
    }
  }

  /// SENDER side: the field is present and some element of the COMBINED value is
  /// empty (RFC 9110 §5.6.1.1), counting a value that names no coding at all.
  ///
  /// Asked of the accumulator rather than of each field line, because an element
  /// BOUNDARY is a fact about §5.2's combined value: a line that only continues
  /// an open `quoted-string` has no boundaries in it, and a per-line check
  /// reported one as an empty element.
  ///
  /// The recipient never asks — §5.6.1.2 has it "parse and ignore" empty
  /// elements, and `push` does exactly that.
  pub(crate) const fn empty_element(&self) -> bool {
    // `parsed` first: an element BOUNDARY is a fact about a value that parsed,
    // and a value ending inside an open `quoted-string` has none to call empty.
    // Reporting one as §5.6.1.1's empty element named a rule the caller had not
    // broken — the same confusion `ListShape::Unparseable` exists to prevent.
    self.present && self.parsed() && (self.saw_empty || self.expecting)
  }

  /// Folds one `Transfer-Encoding` field line's value into the list.
  ///
  /// Splitting on commas ahead of parameters is safe for what this accepts: a
  /// parameter is only legal on a coding this core rejects anyway, so a comma
  /// inside a quoted parameter value can only turn one rejected list into
  /// another.
  pub(crate) fn push(&mut self, value: &[u8]) {
    if self.malformed {
      // Nothing further may be derived from a value that did not parse.
      return;
    }
    let joined = self.present;
    self.present = true;
    // RFC 9110 §5.2 makes the field lines ONE value joined by commas, so a
    // quoted parameter value left open at the end of the previous line resumes
    // HERE, with the join's comma as its first character rather than as a
    // separator. Restarting the scan at each physical line called
    // `foo;p="a` + `b", chunked` unterminated and framed the response by the
    // close instead of by its chunked stream — on a persistent connection that
    // eats the next response as body.
    let mut at = 0usize;
    if self.open.is_none() && joined {
      // Not inside a string: §5.2's comma is the SEPARATOR, so it opens a new
      // element — and if one was already expected, what lies between the two
      // commas is empty.
      self.saw_empty |= self.expecting;
      self.expecting = true;
    }
    if let Some(open) = self.open.take() {
      match scan_quoted_after_join(value, open.escape) {
        QuotedScan::Open { escape } => {
          self.open = Some(OpenCoding { escape, ..open });
          return;
        }
        QuotedScan::Invalid => {
          self.malformed = true;
          return;
        }
        QuotedScan::Closed(end) => match self.parameters(value, end, open) {
          // Through the SAME tail a fresh element takes: an element that
          // resumed across the join still has to be followed by a separator or
          // by the end of the line.
          Parsed::Ended(next) => match self.after_element(value, next) {
            Some(next) => at = next,
            None => return,
          },
          Parsed::Suspended => return,
          Parsed::Malformed => {
            self.malformed = true;
            return;
          }
        },
      }
    }

    loop {
      at = skip_ows(value, at);
      match value.get(at) {
        // The end of this field line. The next line, if any, is a new element:
        // the comma §5.2 joins them with is the separator.
        None => return,
        // RFC 9110 §5.6.1.2: an empty list element, which a recipient "MUST
        // parse and ignore" and which contributes nothing to the count.
        Some(b',') => {
          self.saw_empty |= self.expecting;
          self.expecting = true;
          at = at.saturating_add(1);
          continue;
        }
        Some(_) => {}
      }
      let Some(name_end) = token_end(value, at) else {
        self.malformed = true;
        return;
      };
      self.expecting = false;
      let coding = OpenCoding {
        chunked: eq_ignore_ascii(value.get(at..name_end).unwrap_or_default(), "chunked"),
        parameterized: false,
        escape: false,
      };
      match self.parameters(value, name_end, coding) {
        Parsed::Ended(next) => match self.after_element(value, next) {
          Some(next) => at = next,
          None => return,
        },
        Parsed::Suspended => return,
        Parsed::Malformed => {
          self.malformed = true;
          return;
        }
      }
    }
  }

  /// What may follow a completed element: OWS, then a separator comma or the end
  /// of this field line — and nothing else, or the value is not a list.
  ///
  /// The comma is deliberately NOT consumed here. `push`'s separator arm is the
  /// ONE place that advances past one, so there is exactly one place that
  /// records the element a separator opens. Advancing past a comma HERE as well
  /// is what let `Transfer-Encoding: chunked,` finish with no element expected:
  /// §5.6.1.1's trailing empty went unrecorded and this core was willing to put
  /// it on the wire, and an empty element BETWEEN codings escaped the same way.
  fn after_element(&mut self, value: &[u8], at: usize) -> Option<usize> {
    let at = skip_ows(value, at);
    if !matches!(value.get(at), None | Some(b',')) {
      self.malformed = true;
      return None;
    }
    Some(at)
  }

  /// Parses `*( OWS ";" OWS transfer-parameter )` from `at`, commits the coding
  /// it belongs to, and says where the element ended.
  ///
  /// ```text
  /// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
  /// ```
  ///
  /// RFC 9112 §7 gives no production for a bare parameter name, so the `=` and
  /// its value are required. A quoted value that reaches the end of the line
  /// SUSPENDS rather than failing: §5.2's join continues it on the next line.
  fn parameters(&mut self, value: &[u8], at: usize, coding: OpenCoding) -> Parsed {
    let mut at = at;
    let mut coding = coding;
    loop {
      let semicolon = skip_ows(value, at);
      if value.get(semicolon) != Some(&b';') {
        break;
      }
      coding.parameterized = true;
      let param = skip_ows(value, semicolon.saturating_add(1));
      let Some(param_end) = token_end(value, param) else {
        return Parsed::Malformed;
      };
      let equals = skip_ows(value, param_end);
      if value.get(equals) != Some(&b'=') {
        return Parsed::Malformed;
      }
      let argument = skip_ows(value, equals.saturating_add(1));
      if value.get(argument) == Some(&b'"') {
        match scan_quoted(value, argument.saturating_add(1), false) {
          QuotedScan::Closed(end) => at = end,
          QuotedScan::Open { escape } => {
            self.open = Some(OpenCoding { escape, ..coding });
            return Parsed::Suspended;
          }
          QuotedScan::Invalid => return Parsed::Malformed,
        }
      } else {
        match token_end(value, argument) {
          Some(end) => at = end,
          None => return Parsed::Malformed,
        }
      }
    }
    self.commit(coding);
    Parsed::Ended(at)
  }

  /// Folds one fully parsed coding into the list.
  fn commit(&mut self, coding: OpenCoding) {
    self.any = true;
    // RFC 9112 §7: coding names are case-insensitive tokens.
    if coding.chunked {
      self.parameterized_chunked |= coding.parameterized;
      self.chunked = self.chunked.saturating_add(1);
      self.final_is_chunked = true;
    } else {
      self.undecodable = true;
      self.final_is_chunked = false;
    }
  }

  /// Classifies the folded list.
  ///
  /// The checks are ordered by the strength of the rule they enforce: §6.3 item
  /// 4's framing MUST is decided before §6.1's SHOULD-501, so `chunked, gzip`
  /// (nothing frames the body) is a 400 while `gzip, chunked` (framed, but the
  /// content beneath it is not decodable here) is a 501.
  /// Whether the whole combined value parsed as RFC 9112 §7's `#transfer-coding`
  /// — asked apart from what the codings MEAN, because the two questions have
  /// different answers on the two sides of the wire.
  ///
  /// A recipient reads a malformed list as one that frames nothing and
  /// close-delimits (§6.3 item 4 ¶2), which is a body decision. A SENDER is
  /// refused outright, on every path, whether or not the framing it chose
  /// happened to consult the list — so the send side asks THIS rather than
  /// inferring a parse failure from a framing verdict it may never reach.
  pub(crate) const fn parsed(&self) -> bool {
    !self.malformed && self.open.is_none()
  }

  pub(crate) const fn verdict(&self) -> Codings {
    // First, and it is not merely an ordering: nothing below may be believed
    // about a list that did not parse. `chunked` in particular is never
    // concluded final from a field whose elements and separators were not all
    // read cleanly.
    // …including a quoted value still open when the LAST line ended: §5.2 has no
    // further line to continue it with, so the field is unterminated.
    if self.malformed || self.open.is_some() {
      return Codings::NotFramed(MALFORMED_CODING_LIST);
    }
    if self.parameterized_chunked {
      return Codings::NotFramed("chunked transfer coding carries parameters");
    }
    if !self.any {
      return Codings::NotFramed("Transfer-Encoding lists no transfer coding");
    }
    // Item 4's MUST-400 is a rule ABOUT chunked: it fires when a chunked the
    // message DOES carry has been placed where it frames nothing. A list with no
    // chunked in it at all is not a misplaced chunked but a coding this core does
    // not implement, which §6.1 answers with 501 instead.
    if self.chunked > 0 && !self.final_is_chunked {
      return Codings::NotFramed("chunked is not the final transfer coding");
    }
    if self.chunked > 1 {
      return Codings::NotFramed("chunked transfer coding applied more than once");
    }
    if self.undecodable {
      // `final_is_chunked` is the delimitation half: a final `chunked` still ends
      // the body where its stream ends, whatever sits beneath it.
      return if self.final_is_chunked {
        Codings::ChunkedUndecodable(ONLY_CHUNKED)
      } else {
        Codings::Undecodable(ONLY_CHUNKED)
      };
    }
    // Everything left is chunked, exactly once, and final.
    Codings::Chunked
  }
}

/// A coding being parsed, and the facts already derived from its name.
#[derive(Debug, Copy, Clone)]
struct OpenCoding {
  /// The name is RFC 9112 §7.1's `chunked`.
  chunked: bool,
  /// Some parameter was seen — §7.1 defines none for `chunked`.
  parameterized: bool,
  /// Inside a quoted value, the last byte was an unconsumed backslash.
  escape: bool,
}

/// How far one element got.
#[derive(Debug, Copy, Clone)]
enum Parsed {
  /// It ended at this offset, and its facts are committed.
  Ended(usize),
  /// A quoted value is still open; RFC 9110 §5.2's next line continues it.
  Suspended,
  /// It does not satisfy RFC 9112 §7's grammar.
  Malformed,
}

/// Folds the values of a scanned head's `Transfer-Encoding` lines and classifies
/// them — the receive side's way into [`CodingList`].
fn classify_codings<'a>(values: impl Iterator<Item = &'a [u8]>) -> Codings {
  let mut list = CodingList::new();
  for value in values {
    list.push(value);
  }
  list.verdict()
}

/// The `Content-Length` a message is framed by, reading the repeated field
/// lines only when the peer actually sent more than one.
fn content_length(v: &HeadView<'_>) -> Result<u64, H1Error> {
  let key = v.key_fields();
  if key.content_length_count > 1 {
    fold_content_length(v.header_all("content-length"))
  } else {
    fold_content_length(key.content_length.and_then(|s| v.key_value(s)).into_iter())
  }
}

/// RFC 9112 §6.3 item 5: an invalid `Content-Length` is an unrecoverable
/// framing error, UNLESS the value parses as a comma-separated list whose
/// values are all valid and all the same — then that single value is the
/// length.
///
/// The rule spans field lines as well as commas, because RFC 9110 §5.2 makes
/// repeated lines one comma-joined list. A recipient that read only the first
/// line would take a length its peer contradicted on the second, which is the
/// smuggling case (§11.2).
fn fold_content_length<'a>(values: impl Iterator<Item = &'a [u8]>) -> Result<u64, H1Error> {
  let mut agreed: Option<u64> = None;
  for value in values {
    for element in list_elements(value) {
      let length = parse_content_length(element)?;
      match agreed {
        Some(seen) if seen != length => {
          return Err(H1Error::Framing("Content-Length values disagree"));
        }
        _ => agreed = Some(length),
      }
    }
  }
  agreed.ok_or(H1Error::Framing("Content-Length has no value"))
}

#[cfg(test)]
mod tests;
