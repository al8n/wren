//! `httparse` as a leniency tripwire: a second, independently written HTTP/1.1
//! head parser, run over the same corpus this crate's own tests are built from.
//!
//! # The property
//!
//! **This core is never more permissive than `httparse`.** RFC 9112 §11.2 makes
//! that the security-relevant direction: a head this parser accepts and another
//! recipient refuses is a message the two disagree about, and every smuggling
//! chain starts with such a disagreement. So the assertion is one-directional by
//! design — `ours accepts ⇒ httparse accepts` — and it is checked over every
//! vector in the corpus, valid and malformed alike.
//!
//! The OTHER direction is not a failure, but it is not free either: every case
//! where `httparse` accepts and this core refuses has to be named in
//! [`KNOWN_STRICTER`] with the rule that justifies the refusal, and every case
//! the other way round in [`KNOWN_LOOSER`]. An un-adjudicated divergence in
//! either direction fails the suite, and so does an allowlist entry that no
//! longer diverges — a stale allowance is how a real regression gets a
//! standing exemption.
//!
//! # What "accepted" means on each side
//!
//! Three-valued on both, because "I need more bytes" is not a verdict about the
//! bytes in hand and collapsing it into either answer would make an incomplete
//! head look like a refusal:
//!
//! - **Ours** is the PUBLIC API, driven the way a driver drives it: a fresh
//!   `Connection<Server, General>` (or a `Connection<Client, General>` with a
//!   request outstanding, for the response side) is handed the head and asked
//!   for one item. [`Verdict::Accepts`] is an `Item::Head` coming out —
//!   `find_head_end`, `scan_head` and the start-line codec all having passed,
//!   plus the RFC 9112 §6.3 framing decision that follows them. `Ok(None)` is
//!   [`Verdict::NeedsMore`], an `Err` is [`Verdict::Rejects`].
//! - **Theirs** is `httparse::Request::parse` / `Response::parse`:
//!   `Ok(Status::Complete)` is `Accepts`, `Ok(Status::Partial)` is `NeedsMore`,
//!   and `Err` is `Rejects`. No vector in this corpus is TRUNCATED — the
//!   accepted ones all end in CRLFCRLF, and the refused ones are refused for
//!   what is in them rather than for what is missing, the handful that break the
//!   terminator itself being exactly the point of those vectors — so a `Partial`
//!   is treated as non-acceptance, which keeps the permissiveness assertion
//!   conservative in the direction that matters.
//!
//! `httparse` is handed [`SLOTS`] header slots, comfortably more than this
//! core's `MAX_HEADERS`, so `TooManyHeaders` from ITS side is a harness fault
//! rather than a verdict and is reported as one.
//!
//! # Which `httparse` this is compared against
//!
//! The DEFAULT one — `Request::parse` and `Response::parse` — which is also its
//! strictest. Every leniency `httparse` offers is an opt-in `ParserConfig` flag
//! (obs-fold in responses, whitespace after a field name in responses, multiple
//! spaces in a request-line or status-line), and none of them is on here. That
//! matters twice over: it is why the oracle AGREES with this core on obs-fold and
//! on whitespace before a colon rather than allowlisting them, and it is what
//! makes the permissiveness assertion the demanding form of the question —
//! turning any of those flags on can only widen what `httparse` accepts, which
//! can never turn an agreement into a case of this core being more permissive.
//!
//! # Why the pipeline is the connection and not the scanner
//!
//! `find_head_end` and `scan_head` are crate-private, and an integration test
//! that reached them would be testing something no consumer can call. Driving
//! `Connection::handle` instead costs one thing worth naming: the verdict
//! includes the MESSAGE-level rules (a missing `Host`, an unresolvable framing,
//! a takeover a General connection cannot perform), which `httparse` does not
//! implement at all — it parses a head and says nothing about what the head
//! means. Those cases are the bulk of [`KNOWN_STRICTER`], and each one cites the
//! rule it enforces rather than being waved through as "semantics".
//!
//! # The table
//!
//! [`corpus`] pins what THIS core does with each vector before any comparison is
//! made ([`the_corpus_pins_our_own_verdicts`]), so the table is a specification
//! rather than a recording: a change in behaviour fails there first, with the
//! vector named, instead of quietly moving a divergence into an allowlist. The
//! allowlists are keyed by vector NAME rather than by bytes: two vectors are
//! built at run time from `MAX_HEADERS` and `MAX_HEAD_BYTES` and have no
//! literal to key on, and a name is what makes a failure message readable.

use std::borrow::Cow;

use http1_proto::{
  BodyPlan, Client, Connection, General, Item, MAX_HEAD_BYTES, MAX_HEADERS, Server, Target,
};

/// Header slots handed to `httparse`. Above this core's `MAX_HEADERS` so that
/// the two parsers' field-count limits are never what a comparison measures.
const SLOTS: usize = 256;

/// The RFC 9112 §3.2.1 target the client-side driver opens its request with.
const ORIGIN: Target<'static> = Target::Origin {
  path_and_query: "/",
};

/// The one field RFC 9112 §3.2 requires of that request.
const HOST: &[(&str, &[u8])] = &[("Host", b"h")];

/// Which start line a vector carries, and therefore which parser reads it.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Side {
  /// RFC 9112 §3 `request-line`: read by a server here and by
  /// `httparse::Request` there.
  Request,
  /// RFC 9112 §4 `status-line`: read by a client with a request outstanding
  /// here, and by `httparse::Response` there.
  Response,
}

/// What a parser did with a head.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Verdict {
  /// A complete head came out.
  Accepts,
  /// The parser refused these bytes.
  Rejects,
  /// The parser wants more input. Every vector here is a complete head, so this
  /// is itself a divergence worth adjudicating — it is not acceptance.
  NeedsMore,
}

/// One corpus entry.
struct Vector {
  /// What the vector is, and the key both allowlists use.
  name: &'static str,
  /// Which start line it carries.
  side: Side,
  /// The head, terminator included.
  head: Cow<'static, [u8]>,
  /// What THIS core does with it — pinned, not recorded.
  ours: Verdict,
}

/// Builds one borrowed-bytes entry.
fn v(name: &'static str, side: Side, head: &'static [u8], ours: Verdict) -> Vector {
  Vector {
    name,
    side,
    head: Cow::Borrowed(head),
    ours,
  }
}

/// A head carrying `fields` field lines of the form `H<n>: v`.
fn head_with_fields(fields: usize) -> Vec<u8> {
  let mut head = Vec::from(&b"GET /a HTTP/1.1\r\nHost: h\r\n"[..]);
  for line in 0..fields {
    head.extend_from_slice(format!("H{line}: v\r\n").as_bytes());
  }
  head.extend_from_slice(b"\r\n");
  head
}

/// A head whose field section pushes it one byte past `MAX_HEAD_BYTES`, so the
/// terminator falls outside the window this core will scan.
fn over_the_byte_cap() -> Vec<u8> {
  let mut head = Vec::from(&b"GET /a HTTP/1.1\r\nHost: h\r\nX-Pad: "[..]);
  head.resize(MAX_HEAD_BYTES, b'p');
  head.extend_from_slice(b"\r\n\r\n");
  assert!(head.len() > MAX_HEAD_BYTES);
  head
}

/// The corpus: every valid head this crate's test suites drive, and every
/// malformed head its smuggling and head-parsing vectors carry.
///
/// The `Verdict` column is what this core does, asserted separately before any
/// comparison — see the module doc.
fn corpus() -> Vec<Vector> {
  let mut corpus = vec![
    // ---- Valid requests: the shapes the crate's own suites drive. ----
    // RFC 9112 §6.3 item 7: no framing field, so the message is its head.
    v(
      "simple GET",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §6.3 item 6.
    v(
      "POST with Content-Length",
      Side::Request,
      b"POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §6.3 item 4 with §7.1.
    v(
      "POST with chunked",
      Side::Request,
      b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §6.3 item 5's exception: a list of one repeated value.
    v(
      "identical Content-Length list",
      Side::Request,
      b"POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 42, 42\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9110 §10.1.1.
    v(
      "expect-continue",
      Side::Request,
      b"POST /e HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §9.3: 1.0 is not persistent by default, which changes nothing
    // about parsing the head.
    v(
      "HTTP/1.0 request",
      Side::Request,
      b"GET /a HTTP/1.0\r\nHost: h\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §3.2: `Host` is an HTTP/1.1 addition, so a 1.0 request without
    // one is legal.
    v(
      "HTTP/1.0 request without Host",
      Side::Request,
      b"GET /a HTTP/1.0\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §6.3 item 1: the response to this is bodiless whatever it says.
    v(
      "HEAD request",
      Side::Request,
      b"HEAD /a HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §3.2.4 asterisk-form, which is OPTIONS' alone.
    v(
      "OPTIONS asterisk-form",
      Side::Request,
      b"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §3.2.2 absolute-form.
    v(
      "absolute-form target",
      Side::Request,
      b"GET http://example.com/p?q HTTP/1.1\r\nHost: example.com\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9110 §7.8's offer, both halves.
    v(
      "upgrade offer",
      Side::Request,
      b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9110 §5.5: `obs-text` is field content, not an encoding error.
    v(
      "obs-text field value",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\nX-Raw: caf\xC3\xA9\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9110 §5.5: `field-value = *field-content` admits an empty value.
    v(
      "empty field value",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\nX-Empty:\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §3.2: a client whose target URI has no authority MUST send an
    // empty `Host`.
    v(
      "empty Host value",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost:\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9110 §5.6.3: the OWS around a value is trimmed, not content.
    v(
      "OWS around a field value",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\nX-A: \tv \r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9110 §5.6.2 `tchar`: the punctuation a field name may be made of.
    v(
      "punctuation-heavy field name",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\n!#$%&'*+-.^_`|~9: v\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §2.2: a server ignores the empty lines an older client trailed
    // its last request with — bounded, which the next vector is about.
    v(
      "leading empty lines within the bound",
      Side::Request,
      b"\r\n\r\nGET /a HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Accepts,
    ),
    v(
      "leading empty lines past the bound",
      Side::Request,
      b"\r\n\r\n\r\n\r\n\r\nGET /a HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9110 §6.2 (Control Data): a minor version higher than the recipient
    // implements is processed as the highest minor of that major version the
    // recipient IS conformant to — 1.1 here. (The pinpoint is §6.2 and not the
    // section either specification points at first: RFC 9112 §2.3 carries the
    // HTTP-version grammar and delegates version-number SEMANTICS to RFC 9110
    // §2.5, but §2.5 only defines what the two digits mean — the recipient's
    // processing rule is §6.2's.)
    v(
      "HTTP/1.7 minor version",
      Side::Request,
      b"GET /a HTTP/1.7\r\nHost: h\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9110 §9.3.6: a well-formed head, refused for the MODE it needs.
    v(
      "CONNECT in General mode",
      Side::Request,
      b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
      Verdict::Rejects,
    ),
    // ---- Malformed requests: the smuggling and head-grammar vectors. ----
    // RFC 9112 §5.2.
    v(
      "obs-fold",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\nX-A: a\r\n b\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §2.2, both halves of the terminator.
    v(
      "bare CR as a terminator",
      Side::Request,
      b"GET /a HTTP/1.1\rHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "bare CR inside a field value",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\nX-A: a\rb\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "bare LF as a terminator",
      Side::Request,
      b"GET /a HTTP/1.1\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "bare LF between field lines",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\nX-A: b\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §5.1.
    v(
      "SP before the field colon",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost : h\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "HTAB before the field colon",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost\t: h\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §2.2: whitespace where the first field name belongs.
    v(
      "whitespace before the first field line",
      Side::Request,
      b"GET /a HTTP/1.1\r\n Host: h\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9110 §5.6.2 `token`.
    v(
      "non-token field name",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\nBad{}Name: x\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "empty field name",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\n: x\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "field line with no colon",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\nX-Sum\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9110 §5.5: a CTL is not `obs-text` and never field content.
    v(
      "CTL in a field value",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: h\r\nX-A: a\x00b\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §3: single SP only.
    v(
      "double SP in the request-line",
      Side::Request,
      b"GET  /a HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "HTAB in the request-line",
      Side::Request,
      b"GET\t/a HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "trailing SP in the request-line",
      Side::Request,
      b"GET /a HTTP/1.1 \r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "leading SP in the request-line",
      Side::Request,
      b" GET /a HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "SP inside the request-target",
      Side::Request,
      b"GET /a b HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §3.2.1 with RFC 3986 §3.5: a fragment is never part of a
    // request-target.
    v(
      "fragment in the request-target",
      Side::Request,
      b"GET /a#f HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 3986 §3.3: DEL is not a `pchar`.
    v(
      "DEL in the request-target",
      Side::Request,
      b"GET /a\x7Fb HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9110 §9.1 `method = token`.
    v(
      "non-token method",
      Side::Request,
      b"G{}T /a HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §2.3: the version grammar, and the two ways of breaking it.
    v(
      "HTTP/2.0 request",
      Side::Request,
      b"GET /a HTTP/2.0\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "lowercase http-name",
      Side::Request,
      b"GET /a http/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §3.2: exactly one `Host` on HTTP/1.1, and a valid authority.
    v(
      "HTTP/1.1 request without Host",
      Side::Request,
      b"GET /a HTTP/1.1\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "repeated Host",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "invalid Host value",
      Side::Request,
      b"GET /a HTTP/1.1\r\nHost: a b\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §3.2.3/§3.2.4: the target form is paired with the method.
    v(
      "CONNECT without an authority-form target",
      Side::Request,
      b"CONNECT /p HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "asterisk-form from a non-OPTIONS method",
      Side::Request,
      b"GET * HTTP/1.1\r\nHost: h\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §6.3 item 3 with §11.2: the smuggling primitive itself.
    v(
      "Transfer-Encoding beside Content-Length",
      Side::Request,
      b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §6.3 item 5 with RFC 9110 §5.3.
    v(
      "disagreeing Content-Length lines",
      Side::Request,
      b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 42\r\nContent-Length: 43\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9110 §8.6 `Content-Length = 1*DIGIT`.
    v(
      "non-decimal Content-Length",
      Side::Request,
      b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 0x2A\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §7.1: chunked takes no parameters.
    v(
      "parameterized chunked",
      Side::Request,
      b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked;a=b\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §6.3 item 4: chunked is not the final coding — a 400.
    v(
      "chunked before another coding",
      Side::Request,
      b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §6.1: a coding this core cannot decode — a 501.
    v(
      "undecodable coding under a final chunked",
      Side::Request,
      b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §6.1: chunked postdates HTTP/1.0.
    v(
      "HTTP/1.0 request with Transfer-Encoding",
      Side::Request,
      b"POST /u HTTP/1.0\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
      Verdict::Rejects,
    ),
    // ---- Responses. ----
    // RFC 9112 §6.3 item 6.
    v(
      "counted 200",
      Side::Response,
      b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9110 §15.2 with RFC 9112 §4: an interim response, and the SP before
    // an absent reason-phrase.
    v(
      "interim with an empty reason",
      Side::Response,
      b"HTTP/1.1 100 \r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §6.3 item 8.
    v(
      "HTTP/1.0 close-delimited response",
      Side::Response,
      b"HTTP/1.0 200 OK\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §6.3 item 1: bodiless whatever the fields say.
    v(
      "204 No Content",
      Side::Response,
      b"HTTP/1.1 204 No Content\r\n\r\n",
      Verdict::Accepts,
    ),
    v(
      "304 with a Content-Length",
      Side::Response,
      b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §6.3 item 4 ¶1: a final chunked still DELIMITS the body, so the
    // response side accepts the list the request side answers 501 to.
    v(
      "response with gzip under chunked",
      Side::Response,
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9112 §4: `3DIGIT` is grammar, not semantics.
    v(
      "status-code 999",
      Side::Response,
      b"HTTP/1.1 999 \r\n\r\n",
      Verdict::Accepts,
    ),
    // RFC 9110 §7.8: well-formed, and refused because the request this harness
    // opens made no offer for it to answer — NOT because of the mode. The
    // response-side driver is an unpermitted `Connection<Client, General>`
    // sending a plain GET, so what condemns the head is the indication that was
    // never made.
    v(
      "101 answering no offer",
      Side::Response,
      b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §4: the SP after the status-code is sent "even when the
    // reason-phrase is absent".
    v(
      "status-line without the mandatory SP",
      Side::Response,
      b"HTTP/1.1 200\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "two-digit status-code",
      Side::Response,
      b"HTTP/1.1 20 OK\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "four-digit status-code",
      Side::Response,
      b"HTTP/1.1 2000 OK\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "double SP in the status-line",
      Side::Response,
      b"HTTP/1.1  200 OK\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9110 §5.5: a CTL is not `obs-text`, in a reason-phrase either.
    v(
      "CTL in the reason-phrase",
      Side::Response,
      b"HTTP/1.1 200 Bad\x00Reason\r\n\r\n",
      Verdict::Rejects,
    ),
    // RFC 9112 §6.1: a 1.0 response carrying Transfer-Encoding has faulty
    // framing "even if a Content-Length is present".
    v(
      "HTTP/1.0 response with Transfer-Encoding",
      Side::Response,
      b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "bare LF in a response head",
      Side::Response,
      b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "obs-fold in a response head",
      Side::Response,
      b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-A: a\r\n b\r\n\r\n",
      Verdict::Rejects,
    ),
    v(
      "SP before the field colon in a response",
      Side::Response,
      b"HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n",
      Verdict::Rejects,
    ),
  ];

  // The two cap vectors, built from the constants they are about (RFC 9110
  // §5.4, answered per RFC 6585 §5).
  corpus.push(Vector {
    name: "field count at the cap",
    side: Side::Request,
    head: Cow::Owned(head_with_fields(MAX_HEADERS - 1)),
    ours: Verdict::Accepts,
  });
  corpus.push(Vector {
    name: "field count past the cap",
    side: Side::Request,
    head: Cow::Owned(head_with_fields(MAX_HEADERS)),
    ours: Verdict::Rejects,
  });
  corpus.push(Vector {
    name: "head past the byte cap",
    side: Side::Request,
    head: Cow::Owned(over_the_byte_cap()),
    ours: Verdict::Rejects,
  });
  corpus
}

/// Divergences where `httparse` accepts a head this core refuses, each with the
/// rule that justifies the refusal.
///
/// Nothing is waved through as "semantics": `httparse` is a head PARSER and
/// implements no message-level rule at all, so a message rule this core enforces
/// shows up here as surely as a grammar rule does — and each entry names the
/// MUST or SHOULD it is enforcing.
///
/// Only ONE entry here is a leniency `httparse` takes on purpose: the bare-LF
/// line terminator of RFC 9112 §2.2, which is a MAY. Everything else is a rule
/// `httparse` does not implement — which is the honest reading of a head parser
/// used as an oracle, and the reason each entry cites a section rather than a
/// preference.
const KNOWN_STRICTER: &[(&str, &str)] = &[
  // ---- RFC 9112 §2.2: the line terminator, and the MAY not taken. ----
  (
    "bare LF as a terminator",
    "RFC 9112 §2.2: a recipient MAY recognize a single LF as a line terminator and ignore any \
     preceding CR. The MAY is not taken — §11.2's whole mechanism is two recipients ending a line \
     in different places, and a bare LF is how a smuggled request-line is hidden inside a field \
     value that one hop reads as one line and the next reads as two.",
  ),
  (
    "bare LF between field lines",
    "RFC 9112 §2.2, the same MAY inside the field section.",
  ),
  (
    "bare LF in a response head",
    "RFC 9112 §2.2, the same MAY on the response side, where the split it enables is §11.1 \
     response splitting rather than §11.2 smuggling.",
  ),
  // ---- Bounded work: rules RFC 9110 §5.4 leaves to the recipient. ----
  (
    "leading empty lines past the bound",
    "RFC 9112 §2.2 makes ignoring empty lines before a request-line a SHOULD for \"at least one\", \
     and RFC 9110 §5.4 leaves every recipient allowance bounded: an unbounded skip is a \
     keep-alive channel for a peer that never sends a request. This core takes four \
     (MAX_LEADING_EMPTY_LINES); httparse skips them without a bound.",
  ),
  (
    "field count past the cap",
    "RFC 9110 §5.4: a server that receives more fields than it wishes to process MUST respond \
     with a 4xx — RFC 6585 §5's 431 here. MAX_HEADERS is 64; httparse's only limit is the slot \
     array its caller provides, and this harness provides more than the cap.",
  ),
  (
    "head past the byte cap",
    "RFC 9110 §5.4 again, for the block rather than the count: MAX_HEAD_BYTES is 16 KiB, and a \
     head that has not terminated inside it cannot be completed by any continuation. httparse \
     has no size limit of its own.",
  ),
  // ---- RFC 9112 §3.2: the request-target, and the Host that resolves it. ----
  (
    "fragment in the request-target",
    "RFC 9112 §3.2.1 spells origin-form as absolute-path [ \"?\" query ], and RFC 3986 §3.5 makes \
     a fragment no part of a URI reference sent to a server — RFC 9110 §7.1 requires a client to \
     exclude it. A `#` accepted here is a byte the next hop may re-split the target on.",
  ),
  (
    "HTTP/1.1 request without Host",
    "RFC 9112 §3.2: a server MUST respond 400 to any HTTP/1.1 request message that lacks a Host \
     header field. httparse parses heads and resolves no target, so it has no such rule.",
  ),
  (
    "repeated Host",
    "RFC 9112 §3.2, the same sentence: 400 to any request message that contains more than one \
     Host header field line. Two authorities are two different requests to two different hops.",
  ),
  (
    "invalid Host value",
    "RFC 9112 §3.2, the same sentence again: 400 to a Host header field with an invalid field \
     value. `a b` is not RFC 3986 §3.2.2's uri-host [ \":\" port ].",
  ),
  (
    "CONNECT without an authority-form target",
    "RFC 9112 §3.2.3: the authority-form of request-target is only used for CONNECT requests, and \
     RFC 9110 §9.3.6 makes sending it in that form a client MUST.",
  ),
  (
    "asterisk-form from a non-OPTIONS method",
    "RFC 9112 §3.2.4: the asterisk-form is only used for a server-wide OPTIONS request.",
  ),
  // ---- RFC 9112 §6: the framing decision, which is what §11.2 attacks. ----
  (
    "Transfer-Encoding beside Content-Length",
    "RFC 9112 §6.3 item 3: such a message ought to be handled as an error, and §6.1 makes closing \
     the connection afterwards a MUST — it is the smuggling primitive of §11.2 itself, since the \
     two fields tell two hops to end the message in two places.",
  ),
  (
    "disagreeing Content-Length lines",
    "RFC 9112 §6.3 item 5 with RFC 9110 §5.3 (repeated field lines are one comma-separated list): \
     values that disagree make the framing invalid and the recipient MUST treat that as an \
     unrecoverable error.",
  ),
  (
    "non-decimal Content-Length",
    "RFC 9110 §8.6 spells Content-Length as 1*DIGIT; RFC 9112 §6.3 item 5 makes a value the \
     recipient cannot read an unrecoverable framing error rather than something to guess at.",
  ),
  (
    "parameterized chunked",
    "RFC 9112 §7.1: the chunked coding defines no parameters and their presence SHOULD be treated \
     as an error, which leaves nothing framing the message — §6.3 item 4's 400.",
  ),
  (
    "chunked before another coding",
    "RFC 9112 §6.3 item 4: with chunked not the final encoding the body length cannot be \
     determined reliably, and the server MUST respond 400 and close.",
  ),
  (
    "undecodable coding under a final chunked",
    "RFC 9112 §6.1: a server that receives a transfer coding it does not understand SHOULD respond \
     501. The body is still delimited (item 4 ¶1), which is exactly why this one is a 501 and the \
     entry above is a 400.",
  ),
  (
    "HTTP/1.0 request with Transfer-Encoding",
    "RFC 9112 §6.1: Transfer-Encoding was added in HTTP/1.1, and an implementation advertising \
     only HTTP/1.0 support is assumed not to understand transfer-encoded content — so such a \
     message was likely forwarded by a hop that did not process the chunked coding, which is the \
     framing this core will not trust.",
  ),
  (
    "HTTP/1.0 response with Transfer-Encoding",
    "RFC 9112 §6.1, the response half: a server MUST NOT send a response containing \
     Transfer-Encoding unless the corresponding request indicates HTTP/1.1 or later, so one from \
     a 1.0 peer has faulty framing whatever else the head carries.",
  ),
  // ---- RFC 9112 §4: the status-line's mandatory separator. ----
  (
    "status-line without the mandatory SP",
    "RFC 9112 §4: a server MUST send the space that separates the status-code from the \
     reason-phrase \"even when the reason-phrase is absent\". §4's own leniency MAY — parsing on \
     whitespace-delimited word boundaries — is not taken here, because recipients that disagree \
     about where a status-line ends are the §11.1 response-splitting primitive.",
  ),
  // ---- Mode and indication rules: well-formed heads THIS driver may not act
  // on. ----
  (
    "CONNECT in General mode",
    "RFC 9110 §9.3.6: everything after a 2xx to CONNECT is opaque octets, so the framing this \
     core applies stops applying. Refused where it arrives rather than accepted and then \
     mis-framed — a MODE rule, not a grammar one: Connection<Server, Tunnel> reads this very \
     head.",
  ),
  (
    "101 answering no offer",
    "RFC 9110 §7.8: \"A server MUST NOT switch to a protocol that was not indicated by the client \
     in the corresponding request's Upgrade header field\", and the request this harness opens is \
     a plain GET on a connection the operator never permitted to offer — so it indicated none. \
     httparse parses the head and stops; which request it answers is context httparse does not \
     hold. NOT a mode rule, which is what this entry used to say: the same head switches a \
     Connection<Client, Tunnel>, and a permitted Connection<Client, General> whose request DID \
     offer takes it as Item::Switched.",
  ),
];

/// Divergences the other way: heads this core accepts and `httparse` does not.
///
/// A short list by construction — the permissiveness assertion is what keeps it
/// short — and every entry has to show that the RFC allows the acceptance, since
/// this is the direction RFC 9112 §11.2 is about.
const KNOWN_LOOSER: &[(&str, &str)] = &[(
  "HTTP/1.7 minor version",
  "RFC 9110 §6.2 (Control Data): \"A recipient that receives a message with a major version number \
   that it implements and a minor version number higher than what it implements SHOULD process the \
   message as if it were in the highest minor version within that major version to which the \
   recipient is conformant\", and \"a recipient can assume that a message with a higher minor \
   version ... is sufficiently backwards-compatible to be safely processed by any implementation \
   of the same major version\". So `HTTP/1.7` is processed as 1.1 rather than refused, and the \
   acceptance is the SHOULD rather than a leniency. (Pinpointed to §6.2 deliberately, because the \
   obvious trail does not end there: RFC 9112 §2.3 carries only the HTTP-version grammar and \
   points at RFC 9110 §2.5 for \"the semantics of HTTP version numbers\", and §2.5 defines what \
   the two digits MEAN — the sender's conformance — without stating any rule about what a \
   recipient does with a higher minor. That rule is §6.2's, where both sentences quoted above are \
   the only occurrences in RFC 9110.) A MAJOR version this core does not speak is the other branch \
   — RFC 9110 §15.6.6's 505 — and `HTTP/2.0` in this corpus is refused exactly so. httparse \
   compares the version field against the two literals `HTTP/1.0` and `HTTP/1.1`, which is an \
   implementation limit rather than a stricter reading of §6.2. It is not a boundary divergence \
   either, which is what RFC 9112 §11.2 is about: the version chooses the persistence default (RFC \
   9112 §9.3) and whether a Transfer-Encoding is honoured (RFC 9112 §6.1 — spelled out because \
   this entry cites RFC 9110 §6.2 above it), and a recipient that REFUSES the message forwards \
   nothing for a second recipient to frame differently.",
)];

/// Runs OUR pipeline over `head`, through the public API alone.
fn ours(side: Side, head: &[u8]) -> Verdict {
  match side {
    Side::Request => {
      let mut connection = Connection::<Server, General>::new();
      let mut items = connection.handle(head);
      verdict_of(items.next())
    }
    Side::Response => {
      let mut connection = Connection::<Client, General>::new();
      let mut out = [0u8; 64];
      connection
        .open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
        .expect("a bodiless GET opens the exchange a response answers");
      let mut items = connection.handle(head);
      verdict_of(items.next())
    }
  }
}

/// Classifies what the item pump answered. Only a HEAD is acceptance: a body
/// item cannot be the first thing out of a fresh connection, and `Ok(None)` is
/// the need-more answer a partial head produces.
fn verdict_of(first: Result<Option<Item<'_>>, http1_proto::Error>) -> Verdict {
  match first {
    Ok(Some(Item::Head { .. })) => Verdict::Accepts,
    Ok(Some(_)) | Ok(None) => Verdict::NeedsMore,
    Err(_) => Verdict::Rejects,
  }
}

/// How far OUR pipeline says the head ran, for a head it accepts.
///
/// `Items::consumed` after the head item is the byte just past the block: the
/// pump counts a head's bytes in the same call that yields it, and nothing of
/// the body has been claimed yet.
fn our_head_end(side: Side, head: &[u8]) -> Option<usize> {
  /// The one answer both arms give: the head's extent, or nothing if this core
  /// did not accept the head at all.
  fn end_of(first: Result<Option<Item<'_>>, http1_proto::Error>, consumed: usize) -> Option<usize> {
    matches!(first, Ok(Some(Item::Head { .. }))).then_some(consumed)
  }
  match side {
    Side::Request => {
      let mut connection = Connection::<Server, General>::new();
      let mut items = connection.handle(head);
      let first = items.next();
      end_of(first, items.consumed())
    }
    Side::Response => {
      let mut connection = Connection::<Client, General>::new();
      let mut out = [0u8; 64];
      connection
        .open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
        .expect("a bodiless GET opens the exchange a response answers");
      let mut items = connection.handle(head);
      let first = items.next();
      end_of(first, items.consumed())
    }
  }
}

/// Where `httparse` says the head ended, for a head it accepts.
fn their_head_end(side: Side, head: &[u8]) -> Option<usize> {
  let mut slots = [httparse::EMPTY_HEADER; SLOTS];
  let parsed = match side {
    Side::Request => httparse::Request::new(&mut slots).parse(head),
    Side::Response => httparse::Response::new(&mut slots).parse(head),
  };
  match parsed {
    Ok(httparse::Status::Complete(at)) => Some(at),
    _ => None,
  }
}

/// Vectors where the two parsers ACCEPT the same head but disagree about where
/// it ended, each with the rule that justifies the divergence.
///
/// Empty, and that is the RESULT rather than an omission: over the whole
/// both-accept corpus the two implementations agree byte for byte on the head's
/// extent. An entry here would be a real §11.2 primitive — see
/// [`the_two_parsers_agree_where_a_head_ends`] — so it needs a citation like
/// every other adjudicated divergence in this file.
const KNOWN_DIFFERENT_EXTENT: &[(&str, &str)] = &[];

/// Runs `httparse` over the same bytes.
fn theirs(name: &str, side: Side, head: &[u8]) -> Verdict {
  let mut slots = [httparse::EMPTY_HEADER; SLOTS];
  let parsed = match side {
    Side::Request => httparse::Request::new(&mut slots).parse(head),
    Side::Response => httparse::Response::new(&mut slots).parse(head),
  };
  match parsed {
    Ok(httparse::Status::Complete(_)) => Verdict::Accepts,
    Ok(httparse::Status::Partial) => Verdict::NeedsMore,
    // Not a verdict about the bytes: the harness gave httparse fewer slots than
    // the vector needs, and the comparison would be measuring the harness.
    Err(httparse::Error::TooManyHeaders) => {
      panic!("{name}: httparse ran out of the {SLOTS} header slots the harness gave it")
    }
    Err(_) => Verdict::Rejects,
  }
}

/// The justification an allowlist records for `name`, if it has one.
fn allowance<'a>(list: &[(&str, &'a str)], name: &str) -> Option<&'a str> {
  let why = list
    .iter()
    .find(|(entry, _)| *entry == name)
    .map(|&(_, why)| why)?;
  assert!(!why.trim().is_empty(), "{name}: allowlisted with no reason");
  Some(why)
}

// The table is a SPECIFICATION rather than a recording: what this core does with
// each vector is pinned here, so a behaviour change fails with the vector named
// instead of quietly turning into an allowlist entry in the differential below.
#[test]
fn the_corpus_pins_our_own_verdicts() {
  for vector in corpus() {
    assert_eq!(
      ours(vector.side, &vector.head),
      vector.ours,
      "{}: this core no longer does what the corpus says",
      vector.name
    );
  }
}

// RFC 9112 §11.2: the direction that matters. A head this core accepts and
// another recipient refuses is a message the two disagree about, and a
// disagreement is what a smuggled request is made of — so acceptance here has to
// be matched by acceptance in an independently written parser, or be adjudicated
// as a divergence the RFC allows.
#[test]
fn we_are_never_more_permissive_than_httparse() {
  for vector in corpus() {
    let ours = ours(vector.side, &vector.head);
    let theirs = theirs(vector.name, vector.side, &vector.head);
    if ours != Verdict::Accepts || theirs == Verdict::Accepts {
      continue;
    }
    assert!(
      allowance(KNOWN_LOOSER, vector.name).is_some(),
      "{}: this core accepted a head httparse answered {theirs:?} — either the acceptance is \
       wrong, or it belongs in KNOWN_LOOSER with the rule that allows it",
      vector.name
    );
  }
}

// The reverse direction, adjudicated rather than ignored: this core refusing
// what httparse accepts is not a smuggling risk, but an UNEXPLAINED refusal is a
// bug waiting to be shipped — so each one names the rule it enforces.
#[test]
fn every_stricter_refusal_is_justified() {
  for vector in corpus() {
    let ours = ours(vector.side, &vector.head);
    let theirs = theirs(vector.name, vector.side, &vector.head);
    if theirs != Verdict::Accepts || ours == Verdict::Accepts {
      continue;
    }
    assert!(
      allowance(KNOWN_STRICTER, vector.name).is_some(),
      "{}: this core answered {ours:?} to a head httparse accepted, with no entry in \
       KNOWN_STRICTER saying which rule requires that",
      vector.name
    );
  }
}

// A stale allowance is how a real regression gets a standing exemption: every
// entry has to name a corpus vector AND still diverge in the direction it claims.
#[test]
fn the_allowlists_carry_no_stale_entries() {
  let corpus = corpus();
  let named = |name: &str| corpus.iter().find(|vector| vector.name == name);

  for &(name, _) in KNOWN_STRICTER {
    let Some(vector) = named(name) else {
      panic!("KNOWN_STRICTER names {name}, which is not in the corpus");
    };
    let ours = ours(vector.side, &vector.head);
    let theirs = theirs(name, vector.side, &vector.head);
    assert!(
      theirs == Verdict::Accepts && ours != Verdict::Accepts,
      "{name}: KNOWN_STRICTER excuses a divergence that is no longer there \
       (ours {ours:?}, httparse {theirs:?})"
    );
  }
  for &(name, _) in KNOWN_LOOSER {
    let Some(vector) = named(name) else {
      panic!("KNOWN_LOOSER names {name}, which is not in the corpus");
    };
    let ours = ours(vector.side, &vector.head);
    let theirs = theirs(name, vector.side, &vector.head);
    assert!(
      ours == Verdict::Accepts && theirs != Verdict::Accepts,
      "{name}: KNOWN_LOOSER excuses a divergence that is no longer there \
       (ours {ours:?}, httparse {theirs:?})"
    );
  }
}

// The corpus's own health check: names are unique (the allowlists are keyed by
// them), both sides and both verdicts are represented, and the malformed half is
// not a token gesture.
#[test]
fn the_corpus_is_what_it_claims_to_be() {
  let corpus = corpus();
  let mut names: Vec<&str> = corpus.iter().map(|vector| vector.name).collect();
  names.sort_unstable();
  let total = names.len();
  names.dedup();
  assert_eq!(names.len(), total, "two corpus vectors share a name");

  let count = |side, ours| {
    corpus
      .iter()
      .filter(|vector| vector.side == side && vector.ours == ours)
      .count()
  };
  // Floors at the shipped count less 5%, rather than at a round number far
  // under it: a floor far under the real corpus cannot notice vectors being
  // deleted, which is the only thing a floor is for. Slack enough that adding
  // vectors never requires touching them, tight enough that removing a handful
  // does.
  assert!(
    count(Side::Request, Verdict::Accepts) >= 18,
    "request accept vectors: {}",
    count(Side::Request, Verdict::Accepts)
  );
  assert!(
    count(Side::Request, Verdict::Rejects) >= 36,
    "request reject vectors: {}",
    count(Side::Request, Verdict::Rejects)
  );
  assert!(
    count(Side::Response, Verdict::Accepts) >= 6,
    "response accept vectors: {}",
    count(Side::Response, Verdict::Accepts)
  );
  assert!(
    count(Side::Response, Verdict::Rejects) >= 9,
    "response reject vectors: {}",
    count(Side::Response, Verdict::Rejects)
  );
  // Nothing here is truncated: an accepted vector ends in the CRLFCRLF that
  // closes a head, which is what makes `NeedsMore` a divergence to adjudicate
  // rather than the expected answer to a short read.
  for vector in &corpus {
    assert!(
      vector.head.ends_with(b"\r\n\r\n") || vector.ours == Verdict::Rejects,
      "{}: an accepted vector must be a complete head",
      vector.name
    );
  }
}

// The oracle's own regression test: an oracle that answered the same thing for
// every input would pass every assertion above. These are the three answers each
// half has to be able to give, on inputs whose classification is not in doubt.
#[test]
fn the_oracle_catches_a_lie() {
  const GOOD: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
  const BAD: &[u8] = b"GET /a HTTP/1.1\r\nHost : h\r\n\r\n";
  const CUT: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n";

  assert_eq!(ours(Side::Request, GOOD), Verdict::Accepts);
  assert_eq!(ours(Side::Request, BAD), Verdict::Rejects);
  assert_eq!(ours(Side::Request, CUT), Verdict::NeedsMore);
  assert_eq!(theirs("good", Side::Request, GOOD), Verdict::Accepts);
  assert_eq!(theirs("bad", Side::Request, BAD), Verdict::Rejects);
  assert_eq!(theirs("cut", Side::Request, CUT), Verdict::NeedsMore);

  // And the response side reaches the response parsers, not the request ones: a
  // status-line is not a request-line to either of them.
  assert_eq!(
    ours(
      Side::Response,
      b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    ),
    Verdict::Accepts
  );
  assert_eq!(
    ours(Side::Request, b"HTTP/1.1 200 OK\r\n\r\n"),
    Verdict::Rejects
  );
  assert_eq!(
    theirs(
      "status as request",
      Side::Request,
      b"HTTP/1.1 200 OK\r\n\r\n"
    ),
    Verdict::Rejects
  );
}

// The §11.2 primitive itself, and the one thing acceptance alone cannot see: two
// recipients that both ACCEPT a head but disagree about where it ENDS have
// already disagreed about where the body begins, which is the whole of request
// smuggling. `httparse` reports that extent as `Status::Complete(n)`; this core
// reports it as `Items::consumed` after the head item. Every vector both sides
// accept is checked for equality of the two.
//
// The verdict comparison above cannot state this: two parsers can agree that a
// head is well formed and still cut it in different places — an obs-fold one
// unfolds and the other terminates at, a bare CR one absorbs into a field value
// — so the extent is a second, independent question over the same corpus.
//
// A divergence is not automatically a fault (the two might differ over leading
// empty lines, which RFC 9112 §2.2 lets a recipient skip), but it IS the shape a
// smuggling chain is built out of, so it has to be adjudicated in
// `KNOWN_DIFFERENT_EXTENT` with its rule rather than tolerated. That list is
// empty today, and the test fails on a stale entry the same way the acceptance
// allowlists do.
#[test]
fn the_two_parsers_agree_where_a_head_ends() {
  let mut compared = 0usize;
  for vector in corpus() {
    let (Some(ours), Some(theirs)) = (
      our_head_end(vector.side, &vector.head),
      their_head_end(vector.side, &vector.head),
    ) else {
      continue; // not a both-accept vector; the verdict tests cover those.
    };
    compared = compared.saturating_add(1);
    match allowance(KNOWN_DIFFERENT_EXTENT, vector.name) {
      Some(why) => assert_ne!(
        ours, theirs,
        "{}: allowlisted as an extent divergence ({why}) but the two agree — \
         a stale allowance is how a real one gets a standing exemption",
        vector.name
      ),
      None => assert_eq!(
        ours, theirs,
        "{}: this core ends the head at {ours} and httparse at {theirs}. Two \
         recipients that disagree about where a head ends disagree about where \
         the body begins (RFC 9112 §11.2) — adjudicate it in \
         KNOWN_DIFFERENT_EXTENT with its rule, or fix the parser",
        vector.name
      ),
    }
  }
  // Non-vacuity: the comparison has to have RUN over a real share of the corpus,
  // or an agreement over the empty set would pass it.
  assert!(
    compared >= 20,
    "only {compared} vectors were compared for head extent"
  );
}
