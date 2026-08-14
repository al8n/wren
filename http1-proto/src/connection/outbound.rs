//! The General-mode send side: the calls a driver writes a message with, and
//! the half of the keep-alive gate they discharge.
//!
//! Encode into the CALLER's slice. Every call here takes an `out` and returns
//! how many of its bytes it wrote, so a message is framed without this core
//! owning a buffer to frame it in — the same no-alloc contract the receive side
//! keeps by lending the driver's own bytes back as items. What a heap tier would
//! add is a queue in front of these calls, not a different encoding path; see
//! the "Sending" section of the module doc in `crate::connection` for why PR1
//! ships the slice path on every tier.
//!
//! NOTHING MOVES UNTIL THE BYTES ARE WRITTEN. Each call validates the state, then
//! the arguments, then encodes — and only an encode that succeeded advances the
//! exchange. A short buffer or a refused element therefore leaves the connection
//! exactly where it was, and the caller retries with a bigger slice or a
//! corrected message; there is no half-sent head to unsend (RFC 9112 §2.1 makes
//! a message one thing, and §11.1 is what a partial one becomes).
//!
//! THE HEAD AND THE BODY MUST STATE THE SAME MESSAGE. A `BodyPlan` says what
//! this core is about to write; the framing fields in the caller's head are what
//! the peer will read. When those disagree the peer delimits the message
//! somewhere the sender did not — which is RFC 9112 §11.1 response splitting and
//! §11.2 request smuggling, self-inflicted rather than attacker-supplied — so
//! the combination is refused before a byte is encoded (`check_framing`). The
//! one place the two are allowed to differ is where §6.3 items 1-2 say the
//! recipient IGNORES the fields: a response to HEAD, a 304, a 2xx to CONNECT.
//!
//! WHAT THIS CORE READS, THIS CORE WRITES. A request that `validate_request`
//! would refuse is one this end has no business putting on a connection: the
//! peer's recipient — or an intermediary behind it — applies those same rules,
//! and a message refused there after being written here is at best a wasted
//! round trip and at worst two recipients disagreeing about what was asked
//! (§11.2). So the message-level request rules are enforced on the way out, out
//! of `crate::validate`'s own predicates rather than a second copy of them.
//!
//! Every rule `validate_request` applies, and where it lands on the send side:
//!
//! | RFC 9112 rule | Outbound |
//! |---|---|
//! | §3.2.3/§3.2.4 target-method pairing | ENFORCED — `validate::target_method_fault`, the receive side's own predicate, over `open_request`'s method and target arguments. Tunnel's `open_upgrade` enforces a STRICTER form rule (`SWITCH_TARGET_FORM`) and `open_connect` writes the pair by construction |
//! | §3.2 `Host` present on 1.1 | ENFORCED — [`requires_host`] over the `declared` walk, on all three request paths |
//! | §3.2 exactly one `Host` LINE | ENFORCED — same walk counts the lines |
//! | §3.2 `Host` value valid or empty | ENFORCED — same walk, through `validate::host_value_is_valid` over the OWS-trimmed value, which is what the recipient reads |
//! | §6.1 `Transfer-Encoding` on an HTTP/1.0 request | STRUCTURALLY IMPOSSIBLE — `head::encode` writes `HTTP/1.1` on every request this core sends (RFC 9112 §2.3 makes the version a sender's own) |
//! | §6.3 item 3 both framing fields | STRUCTURALLY IMPOSSIBLE — every [`BodyPlan`] arm of `check_framing` refuses the pair, under three different constants; there is no plan that admits both |
//! | §6.3 item 4 a `chunked` that frames nothing | ENFORCED, and more strictly than the receive side: only `Codings::Chunked` describes what this core writes, so `gzip, chunked` — which a recipient tolerates — is refused here |
//! | §6.1 a coding this core cannot decode | ENFORCED by the same check: a sender knows what it applied, and this core applies one coding |
//! | §6.3 items 5-6 `Content-Length` readable and agreed | ENFORCED, and by the SENDER rule: RFC 9110 §8.6 admits one field line with one `1*DIGIT` value, so item 5's identical-list exception — a recipient's excuse — is not reused here ([`LENGTH_IS_ONE_VALUE`]) |
//! | §6.3 item 7 no framing field means no body | ENFORCED — `BodyPlan::None` is what such a head means, and `CloseDelimited` is refused on a request |
//! | RFC 9110 §7.8/§10.1.1 HTTP/1.0 MUST-ignores | NOT APPLICABLE — receive-side readings of a peer's 1.0 message, and this core writes none |
//! | `head::scan`'s `MAX_HEAD_BYTES` / `MAX_HEADERS` | DELIBERATELY DELEGATED — those bound work a PEER can ask of us; an outbound head is bounded by the caller's own buffer, and refusing to write one a peer would accept would be a rule no RFC has (`head::encode`'s "NO SIZE CAP") |
//! | Which authority the `Host` names | DELIBERATELY DELEGATED — only the caller holds the target URI ([`REQUEST_NEEDS_HOST`]) |
//!
//! What is left after that table is which fields a message ought to carry, and
//! that is not this module's: `crate::head::encode` checks the grammar of each
//! element, and on the way out a caller's head is its own — apart from the
//! framing agreement above, the request rules in the table, and the single
//! `Connection: close` that `send_error_response` is required to state.

use crate::{
  body::encode::{CHUNK_TERMINATOR, encode_chunk_header, encode_last_chunk_and_trailers},
  connection::{
    CONNECT, Client, Connection, Exchange, FAILED, General, Lifecycle, Mode, RecvState, Role,
    SWITCHING_PROTOCOLS, SendBody, SendState, Server, discharge_expect, mint, signal_close,
    tunnel::CONTINUE,
  },
  error::Error,
  event::Event,
  grammar::{
    Expectations, ListShape, eq_ignore_ascii, is_protocol_list, is_sender_token_list,
    sender_list_shape, token_list_contains, trim_ows,
  },
  head::{
    Headers, Target, Version,
    encode::{FieldDigest, encode_request_head, encode_status_head},
  },
  validate::{CodingList, Codings, host_value_is_valid, parse_content_length, target_method_fault},
};

/// What the caller intends to send for a message body.
///
/// The framing decision (RFC 9112 §6.3) stated by the sender rather than read
/// off a head: it is what this core counts a counted body down against, and what
/// makes each [`send_body`](Connection::send_body) a chunk. The head must
/// ANNOUNCE the same thing — see the module doc — and a plan that its head
/// contradicts is refused.
///
/// Three of the four plans are self-delimiting: the peer frames the message
/// without the connection ending, so another exchange may follow it. The fourth,
/// [`CloseDelimited`](Self::CloseDelimited), is item 8's — it is framed BY the
/// close, so choosing it is also a statement about the connection's life, and
/// this core takes that statement rather than leaving it to the caller.
///
/// Deliberately NOT `#[non_exhaustive]`, unlike [`Item`](crate::Item) and the
/// tunnel outcomes: §6.3's decision list closes the ways an HTTP/1.1 message can
/// be delimited, and these four are all of them a SENDER can choose between. A
/// fifth would be a change to HTTP/1.1 rather than to this crate, so a consumer
/// may match them exhaustively.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BodyPlan {
  /// No body at all: the message ends at the empty line that closed its head
  /// (§6.3 item 7 for a request, item 1 for a bodiless status or a response to
  /// HEAD, and a `Content-Length: 0` response otherwise).
  None,
  /// Exactly this many octets follow the head (§6.3 item 6). The head must
  /// announce the same number, and [`send_body`](Connection::send_body) counts
  /// them down.
  ContentLength(u64),
  /// The chunked transfer coding delimits the body (§6.3 item 4, §7.1): each
  /// [`send_body`](Connection::send_body) is one chunk, and
  /// [`finish_body`](Connection::finish_body) writes the last chunk and the
  /// §7.1.2 trailer section.
  Chunked,
  /// The body ends when the CONNECTION does (§6.3 item 8): the head declares
  /// NEITHER framing field, [`send_body`](Connection::send_body) writes the
  /// octets raw, and the connection closes behind the message.
  ///
  /// RESPONSES ONLY. §6.3's note is explicit that "request messages are never
  /// close-delimited … with the absence of both implying the request ends
  /// immediately after the header section", so
  /// [`open_request`](Connection::open_request) refuses this plan — a client
  /// that wants no body is asking for [`None`](Self::None).
  ///
  /// It FORCES the close, which is why it is not merely a fourth framing. §9.3:
  /// "in order to remain persistent, all messages on a connection need to have a
  /// self-defined message length (i.e., one not defined by closure of the
  /// connection)" — so a connection that re-armed behind such a message would
  /// leave the peer with no way to tell where it ended. The close is signalled
  /// when the head goes out, so a driver knows before it writes an octet, and
  /// taken when [`finish_body`](Connection::finish_body) ends the message.
  ///
  /// A last resort rather than a default: §6.3 warns that "there is no way to
  /// distinguish a successfully completed, close-delimited response message from
  /// a partially received message interrupted by network failure", so a sender
  /// "SHOULD generate encoding or length-delimited messages whenever possible".
  /// What it is FOR is the peer that has no other option — "the close-delimiting
  /// feature exists primarily for backwards compatibility with HTTP/1.0", which
  /// is exactly the peer §6.1 forbids sending a `Transfer-Encoding` to.
  CloseDelimited,
}

/// The `trailers` argument for a chunked body that ends with no trailer section
/// — RFC 9112 §7.1's ordinary `last-chunk CRLF`.
///
/// [`finish_body`](Connection::finish_body) is generic over the caller's
/// [`Headers`] supplier, so a bare `None` leaves that type for the compiler to
/// guess and it cannot. This names one:
///
/// ```text
/// connection.finish_body(NO_TRAILERS, &mut out)?;
/// ```
pub const NO_TRAILERS: Option<&'static [(&'static str, &'static [u8])]> = None;

/// The empty trailer section a `None` stands for, once
/// [`finish_body`](Connection::finish_body) has decided there is one to write.
const NO_TRAILER_FIELDS: &[(&str, &[u8])] = &[];

/// RFC 9112 §6.3 item 1: the one method whose response is bodiless whatever its
/// head says.
const HEAD: &str = "HEAD";

/// RFC 9110 §7.6.1 `Connection`, and RFC 9112 §9.6's `close` option.
const CONNECTION: &str = "Connection";

/// RFC 9110 §7.2 `Host`, which RFC 9112 §3.2 makes a client MUST on every
/// HTTP/1.1 request.
const HOST: &str = "Host";

/// RFC 9110 §7.8 `Upgrade`, and the `upgrade` connection option §7.8 requires
/// beside it. Reduced here rather than in `connection::tunnel` so that the
/// handshake decisions come out of the SAME walk as the framing ones — see
/// [`Declared`].
const UPGRADE: &str = "Upgrade";
/// RFC 9110 §10.1.1.
const EXPECT: &str = "Expect";

/// That option, as a token to look for in a caller's `Connection` list.
const UPGRADE_OPTION: &str = "upgrade";

/// The value of that option, as this core writes it.
const CLOSE: &[u8] = b"close";

/// The same option as a token to look for in a caller's list (RFC 9112 §9.6).
const CLOSE_OPTION: &str = "close";

/// RFC 9110 §8.6.
const CONTENT_LENGTH: &str = "content-length";

/// RFC 9112 §6.1.
const TRANSFER_ENCODING: &str = "transfer-encoding";

/// The connection has drained (RFC 9112 §9.6): keep-alive is over and the
/// exchange that was in flight, if any, is through.
const DRAINED: &str = "connection is draining";

/// A client holds ONE exchange of its own in flight (RFC 9112 §9.3.2 — this end
/// does not pipeline its requests), so a second open before the first is
/// answered has no exchange to belong to.
const ONE_REQUEST_AT_A_TIME: &str = "a request is already outstanding";

/// RFC 9112 §9.2: an exchange completed and the offer that completed it has not
/// been read back to its end, so the connection may still be holding bytes that
/// arrived BEFORE this request would be written.
///
/// Opening over them would have them parsed as this request's response, which is
/// exactly what §9.2 forbids — "a client MUST NOT consider [data received on a
/// connection with no outstanding request] to be a valid response". The idle path
/// already diagnoses such bytes; the barrier is what keeps them ON that path
/// instead of letting a new exchange adopt them.
///
/// The cure is one more pump pass: offer the rest of the previous read and pull
/// to `Ok(None)`. Only the pump can lift this, because only the pump sees the
/// buffer — the same rule the EOF path is built on.
pub(super) const UNREAD_TAIL: &str = "the previous offer has not been read back";

/// The read side has ended (a reported EOF), so no response to a new request
/// could ever arrive.
///
/// Named apart from [`UNREAD_TAIL`] on purpose: the two ask the driver for
/// completely different things. That one says "finish reading first"; this one
/// says the connection can never answer, and the driver should stop.
pub(super) const READ_SIDE_ENDED: &str = "the connection can no longer receive a response";

/// RFC 9112 §2.2 with §9.2: a lone CR at an idle client's cursor is undecided
/// until its next byte arrives, and it sits in FRONT of whatever the peer sends
/// next. Opening a request over it would put a bare CR at the head of the
/// response parse; the driver resolves it first (`wants_read()` says so).
const UNDECIDED_CR: &str = "an undecided CR is pending at the read cursor";

/// Nothing is owed in this direction: a server with no request parsed, or one
/// whose final response has already gone out.
const NO_RESPONSE_OWED: &str = "no response is owed on this connection";

/// The single error response is owed only by a connection that failed, and only
/// once.
const NO_ERROR_OWED: &str = "no error response is owed on this connection";

/// RFC 9110 §15.2: a 1xx is informational and the exchange goes on, so it is
/// never the response that ends one.
const INTERIM_NOT_FINAL: &str = "a 1xx response is interim, not final";

/// The single owed answer is the answer to a message this connection COULD NOT
/// FRAME, so a phase whose whole meaning is "a rejection is owed" has no success
/// class to state.
///
/// The same rule the Tunnel side applies at [`reject`](Connection::reject)'s
/// `RejectionOwed` arm, and it is stated identically in both places on purpose:
/// one connection cannot both have latched on the wire and be answering 2xx to
/// what it latched on. A 3xx stays legal — a redirect IS a rejection of the
/// request as put — and so does any other non-1xx, non-2xx status, since RFC
/// 9112 §4 makes the code a bare three-digit and this core does not police
/// semantics it was not given.
///
/// `pub(super)` so the sibling test module can pin WHICH refusal a code earns
/// rather than merely that one happened.
pub(super) const NO_SUCCESS_TO_STATE: &str = "an error response states no 2xx";

/// RFC 9110 §15.2.2: a 101 ends HTTP framing on the connection, which General
/// mode has nothing to replace it with.
const SWITCHING_NEEDS_TUNNEL: &str = "101 requires a Tunnel-mode connection";

/// RFC 9110 §9.3.6: the same, for the request that would provoke one.
/// Caller-side here, unlike the wire-side refusal the inbound path makes of a
/// CONNECT it RECEIVES.
const CONNECT_NEEDS_TUNNEL: &str = "CONNECT requires a Tunnel-mode connection";

/// RFC 9110 §7.8's other takeover, refused for exactly the reason CONNECT is.
///
/// A request stating both halves of an upgrade offer invites the `101` that RFC
/// 9110 §15.2.2 makes the end of HTTP framing on the connection — and General
/// mode's own receive path condemns every 101 it is handed, because it has
/// nothing to become. So a General connection that sent such an
/// offer would have opened an exchange its own continuation forbids: the best
/// case is a server that declines and answers ordinarily, the worst is one that
/// accepts and a connection this end then fails on the answer it asked for.
///
/// Refused before encoding, like CONNECT. What is NOT done is teaching General
/// mode to accept a 101 — the type-state split is the design, and
/// `Connection<_, Tunnel>` is where takeover lives.
pub(super) const UPGRADE_NEEDS_TUNNEL: &str = "an upgrade offer requires a Tunnel-mode connection";

/// RFC 9112 §3.2: "A client MUST send a Host header field in all HTTP/1.1
/// request messages." Unconditional, and every request this core writes states
/// `HTTP/1.1` — so the rule binds every outbound request path, General and
/// Tunnel (RFC 9110 §9.3.6's CONNECT included; §3.2.3 gives it an
/// authority-form target, not an exemption from §3.2).
///
/// PRESENCE is what THIS constant is about; §3.2's other two `Host` MUSTs are
/// [`ONE_HOST_LINE`] and [`HOST_NOT_AUTHORITY`], and [`requires_host`] applies
/// all three. §3.2 also requires an EMPTY `Host` when the target authority is
/// undefined, so an empty value satisfies presence and is not treated as
/// absence.
///
/// Which authority the value NAMES stays the caller's — only it holds the target
/// URI.
pub(super) const REQUEST_NEEDS_HOST: &str = "an HTTP/1.1 request states its Host";

/// RFC 9112 §3.2's second `Host` MUST, which is scoped to "any request message"
/// rather than to an HTTP/1.1 one: a server responds 400 to a request "that
/// contains more than one Host header field line".
///
/// Enforced on the way out for the reason the module doc gives: a second line is
/// a second authority the recipient may route on, and the two need not agree —
/// which is §11.2's primitive with the sender on this side of it.
pub(super) const ONE_HOST_LINE: &str = "a request states exactly one Host field line";

/// §3.2's third: a `Host` "with an invalid field value" is the same 400, and the
/// same unqualified scope.
///
/// Checked against the value the RECIPIENT will read — OWS-trimmed, since
/// RFC 9110 §5.5 makes the whitespace no part of the value — through
/// `validate::host_value_is_valid`, the predicate the receive side applies to a
/// peer's. An EMPTY value passes: §3.2 requires exactly that when the target
/// URI's authority is undefined.
pub(super) const HOST_NOT_AUTHORITY: &str = "the Host field value is not an authority";

/// RFC 9112 §6.3 item 1: a response to HEAD, a 1xx, a 204, a 304, and a 2xx to
/// CONNECT are "always terminated by the first empty line after the header
/// fields" — so there is no body to plan.
const BODILESS_TAKES_NO_BODY: &str = "this status can carry no body";

/// RFC 9112 §6.1 and RFC 9110 §8.6 both spell this MUST NOT for a 1xx and a 204:
/// neither framing field belongs in a message that cannot be framed.
pub(super) const BODILESS_STATUS_FRAMING: &str = "a 1xx or 204 carries no framing field";

/// RFC 9112 §6.2 states it as an unconditional sender rule — "a sender MUST NOT
/// send a Content-Length header field in any message that contains a
/// Transfer-Encoding header field" — and §6.3 item 3 is what a recipient of one
/// does: a message carrying both fields is the smuggling primitive itself
/// (§11.2), and this core will not write one at ANY status, item 1's
/// recipient-ignores rule included.
///
/// `pub(super)` so the sibling test module can pin WHICH refusal a head earns
/// rather than merely that one happened.
pub(super) const BOTH_FRAMINGS: &str = "Content-Length and Transfer-Encoding disagree";

/// A `Transfer-Encoding` tells the peer to read the body as a transfer coding
/// this core is not about to write (RFC 9112 §6.3 item 4): the framing bytes it
/// would look for are payload, and the message never ends where it says.
pub(super) const TE_WITHOUT_CHUNKED: &str =
  "Transfer-Encoding announces a body the plan does not send";

/// The head announces a length this core is not about to write.
pub(super) const LENGTH_DISAGREES: &str = "Content-Length disagrees with the body plan";

/// RFC 9110 §5.6.1.1: "in any production that uses the list construct, a sender
/// MUST NOT generate empty list elements."
///
/// The sender-versus-recipient asymmetry, generalised to every list field this
/// reduction reads. A recipient MUST ignore empty elements (§5.6.1.2) and
/// this core does; that tolerance is about what it ACCEPTS and says nothing
/// about what it may emit. `Connection: ,close` and `Transfer-Encoding: ,chunked`
/// are lists this core reads and will not write.
pub(super) const SENDER_LIST_EMPTY_ELEMENT: &str = "a list field states no empty element";
/// Every field this core interprets is written in its own grammar — see
/// [`declared`].
pub(super) const FIELD_STATES_ITS_GRAMMAR: &str = "an interpreted field states its own grammar";
/// RFC 9110 §10.1.1: a `100-continue` expectation goes on a request that HAS
/// content.
pub(super) const CONTINUE_NEEDS_CONTENT: &str = "100-continue states a request with content";

/// RFC 9110 §8.6: `Content-Length = 1*DIGIT`. One field line, one decimal value,
/// and nothing else.
///
/// RFC 9112 §6.3 item 5's identical-list exception is a RECIPIENT rule — it
/// exists so a recipient handed `42, 42` by a broken intermediary can still frame
/// the message. A sender has no such excuse: §8.6's production admits exactly one
/// value, so this core writes one field line carrying one number and refuses
/// every other spelling, repeated lines included.
pub(super) const LENGTH_IS_ONE_VALUE: &str = "Content-Length is one line with one 1*DIGIT value";

/// A chunked body whose head does not say so is one the peer frames by RFC 9112
/// §6.3 item 8 instead — it would read the chunk framing as payload and never
/// find the message's end.
pub(super) const CHUNKED_UNANNOUNCED: &str = "a chunked body needs a Transfer-Encoding field";

/// The `Transfer-Encoding` is there but names something other than the one coding
/// this core applies (RFC 9112 §7.1 `chunked`, alone, final, and unparameterized)
/// — so the octets it announces are not the octets that will follow.
///
/// `pub(super)` so the sibling test module can pin WHICH refusal a list earns
/// rather than merely that one happened.
pub(super) const CHUNKED_DECLARATION: &str =
  "Transfer-Encoding does not declare a lone chunked coding";

/// RFC 9112 §6.3 item 8: a response with no framing field at all ends when the
/// connection does, which is not a message a connection that stays open can
/// send — [`BodyPlan::CloseDelimited`] is how one says that deliberately.
pub(super) const UNFRAMED_RESPONSE: &str = "a response with a body plan needs a framing field";

/// RFC 9112 §6.3 item 8 is the list's "otherwise": the ABSENCE of both framing
/// fields is what declares it, so either field beside a close-delimited body
/// would have the peer ending the message where this core is not.
///
/// `pub(super)` so the sibling test module can pin WHICH refusal a head earns
/// rather than merely that one happened.
pub(super) const CLOSE_DELIMITED_IS_UNFRAMED: &str =
  "a close-delimited body carries no framing field";

/// RFC 9112 §6.3's note under item 8: a request is never close-delimited,
/// because with neither framing field it ends at its head (item 7).
///
/// `pub(super)` for the same reason.
pub(super) const REQUEST_IS_NEVER_CLOSE_DELIMITED: &str = "a request is never close-delimited";

/// RFC 9112 §6.1: "A server MUST NOT send a response containing
/// Transfer-Encoding unless the corresponding request indicates HTTP/1.1 (or
/// later minor revisions)."
///
/// `pub(super)` for the same reason.
pub(super) const TE_NEEDS_HTTP_11: &str = "Transfer-Encoding requires an HTTP/1.1 request";

/// RFC 9110 §15.2: "Since HTTP/1.0 did not define any 1xx status codes, a server
/// MUST NOT send a 1xx response to an HTTP/1.0 client."
///
/// `pub(super)` for the same reason.
pub(super) const INTERIM_NEEDS_HTTP_11: &str = "a 1xx response requires an HTTP/1.1 request";

/// Nothing to write a body for: the head that would frame it has not gone out,
/// or it framed no body (`BodyPlan::None`).
pub(super) const NO_BODY_IN_FLIGHT: &str = "no message body is in flight";

/// The peer ended the exchange while this end was still writing its request
/// body, so RFC 9112 §9.6 released it from sending the rest ("cease sending")
/// and §9.5 makes the response it already gave the end of the exchange.
///
/// Distinct from [`NO_BODY_IN_FLIGHT`] on purpose: there was a body, and the
/// caller is not confused about its own state. What changed is on the wire, and
/// this says so rather than reporting a silent success or a state the caller
/// would have to guess the cause of.
pub(super) const EXCHANGE_ENDED_BY_PEER: &str =
  "the peer ended the exchange before this body was sent";

/// RFC 9112 §6.3 item 6: the body is exactly as long as the head said, so an
/// octet past the count belongs to the next message (§11.1).
pub(super) const OVER_SEND: &str = "body exceeds the declared Content-Length";

/// The same rule from the other end: a counted body that stops short leaves the
/// peer waiting for octets that never come, and item 6 makes it treat the
/// message as incomplete.
pub(super) const BODY_INCOMPLETE: &str = "body is shorter than the declared Content-Length";

/// RFC 9112 §7.1.2 gives the trailer section to the chunked coding: neither a
/// counted body nor a close-delimited one has a place to put one.
pub(super) const UNCHUNKED_HAS_NO_TRAILERS: &str = "only a chunked body carries trailers";

/// RFC 9110 §5.3: repeated field lines are ONE comma-separated list, so a
/// caller's `Connection` line and the `close` this path must send would be a
/// single field saying two things about the connection.
const CALLER_STATED_CONNECTION: &str = "send_error_response states Connection itself";

/// What [`Connection::send_interim`] tells a caller that asked it for a final
/// status instead.
const NOT_INTERIM: &str = "only a 1xx response is interim";

/// RFC 9112 §9.6 binds the `close` connection option to the response CARRYING
/// it: a sender "MUST initiate closure of the connection … after it sends the
/// response containing the close connection option". A 1xx is a response message
/// (RFC 9110 §15.2), so an interim that states `close` commits this end to
/// closing immediately — before the final response the exchange still owes.
///
/// That is not what this call is. `send_interim` is the informational path:
/// §15.2 makes an interim response one that does NOT end the exchange, and
/// §10.1.1 requires a final status to follow. A caller stating the option here
/// is asking for two contradictory things at once, and this core will not guess
/// which — it refuses before encoding rather than emitting a head and then
/// tearing the connection down under the response still owed.
///
/// A server that means to close says so on the FINAL response (`send_response`,
/// which takes the option and drains behind it) or calls
/// [`close`](Connection::close). Both are unchanged.
///
/// `pub(super)` so the Tunnel side states the identical rule with the identical
/// words — its `send_interim` is the same call for the same reason.
pub(super) const INTERIM_STATES_NO_CLOSE: &str = "an interim response states no Connection: close";

/// The send state a head with this plan leaves behind.
///
/// [`BodyPlan::None`] completes the send side at the head — the message IS the
/// head — while a plan with octets in it leaves the body owed until
/// [`finish_body`](Connection::finish_body) closes it. That difference is what
/// RFC 9112 §9.3.2's re-arm gate waits on.
const fn started(plan: BodyPlan) -> SendState {
  match plan {
    BodyPlan::None => SendState::Idle,
    BodyPlan::ContentLength(expected) => SendState::Sending(SendBody::Counted(expected)),
    BodyPlan::Chunked => SendState::Sending(SendBody::Chunked),
    BodyPlan::CloseDelimited => SendState::Sending(SendBody::ToClose),
  }
}

impl Connection<Client, General> {
  /// Encodes a request head into `out` and opens the exchange it belongs to,
  /// returning the bytes written.
  ///
  /// Callable only between exchanges: RFC 9112 §9.3.2 associates a response with
  /// its request BY ORDER, and this end keeps one request of its own outstanding
  /// (a queue of them is a storage decision the task that needs it makes), so a
  /// second open while one is in flight is [`Error::InvalidState`].
  ///
  /// So is one made while the connection may still be holding bytes from an
  /// earlier read. RFC 9112 §9.2 makes data that arrives with no request
  /// outstanding something a client "MUST NOT consider to be a valid response",
  /// and a request opened over such a tail would have exactly that data parsed as
  /// ITS response — bytes that arrived before it was written. Two refusals cover
  /// it, and they ask the driver for different things:
  ///
  /// - `UNREAD_TAIL` — an exchange completed and the offer that completed it
  ///   has not been read back to its end. Offer the rest and pull to `Ok(None)`;
  ///   the pump either reaches the boundary cleanly or diagnoses the tail. Only
  ///   the pump can lift this, because only the pump sees the buffer.
  /// - `UNDECIDED_CR` — the same situation narrowed to one byte: a lone CR
  ///   (§2.2) whose LF has not arrived. [`wants_read`](Connection::wants_read)
  ///   is already asking for the byte that settles it.
  ///
  /// And `READ_SIDE_ENDED` once an EOF has been reported: no response could
  /// ever arrive, so there is nothing to open.
  ///
  /// BOTH TAKEOVERS are REFUSED, because General mode has nothing to become and
  /// its own receive path says so: a `CONNECT` (RFC 9110
  /// §9.3.6 makes everything after the 2xx opaque octets) and a request stating
  /// both halves of a §7.8 upgrade offer (§15.2.2 makes the 101 that answers it
  /// the end of HTTP framing, and this mode condemns every 101 it reads). Either
  /// one would open an exchange this connection's own continuation forbids.
  /// Takeover lives in `Connection<Client, Tunnel>`. Both refusals are
  /// caller-side ([`Error::InvalidState`]) rather than protocol errors, because
  /// the request is this end's own.
  ///
  /// `body` must agree with the framing fields in `headers` — see the module
  /// doc. A request with neither framing field has NO body (§6.3 item 7 and the
  /// note under item 8: a request is never close-delimited), which is exactly
  /// [`BodyPlan::None`]; [`BodyPlan::CloseDelimited`] is therefore REFUSED here,
  /// since no server would read a request that way.
  ///
  /// `method` and `target` must PAIR, under RFC 9112 §3.2.3 and §3.2.4: the
  /// authority-form belongs to CONNECT (refused above for its own reason) and
  /// the asterisk-form to a server-wide OPTIONS, so `GET *` is
  /// [`Error::InvalidState`] rather than a request this core writes and its own
  /// server half then answers 400.
  ///
  /// `headers` must satisfy all three of §3.2's `Host` MUSTs — exactly one field
  /// line, whose value is a valid authority or EMPTY — or the call is
  /// [`Error::InvalidState`] and writes nothing. An empty value is the field
  /// §3.2 requires when the target authority is undefined, so it passes; the
  /// value is read OWS-trimmed, because that is what the recipient reads. What
  /// stays the caller's is which authority the value NAMES, since only it holds
  /// the target URI.
  ///
  /// Those are the receive side's own rules, asked with the receive side's own
  /// predicates: what this core reads, this core writes, and the module doc
  /// tabulates every `validate_request` rule against where it lands here.
  ///
  /// The head is then validated element by element (`crate::head::encode`): the
  /// method as a §9.1 token, the target against its own form's grammar, every
  /// field line against §5. Nothing is escaped or trimmed to fit, and a short
  /// `out` reports the exact size the whole head needs and writes nothing.
  pub fn open_request<H: Headers + ?Sized>(
    &mut self,
    method: &str,
    target: &Target<'_>,
    headers: &H,
    body: BodyPlan,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    self.sendable()?;
    // Between messages is the whole condition, stated as the three facts that
    // make it: nothing being received, nothing outstanding, nothing owed.
    if !matches!(self.recv, RecvState::Idle)
      || self.exchange.is_some()
      || !matches!(self.send, SendState::Idle)
    {
      return Err(Error::InvalidState(ONE_REQUEST_AT_A_TIME));
    }
    // The read side is gone: nothing this request asked for could come back.
    // Checked ahead of the rest because it is the terminal one — no amount of
    // reading or correcting makes this connection usable again.
    if self.read_closed {
      return Err(Error::InvalidState(READ_SIDE_ENDED));
    }
    if self.pending_cr {
      return Err(Error::InvalidState(UNDECIDED_CR));
    }
    // RFC 9112 §9.2's barrier. `pending_cr` above is the special case of it the
    // connection can name precisely; this is the general one.
    if self.tail_unresolved {
      return Err(Error::InvalidState(UNREAD_TAIL));
    }
    if method == CONNECT {
      return Err(Error::InvalidState(CONNECT_NEEDS_TUNNEL));
    }

    // RFC 9112 §3.2.3/§3.2.4, asked with the receive side's own predicate: a
    // `GET *` or an authority-form target under any other method is a request
    // this core's own server half answers 400, and writing one would spend the
    // round trip to be told so. CONNECT is diagnosed above, so what this catches
    // here is every OTHER method reaching for CONNECT's target form.
    if let Some(what) = target_method_fault(method, target) {
      return Err(Error::InvalidState(what));
    }
    let declared = declared(headers)?;
    // The same rule that refuses CONNECT above: an offer this connection cannot
    // see through is an exchange it must not open — General's own receive path
    // condemns the 101 that answers it.
    if declared.offers_a_protocol() {
      return Err(Error::InvalidState(UPGRADE_NEEDS_TUNNEL));
    }
    requires_host(&declared)?;
    continue_needs_content(&declared, !matches!(body, BodyPlan::None))?;
    check_framing(body, &declared, true)?;

    let written = encode_request_head(method, target, headers, declared.digest, out)?;
    // Committed: the head is in the caller's buffer, so the exchange it opened
    // exists from here on.
    if declared.close {
      signal_close(&mut self.lifecycle, &mut self.event, self.read_closed);
    }
    // A new request opens a new idle period, so the §9.2 stray-CRLF allowance
    // starts over: what it bounds is how long a peer may keep a connection with
    // NOTHING outstanding alive on empty lines alone.
    self.idle_crlfs = 0;
    self.exchange = Some(Exchange {
      id: mint(&mut self.next_exchange),
      // RFC 9112 §6.3 items 1-2, recorded now because the RESPONSE cannot be
      // read for them.
      method_head: method == HEAD,
      connect: false,
      // What `head::encode` just wrote: this core states RFC 9112 §2.3's
      // `HTTP/1.1` on every request it sends.
      version: Version::Http11,
    });
    self.send = started(body);
    Ok(written)
  }
}

impl Connection<Server, General> {
  /// Encodes an interim (1xx) response head into `out`, returning the bytes
  /// written.
  ///
  /// RFC 9110 §15.2 lets any number of them precede the final response, and none
  /// of them ends the exchange: the connection is left exactly where it was, so
  /// the final response is still owed afterwards. Callable only while a request
  /// is being answered — before its final response has gone out, since there is
  /// nothing informational to say about an exchange that is over.
  ///
  /// A `100 Continue` is what a request carrying `Expect: 100-continue` (RFC
  /// 9110 §10.1.1) asks for, and the ask reaches the driver as
  /// [`Item::ExpectContinue`](crate::Item::ExpectContinue). Whether to send one,
  /// to send a final status instead, or to say nothing is the driver's policy —
  /// §15.2.1 requires a client to parse an interim response it did not ask for,
  /// so this core does not make the expectation a precondition. What it does
  /// enforce is §6.1 and RFC 9110 §8.6 — a 1xx carries no framing field — and
  /// RFC 9112 §9.6: an interim may not state `Connection: close`, because the
  /// option binds to the response CARRYING it and this call is the one that does
  /// not end the exchange. See `INTERIM_STATES_NO_CLOSE`.
  ///
  /// An HTTP/1.0 request is answered with NO interim response at all: §15.2 is
  /// explicit that "since HTTP/1.0 did not define any 1xx status codes, a server
  /// MUST NOT send a 1xx response to an HTTP/1.0 client", so the call is
  /// [`Error::InvalidState`] whatever the code. Nothing in such a request can
  /// have asked for one either — §10.1.1 makes a server ignore its expectation,
  /// so no [`Item::ExpectContinue`](crate::Item::ExpectContinue) is ever raised
  /// for it.
  ///
  /// `101` is REFUSED: RFC 9110 §15.2.2 makes everything after it another
  /// protocol's, which a General connection cannot become. It lives
  /// in `Connection<Server, Tunnel>`.
  ///
  /// The reason-phrase is empty; RFC 9112 §4 makes the SP before it mandatory
  /// "even when the reason-phrase is absent", so the line reads
  /// `HTTP/1.1 100 CRLF`.
  pub fn send_interim<H: Headers + ?Sized>(
    &mut self,
    code: u16,
    headers: &H,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    self.sendable()?;
    let (Some(exchange), SendState::Owed) = (self.exchange, self.send) else {
      return Err(Error::InvalidState(NO_RESPONSE_OWED));
    };
    if code == SWITCHING_PROTOCOLS {
      return Err(Error::InvalidState(SWITCHING_NEEDS_TUNNEL));
    }
    // RFC 9110 §15.2: "Since HTTP/1.0 did not define any 1xx status codes, a
    // server MUST NOT send a 1xx response to an HTTP/1.0 client" — such a client
    // has no way to read the interim head as anything but the final response,
    // and would take the real one for the body of it.
    if matches!(exchange.version, Version::Http10) {
      return Err(Error::InvalidState(INTERIM_NEEDS_HTTP_11));
    }
    if !matches!(code, 100..=199) {
      return Err(Error::InvalidState(NOT_INTERIM));
    }
    let declared = declared(headers)?;
    if declared.transfer_encoding > 0 || declared.content_length_lines > 0 {
      return Err(Error::InvalidState(BODILESS_STATUS_FRAMING));
    }
    // Refused, not emitted-then-closed: see `INTERIM_STATES_NO_CLOSE`.
    if declared.close {
      return Err(Error::InvalidState(INTERIM_STATES_NO_CLOSE));
    }
    let written = encode_status_head(code, b"", headers, declared.digest, out)?;
    // Committed. Neither the exchange NOR the connection moves — an interim
    // response is a fact about a message still being answered, and the one field
    // that would have moved the connection is refused above — but a `100` is the
    // answer RFC 9110 §10.1.1's expectation was waiting for, so it stops being
    // owed HERE, whether or not the driver ever pulled the item that states it.
    if code == CONTINUE {
      discharge_expect(&mut self.recv);
    }
    Ok(written)
  }

  /// Encodes the final response head into `out` and starts the body `body`
  /// declares, returning the bytes written.
  ///
  /// The framing is decided by `body` AND by the request this answers, in RFC
  /// 9112 §6.3's order of precedence rather than by reading the head back:
  ///
  /// - A response to HEAD, a 204, a 304, and a 2xx to CONNECT are terminated by
  ///   the empty line that ends the head "regardless of the header fields
  ///   present in the message" (items 1-2), so `body` MUST be
  ///   [`BodyPlan::None`]. Their framing fields are the caller's to state, since
  ///   the recipient ignores them — a HEAD response may carry the
  ///   `Content-Length` of the body a GET would have received.
  /// - A 1xx is not a final response at all: it goes through
  ///   [`send_interim`](Self::send_interim), and `101` is refused outright.
  /// - Otherwise the head must announce what `body` will write: a
  ///   `Content-Length` equal to the plan's, or a `Transfer-Encoding` for a
  ///   chunked one, and never both (item 3). A response carrying neither field
  ///   is close-delimited (item 8), which a connection that stays open cannot
  ///   send — so [`BodyPlan::None`] on a status that CAN have a body needs
  ///   `Content-Length: 0`, and a caller that MEANS item 8 says so with
  ///   [`BodyPlan::CloseDelimited`], which ends the connection behind the
  ///   message.
  ///
  /// The version of the REQUEST decides one thing on top of that list. §6.1: "A
  /// server MUST NOT send a response containing Transfer-Encoding unless the
  /// corresponding request indicates HTTP/1.1 (or later minor revisions)" — so
  /// against an HTTP/1.0 request both [`BodyPlan::Chunked`] and any
  /// `Transfer-Encoding` in `headers` are [`Error::InvalidState`], whatever the
  /// status. Such a peer takes a counted body or a close-delimited one.
  ///
  /// Not callable from a failed connection: the one answer such a connection may
  /// still send is [`send_error_response`](Self::send_error_response)'s.
  ///
  /// A bodiless response completes the send side, which is the other half of the
  /// keep-alive re-arm gate (§9.3.2): with the request through as well, the
  /// connection re-arms here and the bytes of the next one become readable.
  pub fn send_response<H: Headers + ?Sized>(
    &mut self,
    code: u16,
    reason: &[u8],
    headers: &H,
    body: BodyPlan,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    self.sendable()?;
    let (Some(exchange), SendState::Owed) = (self.exchange, self.send) else {
      return Err(Error::InvalidState(NO_RESPONSE_OWED));
    };
    if code == SWITCHING_PROTOCOLS {
      return Err(Error::InvalidState(SWITCHING_NEEDS_TUNNEL));
    }
    if matches!(code, 100..=199) {
      return Err(Error::InvalidState(INTERIM_NOT_FINAL));
    }
    let declared = declared(headers)?;
    check_response_framing(code, body, &exchange, &declared)?;

    let written = encode_status_head(code, reason, headers, declared.digest, out)?;
    // Committed: the head is written, so the message it framed is under way.
    //
    // RFC 9110 §15.2 puts every informational response BEFORE the final one, so
    // an expectation still outstanding here can never be answered: the exchange
    // has had its answer. Cancelled rather than left, because a stale ask
    // surfaces as an `ExpectContinue` item behind a final response, and a driver
    // that acted on it would write a 1xx §15.2 forbids.
    discharge_expect(&mut self.recv);
    // RFC 9112 §9.6 next, so that a response which states `close` drains the
    // connection in this same call rather than re-arming it: a sender of the
    // option "MUST initiate a close of the connection after it sends the
    // response", and a driver that wrote the field means it.
    //
    // A close-delimited body says the same thing without a field: §6.3 item 8
    // makes the CLOSE the delimiter, so the message has no end until the
    // connection has one (§9.3 — a persistent connection needs messages with a
    // self-defined length). Announced HERE rather than at
    // [`finish_body`](Self::finish_body) so that a driver knows the connection
    // is ending before it writes the first body octet.
    if declared.close || matches!(body, BodyPlan::CloseDelimited) {
      signal_close(&mut self.lifecycle, &mut self.event, self.read_closed);
    }
    self.send = started(body);
    // A bodiless response is complete here, which may be the second of the two
    // directions §9.3.2 gates re-arm on.
    self.settle();
    Ok(written)
  }

  /// Encodes the ONE response a failed connection may still send — bodiless,
  /// carrying `Connection: close` — and forces the connection into draining,
  /// returning the bytes written.
  ///
  /// RFC 9112 §6.3 items 4-5 and §6.1 taken literally: a server that cannot
  /// frame what it received "MUST respond with a 400 (Bad Request) status code
  /// and then close the connection". Typically called with
  /// the latched error's
  /// [`suggested_status`](crate::Error::suggested_status), whose code is the one
  /// this core would advise for that violation.
  ///
  /// The `close` connection option (RFC 9110 §7.6.1, RFC 9112 §9.6) is
  /// INJECTED — a response that did not state it would leave the peer expecting
  /// the connection to survive a message this core has already stopped parsing.
  /// A caller that states a `Connection` field of its own is REFUSED rather than
  /// having a second one appended: RFC 9110 §5.3 makes repeated field lines one
  /// comma-separated list, so the two would become a single field saying two
  /// things about the connection. The refusal costs nothing — it writes no
  /// bytes and does not spend the single answer, so the caller retries without
  /// the field.
  ///
  /// The message needs no `Content-Length`: it is close-delimited by the close
  /// it forces (§6.3 item 8), which is what [`BodyPlan::CloseDelimited`] states
  /// deliberately and this path arrives at by necessity — a connection that
  /// cannot frame what it received has no second message to keep self-delimiting
  /// for. What it may not do is ANNOUNCE a body — a
  /// `Content-Length` past zero, or any `Transfer-Encoding` — since the one
  /// answer the peer is going to get would then read as incomplete when the
  /// connection closes behind it (item 6).
  ///
  /// A 1xx is REFUSED — an interim response answers nothing, and this path has
  /// no second call to leave the real answer owed in — and so is the whole 2xx
  /// class, which is the same rule Tunnel's [`reject`](Connection::reject)
  /// applies while a rejection is owed: a phase whose whole meaning is "a
  /// rejection is owed" has no success class to state, and the message being
  /// answered is one this connection could not frame. A 3xx is legal, because a
  /// redirect IS a refusal of the request as it was put.
  ///
  /// EXACTLY ONCE, and only from a failed connection. Afterwards the connection
  /// is draining: [`poll_event`](Connection::poll_event) yields
  /// [`Event::CloseSignaled`], no further inbound byte is processed (§9.6), and
  /// every send call — this one included — is [`Error::InvalidState`].
  pub fn send_error_response<H: Headers + ?Sized>(
    &mut self,
    code: u16,
    reason: &[u8],
    headers: &H,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    let (Lifecycle::Failed, SendState::ErrorOwed { close_signaled }) = (self.lifecycle, self.send)
    else {
      return Err(Error::InvalidState(NO_ERROR_OWED));
    };
    // An interim response answers nothing and would leave this one owed, which
    // is a state this path has no second call to leave.
    if matches!(code, 100..=199) {
      return Err(Error::InvalidState(INTERIM_NOT_FINAL));
    }
    // And the whole 2xx class, for the reason the Tunnel side spells out at its
    // own rejection site: a phase whose whole meaning is "a rejection is owed"
    // has no success class to state. A 3xx is not caught — a redirect is a valid way to
    // refuse the request as it was put.
    if matches!(code, 200..=299) {
      return Err(Error::InvalidState(NO_SUCCESS_TO_STATE));
    }
    // The message this path writes is bodiless, so its head may not announce a
    // body: a `Content-Length` past zero would leave the peer treating the one
    // answer it is going to get as incomplete when the connection closes behind
    // it (RFC 9112 §6.3 item 6), and a `Transfer-Encoding` would frame a chunked
    // body that never comes.
    let declared = declared(headers)?;
    if declared.transfer_encoding > 0 || announces_octets(&declared) {
      return Err(Error::InvalidState(BODILESS_TAKES_NO_BODY));
    }
    // The section the encoder walks is the caller's PLUS the injected option, so
    // the digest it is held to is the reduction's with that same pair folded on
    // the end — the order `WithClose` writes them in. Anything else would refuse
    // every error response, and dropping the check here would leave this one path
    // able to write a section nothing had validated.
    let mut expect = declared.digest;
    expect.mix(CONNECTION.as_bytes(), CLOSE);
    let written = encode_status_head(code, reason, &WithClose { inner: headers }, expect, out)?;

    // Committed, and terminal: §6.1's MUST-close, taken the moment the answer is
    // in the caller's buffer.
    self.send = SendState::Idle;
    self.lifecycle = Lifecycle::Draining;
    // The notice keeps the exactly-once rule `signal_close` states: a connection
    // whose close was already signalled — the peer's option, or a local
    // `close()` — does not hear it twice for the same fact.
    if !close_signaled {
      self.event = Some(Event::CloseSignaled);
    }
    // Nothing is in flight on a connection that has answered its last message.
    // Said here rather than left to rot: a stale receive state would let
    // `handle_eof` diagnose the truncation of a message this connection has
    // already stopped parsing.
    self.recv = RecvState::Idle;
    self.exchange = None;
    self.watermark = 0;
    self.pending_cr = false;
    Ok(written)
  }
}

impl<Ro: Role> Connection<Ro, General> {
  /// The lifecycle gate for a BODY write, which differs from [`sendable`] in one
  /// place and for one reason.
  ///
  /// An abandoned body (RFC 9112 §9.6 — the peer ended the exchange and released
  /// this end from "sending") also drove the connection to draining, so the
  /// generic gate would answer `DRAINED`. That is true and useless: it describes
  /// the connection rather than what happened to THIS message, and a caller
  /// holding half an upload wants the second. So the specific reason is checked
  /// ahead of it.
  ///
  /// A latched violation still outranks both: the connection has already handed
  /// its one error back, and nothing after it is anything else.
  ///
  /// [`sendable`]: Connection::sendable
  fn body_sendable(&self) -> Result<(), Error> {
    if matches!(self.lifecycle, Lifecycle::Failed) {
      return Err(Error::InvalidState(FAILED));
    }
    if matches!(self.send, SendState::Abandoned) {
      return Err(Error::InvalidState(EXCHANGE_ENDED_BY_PEER));
    }
    self.sendable()
  }

  /// Writes body octets under the plan the head declared, returning the bytes
  /// written to `out`.
  ///
  /// `data` is COPIED into `out`, framed as the plan requires: a counted body
  /// (RFC 9112 §6.3 item 6) writes the octets and counts them down, a chunked
  /// one (§7.1) wraps each call in its own `chunk-size CRLF chunk-data CRLF`,
  /// and a close-delimited one (item 8) writes them unframed — nothing in the
  /// stream delimits that body, so there is nothing to add around it. The caller
  /// therefore hands the transport one contiguous slice per call rather than
  /// having to interleave framing with payload itself.
  ///
  /// A chunk is written whole or not at all: a destination that fits the size
  /// line but not the octets behind it reports the exact `need` and writes
  /// nothing, because a truncated chunk delimits the body somewhere the sender
  /// did not.
  ///
  /// An EMPTY `data` writes nothing and reports 0. §7.1 spells `last-chunk` as
  /// `1*("0")`, so a zero-size chunk header IS the end of the body — emitting one
  /// mid-body would end the message and leave the rest to be read as the next one
  /// (§11.2, self-inflicted). The one legitimate `0` line comes from
  /// [`finish_body`](Self::finish_body).
  ///
  /// Over-sending a counted body is [`Error::InvalidState`] and writes nothing:
  /// the octets past the count are the next message's as far as the peer is
  /// concerned (§11.1).
  pub fn send_body(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    self.body_sendable()?;
    let SendState::Sending(sending) = self.send else {
      return Err(Error::InvalidState(NO_BODY_IN_FLIGHT));
    };
    if data.is_empty() {
      return Ok(0);
    }

    let (written, left) = match sending {
      SendBody::Counted(remaining) => {
        // A body longer than `u64` cannot be counted by a field that is a
        // decimal number of octets, so an unrepresentable length is an
        // over-send like any other rather than a wrapped count.
        let Some(left) = u64::try_from(data.len())
          .ok()
          .and_then(|sent| remaining.checked_sub(sent))
        else {
          return Err(Error::InvalidState(OVER_SEND));
        };
        let Some(written) = put(out, 0, data) else {
          return Err(Error::BufferTooSmall {
            need: data.len(),
            have: out.len(),
          });
        };
        (written, SendBody::Counted(left))
      }
      SendBody::Chunked => {
        // Sized before anything is written, out of the encoder that writes the
        // line: a second rendering of the same number here is exactly the drift
        // `head::encode`'s two passes exist to prevent.
        let need = chunk_size_line(data.len())?
          .saturating_add(data.len())
          .saturating_add(CHUNK_TERMINATOR.len());
        if need > out.len() {
          return Err(Error::BufferTooSmall {
            need,
            have: out.len(),
          });
        }
        let at = encode_chunk_header(data.len(), out)?;
        let Some(at) = put(out, at, data).and_then(|at| put(out, at, CHUNK_TERMINATOR)) else {
          // Unreachable: `need` was measured from the same three pieces and
          // checked against `out` above. Answered rather than asserted, since a
          // codec may not panic on any input.
          return Err(Error::BufferTooSmall {
            need,
            have: out.len(),
          });
        };
        (at, SendBody::Chunked)
      }
      // RFC 9112 §6.3 item 8: nothing in the stream delimits this body, so the
      // octets go out exactly as they were handed over — no count to keep, no
      // framing to interleave, and no length this write could exceed. The
      // message is over when the connection is.
      SendBody::ToClose => {
        let Some(written) = put(out, 0, data) else {
          return Err(Error::BufferTooSmall {
            need: data.len(),
            have: out.len(),
          });
        };
        (written, SendBody::ToClose)
      }
    };
    self.send = SendState::Sending(left);
    Ok(written)
  }

  /// Ends the message body, returning the bytes written to `out`.
  ///
  /// For a chunked body this is RFC 9112 §7.1's `last-chunk` and the §7.1.2
  /// trailer section that may follow it — `0 CRLF CRLF` with no trailers, which
  /// is what [`NO_TRAILERS`] asks for. For a counted body there is nothing to
  /// write: the body ended at its last octet, so the call writes 0 bytes and
  /// only CHECKS that every octet the head announced has been sent. One that
  /// stopped short is [`Error::InvalidState`] rather than a message the peer
  /// will treat as incomplete (§6.3 item 6). A close-delimited body (item 8)
  /// writes nothing either, and has nothing to check: it is however many octets
  /// went out, and the close behind it is the end. Trailers are refused on both
  /// — §7.1.2 gives the trailer section to the chunked coding alone.
  ///
  /// FOUR field names are refused in `trailers` whatever the message is:
  /// `Content-Length`, `Transfer-Encoding`, `Host` and `Trailer`
  /// (ASCII-case-insensitively). RFC 9110 §6.5.1 makes generating a trailer
  /// field a sender MUST NOT "unless the sender knows the corresponding header
  /// field name's definition permits the field to be sent in trailers", naming
  /// framing and routing fields as the ones whose evaluation must precede the
  /// content — and a framing field in a trailer section would state a second,
  /// contradictory delimitation of a message this core has already framed by the
  /// chunked coding. The list is deliberately NARROW: which other definitions
  /// permit a trailer is a registry question for the layer that knows what the
  /// message is, so every other name is passed through with its syntax checked
  /// and nothing more.
  ///
  /// This is the send side's completion point, and the other half of RFC 9112
  /// §9.3.2's re-arm gate: with the inbound side of the exchange through as
  /// well, the connection re-arms here — or drains, if keep-alive is over, which
  /// for a close-delimited body it always is.
  pub fn finish_body<H: Headers + ?Sized>(
    &mut self,
    trailers: Option<&H>,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    self.body_sendable()?;
    let SendState::Sending(sending) = self.send else {
      return Err(Error::InvalidState(NO_BODY_IN_FLIGHT));
    };

    let written = match sending {
      // Two framings with nothing left to write, for two reasons. A counted body
      // (RFC 9112 §6.3 item 6) ended at its last octet, and the count reaching
      // zero is the proof; a close-delimited one (item 8) has no count that
      // could come up short, because it is however many octets went out and the
      // CLOSE is what ends it. Either way what this call does is end the SEND
      // side — which for item 8 is what lets the connection take the close its
      // head committed to.
      SendBody::Counted(0) | SendBody::ToClose => {
        if trailers.is_some() {
          return Err(Error::InvalidState(UNCHUNKED_HAS_NO_TRAILERS));
        }
        0
      }
      SendBody::Counted(_) => return Err(Error::InvalidState(BODY_INCOMPLETE)),
      SendBody::Chunked => match trailers {
        Some(trailers) => encode_last_chunk_and_trailers(trailers, out)?,
        None => encode_last_chunk_and_trailers(NO_TRAILER_FIELDS, out)?,
      },
    };

    // Committed: the message is complete in the caller's buffer.
    self.send = SendState::Idle;
    self.settle();
    Ok(written)
  }
}

impl<Ro: Role, Mo: Mode> Connection<Ro, Mo> {
  /// Whether the connection is in a state that can still send anything at all.
  ///
  /// The lifecycle gate every send call opens with, so a failed or drained
  /// connection answers the same way whatever was asked of it. The single error
  /// response is the one exception and checks the latch itself.
  fn sendable(&self) -> Result<(), Error> {
    match self.lifecycle {
      Lifecycle::Failed => Err(Error::InvalidState(FAILED)),
      Lifecycle::Draining => Err(Error::InvalidState(DRAINED)),
      // POLICY decides this and the transport fact deliberately does not appear:
      // the peer shutting its WRITE side says nothing about whether it is still
      // reading the response it asked for (RFC 9112 §9.5), so a closed read side
      // must not refuse an owed answer to a request that arrived in full.
      Lifecycle::Open | Lifecycle::Closing => Ok(()),
    }
  }
}

/// What a caller's field section says about the body under it.
///
/// Gathered in ONE walk of the supplier, ahead of the two the encoder makes, so
/// the rules below read a section already reduced to the few facts they need:
/// how it frames its body, how it routes (RFC 9112 §3.2's `Host`), whether it
/// offers RFC 9110 §7.8's protocol switch, and whether it ends the connection.
///
/// ONE walk is a correctness property, not an economy. Every outbound decision
/// is taken from this single traversal and the traversal is SIGNED
/// ([`Declared::digest`]), so no decision can describe a different section than
/// the one the encoder goes on to write — which is also why the §7.8 offer is
/// reduced here rather than by a second walk in `connection::tunnel`.
///
/// `pub(super)` because these questions are not General's alone: every message
/// `connection::tunnel` writes is its head, and it asks THIS reduction rather
/// than walking the section with rules of its own.
pub(super) struct Declared {
  /// How many `Transfer-Encoding` field lines the section carries — whether the
  /// head says a transfer coding is there at all, which is a different question
  /// from what the list says.
  pub(super) transfer_encoding: usize,
  /// The coding list those lines fold into (RFC 9110 §5.2), classified by the
  /// receive side's own rules. A caller states the codings it applied; this core
  /// applies exactly one, so the two have to be the same one.
  codings: CodingList,
  /// How many `Content-Length` field lines the section carries.
  pub(super) content_length_lines: usize,
  /// The single length they all agree on (RFC 9112 §6.3 item 5's exception, and
  /// RFC 9110 §5.3's folding of repeated lines into one list). `None` when there
  /// is no such field.
  length: Option<u64>,
  /// The section states `Content-Length` more than once, or with anything other
  /// than one `1*DIGIT` value (RFC 9110 §8.6) — see [`LENGTH_IS_ONE_VALUE`].
  length_not_single: bool,
  /// Some list field carries an empty element, which RFC 9110 §5.6.1.1 forbids a
  /// SENDER to generate — see [`SENDER_LIST_EMPTY_ELEMENT`].
  list_fault: bool,
  /// How many `Host` field lines (RFC 9110 §7.2) the section carries. RFC 9112
  /// §3.2 makes one a client MUST on every HTTP/1.1 request and makes more than
  /// one a 400 at the recipient, so the COUNT is what both rules are about.
  ///
  /// Observed in the walk that is already happening rather than in one of its
  /// own: the encoder's two passes come after this reduction, so a request that
  /// owes a `Host` is refused before a byte of it is measured.
  host_lines: usize,
  /// Some `Host` line's value is not the authority-or-empty §3.2 requires,
  /// measured over the OWS-trimmed value the recipient will read.
  ///
  /// A fact about ANY of the lines rather than the first: with more than one the
  /// section is refused anyway, and folding this way means the reduction never
  /// has to decide which line the recipient would have believed.
  host_invalid: bool,
  /// The head states the `close` connection option (RFC 9110 §7.6.1, RFC 9112
  /// §9.6), so this message is the last one on the connection.
  ///
  /// Read on the way OUT for the same reason the receive path reads it on the
  /// way in: §9.6 makes a sender of the option one that "MUST initiate a close
  /// of the connection after it sends the response", so a connection that
  /// re-armed behind such a message would go on processing requests the peer has
  /// already stopped expecting answers to.
  ///
  /// `pub(super)` because Tunnel mode asks the same question of its own interim
  /// path: RFC 9112 §9.6's option binds to the response carrying it, so neither
  /// mode may write one on a head that does not end the exchange.
  pub(super) close: bool,
  /// The section states the `upgrade` connection option (RFC 9110 §7.6.1).
  connection_upgrade: bool,
  /// The section carries an `Upgrade` field line (RFC 9110 §7.8).
  upgrade_field: bool,
  /// RFC 9110 §10.1.1's `Expect`, accumulated across the section's field lines
  /// rather than checked one line at a time.
  ///
  /// §5.2 makes those lines ONE value, so a legal `quoted-string` argument may
  /// span the join — and the per-line check this replaces refused one, while
  /// accepting `ext = value` and `ext;flag`, which the field's production does
  /// not admit. The SAME parser the receive side folds with, asked different
  /// questions: §5.6.1.1's no-empty-elements and a flat refusal of what does not
  /// parse.
  expect: Expectations,
  /// Some field this core INTERPRETS does not parse as its own grammar — see
  /// [`FIELD_STATES_ITS_GRAMMAR`].
  ///
  /// One flag for every such field rather than one per field, because the
  /// consequence is the same for all of them and stating it once is what keeps a
  /// field from being added with the check quietly left out.
  grammar_fault: bool,
  /// The signature of the section this reduction READ, in order.
  ///
  /// The bridge between this walk and the encoder's two: every decision above is
  /// made here, and the encoder refuses to write a section whose digest is not
  /// this one. [`Headers`] requires `for_each` to be idempotent, and this is what
  /// makes the requirement enforced rather than trusted — a byte COUNT would not,
  /// since a supplier can substitute `Content-Length: 6` for `Content-Length: 5`
  /// without changing one.
  pub(super) digest: FieldDigest,
}

impl Declared {
  /// Whether the section states BOTH halves of RFC 9110 §7.8's offer — the
  /// `upgrade` connection option, and an `Upgrade` field naming at least one
  /// well-formed protocol.
  ///
  /// The send-side twin of `tunnel::names_a_protocol`, over the same grammar
  /// (`grammar::is_protocol_list`) and out of the reduction's own walk.
  ///
  /// No malformed-value term: a section whose `Upgrade` does not parse never
  /// reaches this question, because [`declared`] refuses it.
  pub(super) const fn offers_a_protocol(&self) -> bool {
    self.connection_upgrade && self.upgrade_field
  }

  /// Whether the section asks RFC 9110 §10.1.1's `100-continue`.
  pub(super) const fn expects_continue(&self) -> bool {
    self.expect.expects_continue()
  }
}

impl Declared {
  /// Records what one interpreted field's value is as a list, in §5.6.1.1's
  /// terms — and records a value that is not a list at all as the grammar fault
  /// it is, rather than as the empty element it has no elements to have.
  fn note_shape(&mut self, value: &[u8]) {
    match sender_list_shape(value) {
      ListShape::Sendable => {}
      ListShape::EmptyElement => self.list_fault = true,
      ListShape::Unparseable => self.grammar_fault = true,
    }
  }
}

/// Reduces a caller's field section to what it says about the message.
pub(super) fn declared<H: Headers + ?Sized>(headers: &H) -> Result<Declared, Error> {
  let mut declared = Declared {
    transfer_encoding: 0,
    codings: CodingList::new(),
    content_length_lines: 0,
    length: None,
    length_not_single: false,
    list_fault: false,
    host_lines: 0,
    host_invalid: false,
    close: false,
    connection_upgrade: false,
    upgrade_field: false,
    expect: Expectations::new(),
    grammar_fault: false,
    digest: FieldDigest::new(),
  };
  headers.for_each(&mut |name, value| {
    let name = name.as_bytes();
    // Signed FIRST and unconditionally, so the digest covers the whole section
    // rather than the fields this reduction happens to care about: what the
    // encoder writes is every pair, and what may drift is every pair.
    declared.digest.mix(name, value);
    if eq_ignore_ascii(name, HOST) {
      declared.host_lines = declared.host_lines.saturating_add(1);
      // Against the value the RECIPIENT reads: RFC 9110 §5.5 makes the OWS
      // around a field value no part of it, and `head::encode` writes a caller's
      // value verbatim — so trimming here is what makes this the same question
      // the peer's `check_host` will ask, rather than a stricter one that would
      // refuse a request the peer accepts.
      declared.host_invalid |= !host_value_is_valid(trim_ows(value));
    } else if eq_ignore_ascii(name, CONNECTION) {
      // PARSE, then derive — never the reverse. §7.6.1's `connection-option` is
      // a bare token, so a value carrying anything else is not a `Connection`
      // header, and no option is read out of one: matching a member of it would
      // let this core act on a field whose remaining members it never read.
      // RFC 9110 §5.3 then folds repeated lines into one list, which is what
      // accumulating rather than assigning makes of them.
      if is_sender_token_list(value) {
        declared.close |= token_list_contains(value, CLOSE_OPTION);
        declared.connection_upgrade |= token_list_contains(value, UPGRADE_OPTION);
      } else {
        declared.grammar_fault = true;
      }
      declared.note_shape(value);
    } else if eq_ignore_ascii(name, UPGRADE) {
      // RFC 9110 §7.8, folded the same way: a section stating `Upgrade` twice
      // states it, and one malformed line names no protocol however many other
      // lines are well formed.
      declared.upgrade_field = true;
      declared.grammar_fault |= !is_protocol_list(value);
      declared.note_shape(value);
    } else if eq_ignore_ascii(name, EXPECT) {
      // Accumulated, not decided: both the grammar verdict and §5.6.1.1's shape
      // are questions about the COMBINED value, and they are asked after the
      // walk.
      declared.expect.push(value);
    } else if eq_ignore_ascii(name, TRANSFER_ENCODING) {
      declared.transfer_encoding = declared.transfer_encoding.saturating_add(1);
      declared.codings.push(value);
    } else if eq_ignore_ascii(name, CONTENT_LENGTH) {
      declared.content_length_lines = declared.content_length_lines.saturating_add(1);
      // §8.6's production, exactly: ONE value, no list at all. Item 5's
      // identical-list exception is the RECIPIENT's, and reusing it here is what
      // let this core emit `Content-Length: 5,`.
      match parse_content_length(trim_ows(value)) {
        Ok(length) if declared.length.is_none() => declared.length = Some(length),
        // A second line, agreeing or not: §8.6 admits one.
        Ok(_) | Err(_) => declared.length_not_single = true,
      }
    }
  })?;
  // The two fields with a `quoted-string` in their grammar answer §5.6.1.1 from
  // the ACCUMULATOR rather than line by line, for the same reason they answer
  // the grammar there: an element boundary is a fact about §5.2's combined
  // value, and a line that merely continues an open string has none.
  declared.list_fault |= declared.codings.empty_element() || declared.expect.empty_element();
  // Both faults are messages this core will not put on the wire, and both are
  // refused HERE — the one reduction every outbound path goes through — rather
  // than by each of them remembering to ask. Shape before members: an EMPTY
  // element has its own §5.6.1.1 rule and its own diagnosis, and a value that is
  // nothing but one would otherwise be reported as a grammar it never reached.
  if declared.list_fault {
    return Err(Error::InvalidState(SENDER_LIST_EMPTY_ELEMENT));
  }
  // A field this core interprets and cannot parse is refused HERE — the one
  // reduction every outbound path goes through — rather than wherever its
  // meaning happens to be consulted. `Transfer-Encoding` is why the distinction
  // matters: its list is READ only by the chunked framing arm, so a section
  // whose framing is decided elsewhere (a HEAD request, a 304, a body-less
  // status) would otherwise carry an unparseable one onto the wire, where the
  // recipient takes §6.3 item 4 ¶2's close-delimitation and the connection's
  // framing stops being something both ends agree on.
  if declared.grammar_fault || !declared.codings.parsed() || declared.expect.grammar_fault() {
    return Err(Error::InvalidState(FIELD_STATES_ITS_GRAMMAR));
  }
  // Either fault is a message this core will not put on the wire, so it is
  // refused HERE — the one reduction every outbound path goes through — rather
  // than by each of them remembering to ask.
  if declared.length_not_single || (declared.content_length_lines > 0 && declared.length.is_none())
  {
    return Err(Error::InvalidState(LENGTH_IS_ONE_VALUE));
  }
  Ok(declared)
}

/// RFC 9110 §10.1.1's sender rule, applied to a section already reduced: "A
/// client MUST NOT generate a 100-continue expectation in a request that does
/// not include content."
///
/// Shared by every outbound request path for the same reason [`requires_host`]
/// is — all three write requests, so all three owe the rule. The two Tunnel
/// paths pass `false`: RFC 9110 §9.3.6 gives CONNECT no content and this core's
/// upgrade request carries none either, so on those paths the expectation asks
/// for a `100 Continue` that nothing would follow.
///
/// A rule about the BARE expectation, because that is the only one §10.1.1
/// defines — `declared` never records a parameterised member as one.
pub(super) fn continue_needs_content(declared: &Declared, has_content: bool) -> Result<(), Error> {
  if declared.expects_continue() && !has_content {
    return Err(Error::InvalidState(CONTINUE_NEEDS_CONTENT));
  }
  Ok(())
}

/// ALL THREE of RFC 9112 §3.2's `Host` MUSTs, applied to a section already
/// reduced.
///
/// Shared by every outbound request path rather than restated in each: General's
/// [`open_request`](Connection::open_request) and Tunnel's `open_upgrade` /
/// `open_connect` all write `HTTP/1.1` requests, so all three owe the same
/// field under the same three rules.
///
/// The rules are the receive side's, in the order §3.2 states them and with the
/// scopes it gives them — a MISSING `Host` is a fault of "any HTTP/1.1 request
/// message" and the other two of "any request message". Every request this core
/// writes is an HTTP/1.1 one, so all three bind here unconditionally, and the
/// value question goes through `validate::host_value_is_valid` rather than
/// through a second reading of the grammar.
pub(super) fn requires_host(declared: &Declared) -> Result<(), Error> {
  match declared.host_lines {
    0 => Err(Error::InvalidState(REQUEST_NEEDS_HOST)),
    1 if declared.host_invalid => Err(Error::InvalidState(HOST_NOT_AUTHORITY)),
    1 => Ok(()),
    _ => Err(Error::InvalidState(ONE_HOST_LINE)),
  }
}

/// Whether a head announces octets after it — a `Content-Length` that is not
/// zero, which is the only thing a message with no body may still carry
/// (RFC 9110 §8.6 makes `Content-Length: 0` the way to say "no body").
pub(super) fn announces_octets(declared: &Declared) -> bool {
  !matches!(declared.length, None | Some(0))
}

/// Checks that a RESPONSE head and the body plan under it frame the same
/// message, in RFC 9112 §6.3's order of precedence.
fn check_response_framing(
  code: u16,
  plan: BodyPlan,
  exchange: &Exchange,
  declared: &Declared,
) -> Result<(), Error> {
  // RFC 9112 §6.1, ahead of §6.3's list because it is not a question about where
  // this body ends: "A server MUST NOT send a response containing
  // Transfer-Encoding unless the corresponding request indicates HTTP/1.1 (or
  // later minor revisions)". The coding was added in 1.1, and §6.1 states the
  // assumption behind the rule — an implementation "advertising only HTTP/1.0
  // support will not understand how to process transfer-encoded content", so it
  // would read the chunk framing as content and the message would never end
  // where this core said it did.
  //
  // The MUST NOT names the FIELD, so the head is refused even where items 1-2
  // make the recipient ignore it (a 304's fields describe a representation), and
  // the PLAN is refused with it: a chunked body under a head that could not have
  // announced one is the same message by another route. What a 1.0 peer CAN be
  // answered with is item 6's counted body or item 8's close-delimited one.
  if matches!(exchange.version, Version::Http10)
    && (declared.transfer_encoding > 0 || matches!(plan, BodyPlan::Chunked))
  {
    return Err(Error::InvalidState(TE_NEEDS_HTTP_11));
  }
  // Items 1-2, before any framing field is consulted — the same order the
  // receive side applies them in, for the same reason: reading the fields first
  // and applying the status rule afterwards is how a body nobody expects gets
  // attributed to the next message (§11.1).
  let bodiless = exchange.method_head
    || matches!(code, 100..=199 | 204 | 304)
    // General mode never opens a CONNECT exchange — both ends refuse one — so
    // this arm states item 2's rule rather than serving it.
    || (exchange.connect && matches!(code, 200..=299));
  if bodiless {
    if !matches!(plan, BodyPlan::None) {
      return Err(Error::InvalidState(BODILESS_TAKES_NO_BODY));
    }
    // RFC 9112 §6.1 and RFC 9110 §8.6 name 1xx and 204 specifically: a server
    // MUST NOT send either framing field there. For a HEAD response or a 304 the
    // fields describe the body a different request would have received, and item
    // 1 makes the recipient ignore them — so they are the caller's to state.
    if matches!(code, 100..=199 | 204)
      && (declared.transfer_encoding > 0 || declared.content_length_lines > 0)
    {
      return Err(Error::InvalidState(BODILESS_STATUS_FRAMING));
    }
    // Item 1 lets the RECIPIENT ignore these fields; it does not license the
    // SENDER to write anything into them. Two sender rules bind whatever the
    // status is, and both are unconditional:
    //
    // - RFC 9112 §6.2: "A sender MUST NOT send a Content-Length header field in
    //   any message that contains a Transfer-Encoding header field." *Any*
    //   message — item 1 carves out no exception, and the pair is the §11.2
    //   smuggling primitive whether or not this end means a body by it.
    // - RFC 9110 §8.6 spells `Content-Length = 1*DIGIT`, so a length this core
    //   cannot read as one agreed value is one two recipients may read
    //   differently — the same reason `check_framing` refuses it below.
    //
    // What stays legal is item 1's own case: a SINGLE well-formed
    // `Content-Length` on a HEAD response or a 304, which is exactly the field
    // describing the body a GET would have received.
    if declared.transfer_encoding > 0 && declared.content_length_lines > 0 {
      return Err(Error::InvalidState(BOTH_FRAMINGS));
    }
    return Ok(());
  }
  check_framing(plan, declared, false)
}

/// Checks that a head's framing fields announce the body its sender is about to
/// write.
///
/// `request` selects the rules the two directions do not share, and both of them
/// are RFC 9112 §6.3's split over the same absence. With neither framing field a
/// REQUEST has no body (item 7, and the note under item 8 that a request is
/// never close-delimited), so [`BodyPlan::None`] is what that head means and
/// [`BodyPlan::CloseDelimited`] is a message no server would read; a RESPONSE
/// with neither is delimited by the connection closing (item 8), which a
/// connection that stays open is not about to do — so a response either says
/// what it is sending or says it is item 8's.
fn check_framing(plan: BodyPlan, declared: &Declared, request: bool) -> Result<(), Error> {
  match plan {
    BodyPlan::Chunked => {
      if declared.transfer_encoding == 0 {
        return Err(Error::InvalidState(CHUNKED_UNANNOUNCED));
      }
      // §6.3 item 3: the recipient would resolve the disagreement by ignoring
      // the length, and a recipient BEHIND it might not.
      if declared.content_length_lines > 0 {
        return Err(Error::InvalidState(BOTH_FRAMINGS));
      }
      // What the list SAYS, not merely that there is one — and read more
      // strictly than the receive side reads a peer's. A recipient tolerates
      // `gzip, chunked` because item 4 ¶1 still tells it where the body ends
      // (`Codings::ChunkedUndecodable`); a SENDER that wrote it would be naming a
      // coding it never applied, and this core applies exactly one. So only a
      // lone, final, unparameterized `chunked` — `Codings::Chunked` — describes
      // the octets `send_body` is about to write; anything else would have the
      // peer decoding chunk framing as gzip, or reading the framing as payload
      // and never finding the message's end (§11.1, §11.2).
      if !matches!(declared.codings.verdict(), Codings::Chunked) {
        return Err(Error::InvalidState(CHUNKED_DECLARATION));
      }
    }
    BodyPlan::ContentLength(expected) => {
      if declared.transfer_encoding > 0 {
        return Err(Error::InvalidState(if declared.content_length_lines > 0 {
          BOTH_FRAMINGS
        } else {
          TE_WITHOUT_CHUNKED
        }));
      }
      if declared.length != Some(expected) {
        return Err(Error::InvalidState(if declared.length.is_none() {
          UNFRAMED_RESPONSE
        } else {
          LENGTH_DISAGREES
        }));
      }
    }
    BodyPlan::CloseDelimited => {
      // The note under item 8: with neither field a REQUEST ends at its head
      // (item 7), so a close-delimited one is a message no recipient reads that
      // way — and this end could not deliver it either, since the close would
      // have to come before the response it is waiting for.
      if request {
        return Err(Error::InvalidState(REQUEST_IS_NEVER_CLOSE_DELIMITED));
      }
      // Item 8 is the list's "otherwise", so the ABSENCE of both fields is the
      // declaration and there is nothing to require. Either field would frame
      // the message somewhere the close is not — at a count this core never
      // writes down to, or by a coding it is not applying — and the peer would
      // end it there (§11.1).
      if declared.transfer_encoding > 0 || declared.content_length_lines > 0 {
        return Err(Error::InvalidState(CLOSE_DELIMITED_IS_UNFRAMED));
      }
    }
    BodyPlan::None => {
      if declared.transfer_encoding > 0 {
        return Err(Error::InvalidState(TE_WITHOUT_CHUNKED));
      }
      match declared.length {
        Some(0) => {}
        // Item 7: a request with no framing field at all has no body, which is
        // exactly what this plan says.
        None if request => {}
        None => return Err(Error::InvalidState(UNFRAMED_RESPONSE)),
        Some(_) => return Err(Error::InvalidState(LENGTH_DISAGREES)),
      }
    }
  }
  Ok(())
}

/// The exact size of the `chunk-size CRLF` line for `size` octets.
///
/// Asked of the encoder that writes the line rather than computed a second time
/// here: a zero-length destination cannot take a byte, so `two_pass`'s sizing
/// pass answers with the exact `need` and nothing moves. A length calculation
/// kept in step with a writer by hand is the drift `head::encode` is built to
/// rule out, and this keeps that property while letting a whole chunk be sized
/// before any part of it is written.
fn chunk_size_line(size: usize) -> Result<usize, Error> {
  match encode_chunk_header(size, &mut []) {
    // A chunk line is never empty, so the sizing pass is always what answers.
    Ok(written) => Ok(written),
    Err(Error::BufferTooSmall { need, .. }) => Ok(need),
    Err(other) => Err(other),
  }
}

/// Copies `bytes` into `out` at `at`, returning where the next write goes.
/// `None` when they do not fit, in which case nothing was written.
fn put(out: &mut [u8], at: usize, bytes: &[u8]) -> Option<usize> {
  let end = at.checked_add(bytes.len())?;
  let destination = out.get_mut(at..end)?;
  // `get_mut` returned exactly `bytes.len()` slots, so a copy that stops at the
  // shorter of the two stops at neither. A loop rather than `copy_from_slice`,
  // like `head::encode`'s writer, so the leaf stays provably panic-free.
  for (slot, &byte) in destination.iter_mut().zip(bytes) {
    *slot = byte;
  }
  Some(end)
}

/// A caller's field section with the `close` connection option after it.
///
/// The injection is done as a [`Headers`] supplier rather than by writing bytes
/// after the head: the option has to be INSIDE the field
/// section, and going through the same encoder is what keeps it validated,
/// measured, and written exactly like every other field.
struct WithClose<'h, H: Headers + ?Sized> {
  /// The caller's own section, written first.
  inner: &'h H,
}

impl<H: Headers + ?Sized> Headers for WithClose<'_, H> {
  fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), Error> {
    let mut theirs = false;
    self.inner.for_each(&mut |name, value| {
      theirs |= eq_ignore_ascii(name.as_bytes(), CONNECTION);
      f(name, value);
    })?;
    // Refused rather than folded — see `CALLER_STATED_CONNECTION`. The fault is
    // found in the encoder's SIZING pass, which runs before any byte is written,
    // so the caller's buffer is untouched.
    if theirs {
      return Err(Error::InvalidState(CALLER_STATED_CONNECTION));
    }
    f(CONNECTION, CLOSE);
    Ok(())
  }
}
