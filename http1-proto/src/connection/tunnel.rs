//! Tunnel mode: the ONE protocol switch a tunnel connection exists to complete,
//! and the byte stream it hands over once that switch is through.
//!
//! TWO TAKEOVERS, ONE SHAPE. RFC 9110 §7.8's protocol upgrade — answered by the
//! §15.2.2 `101 (Switching Protocols)` — and §9.3.6's CONNECT tunnel — answered
//! by any 2xx — both end HTTP framing at the empty line that closes a head.
//! After that line the "data stream switches to" the new protocol (§7.8), and
//! "data received after that header section is from the server identified by the
//! request target" (§9.3.6). Everything in this module exists to reach that line
//! and hand the rest of the stream over untouched.
//!
//! # What a tunnel connection is not
//!
//! It is not a [`General`](super::General) connection with a flag set. There is
//! no exchange counter (RFC 9112 §9.3.2 correlates messages this connection will
//! never carry), no body decoder (a handshake message IS its head), no
//! keep-alive gate (§9.3's persistence is about the next message, and there is
//! no next message), and no pipelining. The state is the handshake: which
//! takeover is being attempted, whether a `100 (Continue)` is still owed before
//! the 101, and whether the handshake is still open.
//!
//! # The leftover contract
//!
//! Every outcome that CONSUMES a head reports where the bytes behind it begin,
//! and those bytes are handed back VERBATIM — this core neither parses nor
//! buffers them, because they are not HTTP any more. `NeedMore` consumes
//! nothing: a head that has not terminated leaves the whole offer in the
//! driver's buffer, and the scan resumes where it stopped rather than restarting
//! (the same watermark the General path uses).
//!
//! A driver therefore advances its buffer by exactly what an outcome hands back:
//! the leftover of a `Switched` / `Tunneled` / `Connect` / `Upgrade` is the first
//! byte of the new protocol, the leftover of an `Interim` is the first byte of
//! the head that follows it, and the leftover of a `Refused` is the first byte of
//! whatever content that refusal carries. EVERY outcome that consumes a head
//! says where the bytes behind it begin, with no exception to remember.
//!
//! `NeedMore` is an answer about a LIVE transport, so a driver whose read side
//! has ended reports that with [`handle_eof`](Connection::handle_eof) — which
//! records the transport fact and nothing else, leaving the two `handle` calls to
//! resolve the offer that runs out. Its doc carries the table of where each
//! ending lands.
//!
//! # Refusals are terminal, and their bodies are not FRAMED
//!
//! A tunnel completes one handshake. When the answer is not the switch — a 426
//! to an upgrade offer, a 407 to a CONNECT — the handshake is over, and the
//! phase records that: no further call on the connection succeeds.
//!
//! What that does NOT mean is that the refusal's content is unreachable. RFC
//! 9110 §15.5.22's `426` describes the protocol it wants and §11.7's `407`
//! carries the `Proxy-Authenticate` challenge a client must read to retry, so a
//! driver that could not locate the first byte of the content would have to
//! re-scan the head itself to find it. `Refused` reports the leftover like every
//! other consuming outcome.
//!
//! This core still does not DELIMIT that content: it has no body machinery in
//! Tunnel mode, and building one for a message the connection is about to close
//! behind would be a second implementation of RFC 9112 §6.3 living where no
//! second message can follow it. Where the body ends is therefore the caller's
//! reading of the head it was just handed — item 6's `Content-Length`, item 4's
//! chunked coding, or item 8's close — and a caller that wants it framed asks
//! over a [`General`](super::General) connection.
//!
//! # Reject, never mangle — in this direction too
//!
//! Every message this module writes goes through `head::encode`, so a caller's
//! fields are validated element by element and a short buffer reports the exact
//! size and writes nothing. What is checked HERE is what the RFCs make a
//! property of the handshake itself: an offer states both halves of §7.8, a
//! CONNECT target states its port (§9.3.6, RFC 9112 §3.2.3), a handshake message
//! announces no content it will not send, and the head that switches carries no
//! framing field at all.

use core::marker::PhantomData;

use crate::{
  connection::{
    CLOSED_BEFORE_RESPONSE, CLOSED_MID_HEAD, CONNECT, Client, Connection, FAILED, General,
    Lifecycle, RecvState, SWITCHING_PROTOCOLS, SendState, Server, TransitionRefused, Tunnel,
    head_digest,
    inbound::SWITCH_AFTER_CLOSE,
    latch_read_closed,
    outbound::{
      Declared, INTERIM_STATES_NO_CLOSE, READ_SIDE_ENDED, announces_octets, continue_needs_content,
      declared, requires_host,
    },
  },
  error::{Error, H1Error},
  grammar::lists_a_protocol,
  head::{
    HeadView, Headers, RequestLine, StatusLine, Target, Version,
    encode::{encode_request_head, encode_status_head},
    find_head_end, malformed, parse_request_line, parse_status_line, scan_head,
    skip_leading_empty_lines,
  },
  validate::{
    BodyFraming, check_response_head, ends_persistence, has_close_option, validate_request,
  },
};

/// The method an upgrade offer uses. RFC 9110 §7.8's own example is a GET, and
/// the request has to be one whose "message semantics can be honored by the new
/// protocol" — a client of this core states the semantics it is switching AWAY
/// from with the plainest method there is.
const GET: &str = "GET";

/// RFC 9110 §15.3.1: the 2xx that establishes a CONNECT tunnel. §9.3.6 admits
/// "any 2xx (Successful) response"; this core sends the one every proxy sends.
const CONNECTION_ESTABLISHED: u16 = 200;

/// The reason-phrase of that response. RFC 9112 §4 makes a `reason-phrase`
/// optional and purely advisory, so this is convention rather than protocol —
/// but it is the convention every CONNECT client's logs are written against.
const ESTABLISHED_REASON: &[u8] = b"Connection Established";

/// The reason-phrase of the 101 (RFC 9110 §15.2.2's own name for it).
const SWITCHING_REASON: &[u8] = b"Switching Protocols";

/// RFC 9110 §10.1.1's `100 (Continue)`, and §7.8's MUST: it is the one interim
/// response that discharges the ordering rule before a 101.
pub(super) const CONTINUE: u16 = 100;

/// RFC 9110 §7.8 `Upgrade`, the field a RECEIVED head is read for here. Its
/// send-side twin — and the `upgrade` connection option §7.8 requires beside
/// it — live in `connection::outbound`'s one reduction of a caller's section,
/// so the two facts an offer is made of come out of a single walk.
const UPGRADE: &str = "Upgrade";

/// A tunnel completes ONE handshake, so a second open — or a second request on
/// a connection that has already classified one — has nothing to belong to.
pub(super) const ONE_HANDSHAKE: &str = "this connection has already begun its handshake";

/// Nothing is in flight: a client that has not sent its request (RFC 9112 §9.2
/// makes arriving bytes not a response at all), or a handshake that is over.
pub(super) const NO_HANDSHAKE: &str = "no handshake is in flight on this connection";

/// The single rejection a handshake may still be answered with is not owed —
/// there was none to answer, or it has been written already.
pub(super) const NOTHING_TO_ANSWER: &str = "no rejection is owed on this connection";

/// RFC 9110 §7.8: "A sender of Upgrade MUST also send an `Upgrade` connection
/// option in the Connection header field" — so an offer states both halves, and
/// each protocol it names is `protocol-name ["/" protocol-version]`.
///
/// ONE constant for BOTH offering senders, because §7.8 states ONE rule and it
/// is written over the sender rather than over the mode. The two are:
///
/// - `Tunnel`'s `open_upgrade`, which builds a handshake and so requires the
///   whole offer, either half missing.
/// - `General`'s `open_request`, which BRANCHES on §7.8's indication — the
///   `Upgrade` field alone — and then requires the connection option inside that
///   branch, so an indication cannot go out un-optioned. The missing-field half
///   cannot be its reason: a request without the field made no offer and is an
///   ordinary request this mode writes.
///
/// A mode-specific spelling would say the rule was two rules, and a driver
/// diagnosing the same omission would read two different reasons for it.
pub(super) const OFFER_NEEDS_BOTH_HALVES: &str =
  "an upgrade offer states Connection: upgrade and an Upgrade protocol list";

/// The same rule on the 101 that answers it, in both directions: RFC 9110
/// §15.2.2 makes the `Upgrade` field a MUST for the server that switches, and
/// §7.8 requires the connection option beside it.
pub(super) const SWITCH_NEEDS_BOTH_HALVES: &str =
  "a 101 states Connection: upgrade and an Upgrade protocol list";

/// RFC 9110 §7.8: "A server MUST NOT switch to a protocol that was not indicated
/// by the client in the corresponding request's Upgrade header field."
///
/// ONE constant for BOTH readers, because §7.8 states ONE rule — it is written
/// over the indication, not over the mode that reads it, and a 101 accepted by
/// one reader and refused by the other would be the recipient disagreement RFC
/// 9112 §11.1 is about. The two are:
///
/// - A `Tunnel` handshake opened as a CONNECT, which indicates no protocol at
///   all (`handle_response`).
/// - A `General` exchange whose request sent no `Upgrade` field — every exchange
///   on an unpermitted connection, and any exchange on a permitted one that did
///   not take the offer up (`inbound::switch_or_fault`). Permission is not
///   indication.
///
/// BOTH descriptions are claims about what this end SENT, and each is kept true
/// by a send-side guard rather than by good fortune. Deleting either falsifies
/// this doc from another file, and turns the constant into an accusation against
/// a peer that broke nothing:
///
/// - The CONNECT arm rests on [`CONNECT_INDICATES_NO_PROTOCOL`]: without it a
///   caller may put `Upgrade:` on a CONNECT, and the 101 that answers it is
///   indicated exactly as §7.8 means the word.
/// - The `General` arm rests on `open_request`'s offer gates, which key on the
///   `Upgrade` field alone: keyed on both of §7.8's halves instead, an
///   un-optioned field goes out un-recorded and its lawful 101 arrives here.
pub(super) const SWITCH_WAS_NEVER_OFFERED: &str = "101 to a request that offered no protocol";

/// RFC 9112 §3.2.3 scopes the authority-form to CONNECT and §3.2.4 the
/// asterisk-form to a server-wide OPTIONS: neither addresses anything a GET
/// carrying an upgrade offer could be answered for.
pub(super) const SWITCH_TARGET_FORM: &str =
  "an upgrade offer takes an origin- or absolute-form target";

/// RFC 9110 §9.3.6: "A CONNECT request message does not have content", and
/// nothing else this core writes in Tunnel mode has one either — every message
/// here is its head.
pub(super) const HANDSHAKE_HAS_NO_CONTENT: &str = "a tunnel handshake message carries no content";

/// A CONNECT states RFC 9110 §9.3.6's takeover, and stating §7.8's as well would
/// open a handshake whose own continuation forbids one of the two answers it
/// invited.
///
/// The `Upgrade` field is what §7.8 makes an INDICATION — "A server MUST NOT
/// switch to a protocol that was not indicated by the client in the
/// corresponding request's Upgrade header field" — so a CONNECT carrying it
/// invites a `101` that a conformant server may legally send. This mode has no
/// answer that could carry one: [`ClientTunnelOutcome`] represents a CONNECT's
/// success as §9.3.6's 2xx tunnel, and `handle_response`'s
/// `(SWITCHING_PROTOCOLS, true)` arm condemns the 101 as
/// [`SWITCH_WAS_NEVER_OFFERED`] — an accusation that would be FALSE against a
/// server acting on the very field this end wrote.
///
/// So it is refused before encoding, for exactly the reason General's
/// `UPGRADE_NEEDS_TUNNEL` refuses its own case: such a request "would have
/// opened an exchange its own continuation forbids". Asked over the INDICATION
/// alone ([`Declared::indicates_a_protocol`]), because the `upgrade` connection
/// option beside it changes nothing about whether a server may act — and a
/// predicate that wanted both halves would let the un-optioned field through,
/// which is what the General side's own predicate exists to prevent.
///
/// [`Declared::indicates_a_protocol`]: super::outbound::Declared::indicates_a_protocol
pub(super) const CONNECT_INDICATES_NO_PROTOCOL: &str =
  "a CONNECT request indicates no protocol upgrade";

/// RFC 9112 §6.1 and RFC 9110 §8.6 (a 1xx carries neither framing field) with
/// RFC 9110 §9.3.6 ("A server MUST NOT send any Transfer-Encoding or
/// Content-Length header fields in a 2xx (Successful) response to CONNECT"): the
/// head that switches frames nothing, because what follows it is not a body.
pub(super) const SWITCH_HAS_NO_FRAMING: &str = "a response that switches carries no framing field";

/// RFC 9112 §3.2.3 `authority-form = uri-host ":" port` with RFC 9110 §9.3.6:
/// "There is no default port; a client MUST send the port number" — and a
/// number that addresses a TCP port, which is what [`port_number`] decides.
pub(super) const CONNECT_NEEDS_A_PORT: &str = "a CONNECT target states host and a port in 1-65535";

/// The server half of the same rule: "A server MUST reject a CONNECT request
/// that targets an empty or invalid port number, typically by responding with a
/// 400 (Bad Request) status code" (RFC 9110 §9.3.6). BOTH adjectives are
/// enforced — see [`port_number`] for what makes one invalid.
pub(super) const CONNECT_TARGET_NEEDS_A_PORT: &str =
  "CONNECT request-target has an empty or invalid port";

/// The SEND half of the one-takeover-no-close invariant — see
/// [`TunnelPhase::Switched`], which states it once for all its sites.
///
/// RFC 9112 §9.6 binds a sender of the option: a server that sends `close`
/// "MUST initiate closure of the connection (see below) after it sends the
/// response containing the close connection option". A message that offers or
/// makes RFC 9110 §7.8's switch while stating `close` therefore promises to end
/// the connection it is handing to another protocol, which is not a promise this
/// core will put on the wire.
///
/// Caller-side, and that is why it is not
/// [`SWITCH_AFTER_CLOSE`](super::inbound::SWITCH_AFTER_CLOSE): this refuses what
/// the CALLER asked for rather than diagnosing what a peer did, and a driver
/// reading a reason needs to know which of the two it has. ONE constant across
/// the three send sites, because they are one rule — `open_request`'s offer
/// branch, [`open_upgrade`](Connection::open_upgrade), and
/// [`accept`](Connection::accept)'s 101 — and the message is true at each.
pub(super) const TAKEOVER_STATES_NO_CLOSE: &str = "a protocol takeover states no Connection: close";

/// The RECEIVE half of the same invariant, on a request rather than a response.
///
/// RFC 9112 §9.6's other MUST: a server that RECEIVES the option "MUST initiate
/// closure of the connection (see below) after it sends the final response to
/// the request that contained the close connection option". A server owes a
/// close once it has answered, and a switch is the opposite promise — so an
/// offer carrying `close` is not a handshake this connection could complete.
///
/// NOT [`NOT_A_HANDSHAKE`], whose message — "request is neither a protocol
/// upgrade nor a CONNECT" — would be false here: this request IS a protocol
/// upgrade, and the `close` beside it is why it is refused. NOT
/// [`SWITCH_AFTER_CLOSE`](super::inbound::SWITCH_AFTER_CLOSE) either, whose
/// message names a 101 that does not exist on this path. Same disposition as
/// [`NOT_A_HANDSHAKE`] — [`H1Error::Framing`], which a driver answers 400 — for
/// the reason that constant states: the message is well formed and what this
/// connection cannot do is SERVE it.
///
/// THE TWIN OF THIS RULE IS GENERAL'S, and the two answer one wire request:
/// General accumulates the close at `commit_head` and refuses the transition
/// with `TransitionRefused::NOT_OPEN`. This path reads `has_upgrade` and
/// `expect_continue` out of the same directives, and must read the `close`
/// beside them — two recipients disagreeing about the same bytes is what RFC
/// 9112 §11.1 is.
pub(super) const HANDSHAKE_STATES_CLOSE: &str =
  "a handshake request that also states Connection: close";

/// RFC 9110 §7.8: "If a server receives both an Upgrade and an Expect header
/// field with the `100-continue` expectation, the server MUST send a 100
/// (Continue) response before sending a 101 (Switching Protocols) response."
pub(super) const CONTINUE_BEFORE_SWITCH: &str = "a 100 (Continue) is owed before this 101";

/// The statuses that MAKE the switch rather than talk about one: the 101, which
/// RFC 9110 §7.8 makes the last thing this end says as HTTP — immediately after
/// sending it the server is expected "to continue responding to the original
/// request as if it had received its equivalent within the new protocol", while
/// §15.2.2 defines the status code rather than the rule about what follows it —
/// and, wherever the peer would read one as the tunnel, any 2xx — §9.3.6: "Any
/// 2xx (Successful) response indicates that the sender (and all inbound
/// proxies) will switch to tunnel mode immediately after the response header
/// section".
/// Neither is something said while a handshake is being decided, and neither
/// REFUSES one: `accept` writes them, because it is the call that records that
/// this connection stopped being HTTP.
///
/// "Wherever the peer would read one" is the recipient's rule and not this
/// core's classification, so it covers two phases: a CLASSIFIED CONNECT, and a
/// request that failed classification — which may have BEEN a CONNECT, and which
/// in any case owes a rejection rather than a success. The classified upgrade
/// side is deliberately not covered: only its 101 switches, so a 200 there is
/// the ordinary answer §7.8 lets a server give instead of upgrading.
pub(super) const SWITCH_THROUGH_ACCEPT: &str = "the response that switches goes through accept";

/// RFC 9110 §15.2: a 1xx is interim, and a tunnel's final answer is either the
/// switch (`accept`) or the refusal (`reject`).
pub(super) const NOT_INTERIM: &str = "only a 1xx response is interim";

/// RFC 9110 §15.2: "Since HTTP/1.0 did not define any 1xx status codes, a server
/// MUST NOT send a 1xx response to an HTTP/1.0 client."
pub(super) const INTERIM_NEEDS_HTTP_11: &str = "a 1xx response requires an HTTP/1.1 request";

/// RFC 9112 §6.1 with RFC 9110 §8.6: neither framing field belongs in a 1xx.
pub(super) const INTERIM_HAS_NO_FRAMING: &str = "a 1xx carries no framing field";

/// A request that is neither RFC 9110 §7.8's offer nor §9.3.6's tunnel. Framing
/// rather than caller-side: the message is on the wire and well formed, and what
/// this connection cannot do is SERVE it — which is what a 400 says.
pub(super) const NOT_A_HANDSHAKE: &str = "request is neither a protocol upgrade nor a CONNECT";

/// RFC 9112 §3.2.3 pairs the authority-form with CONNECT and validation enforces
/// the pairing, so this is the answer to a target that somehow was not one —
/// stated rather than assumed.
const CONNECT_TARGET_FORM: &str = "CONNECT request-target is not in the authority-form";

/// Client-side outcome of a tunnel handshake. The two directions get SEPARATE
/// enums — one enum serving both would leave most variants unreachable per role,
/// which is the runtime-flag anti-pattern the type-state exists to remove.
///
/// Every variant that consumed a head says where the bytes behind it begin; see
/// the module doc for the contract a driver advances its buffer by.
///
/// `#[non_exhaustive]`, unlike [`Target`] or [`BodyPlan`](super::BodyPlan): the
/// variants below are this core's REPORTING vocabulary rather than a closed set
/// the RFCs fixed, so a handshake shape that is worth telling a driver apart
/// from the four here can be added without a breaking release. A consumer
/// therefore matches with a `_` arm.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientTunnelOutcome<'a> {
  /// RFC 9110 §15.2.2: the server switched, and `leftover` is the new protocol's
  /// first byte. Which protocol it switched TO is the caller's to check against
  /// what it offered — `head` carries the `Upgrade` field that names it (§7.8
  /// requires the server to send one) — since only the caller knows the offer.
  Switched {
    /// The 101 head.
    head: HeadView<'a>,
    /// The bytes after that head, verbatim: they are the new protocol's.
    leftover: &'a [u8],
  },
  /// RFC 9112 §6.3 item 2: a 2xx to CONNECT, so "the connection will become a
  /// tunnel immediately after the empty line that concludes the header
  /// fields". Any `Content-Length` or `Transfer-Encoding` in that head is
  /// IGNORED, as that item requires of a client — `leftover` is tunnel data,
  /// not content.
  Tunneled {
    /// The 2xx head.
    head: HeadView<'a>,
    /// Its status-line, as this core parsed it (RFC 9112 §4).
    ///
    /// §9.3.6 admits "any 2xx (Successful) response", so WHICH 2xx established
    /// the tunnel is a fact the head alone does not hand over — and the §4 codec
    /// that produced it is crate-private. A driver logging or branching on the
    /// established code reads it here rather than re-parsing a start line.
    status: StatusLine<'a>,
    /// The bytes after that head, verbatim: they are the tunnel's.
    leftover: &'a [u8],
  },
  /// RFC 9110 §15.2: an interim (non-101 1xx) response. The head is consumed and
  /// the handshake is still open, so the caller offers `leftover` back and keeps
  /// reading.
  ///
  /// `leftover` is here for the same reason the server enum carries one, and it
  /// is not optional: this variant CONSUMES a head, so a driver that
  /// were handed only the head could not work out how far to advance its buffer —
  /// it would re-offer the interim response and read it again forever. Every
  /// variant that consumes says where the remainder starts.
  Interim {
    /// The interim head.
    head: HeadView<'a>,
    /// Its status-line, as this core parsed it (RFC 9112 §4).
    ///
    /// WHICH interim arrived is the caller's next question — a `100 (Continue)`
    /// discharges an expectation, a `103 (Early Hints)` carries links to act on
    /// — and §15.2 lets any number of them precede the final answer, so the code
    /// is the only thing telling two of them apart. Carried for the same reason
    /// [`Refused`](Self::Refused) carries one: the §4 codec is crate-private.
    status: StatusLine<'a>,
    /// The bytes after it — where the next head begins.
    leftover: &'a [u8],
  },
  /// The switch will not happen (RFC 9110 §7.8: "Upgrade cannot be used to
  /// insist on a protocol change"; §9.3.6: "Any response other than a successful
  /// response indicates that the tunnel has not yet been formed").
  ///
  /// Any final response that is not the switch, AND an interim one that states
  /// RFC 9112 §9.6's `close` option: §9.6 makes a sender of that option close
  /// "after it sends the response containing" it, and a 1xx is a response
  /// message — so a peer that puts it on an interim has committed to closing,
  /// and no switch may follow. The [`status`](Self::Refused::status) is what
  /// tells the two apart.
  ///
  /// TERMINAL for the HANDSHAKE, and it says where the head ended like every
  /// other outcome that consumed one.
  ///
  /// WHY it was refused is the caller's next question — a 426 asks for a
  /// different protocol (RFC 9110 §15.5.22), a 401/407 asks for credentials, a
  /// 403 is final — so the parsed [`StatusLine`] travels with the head rather
  /// than leaving a consumer to re-parse a start line whose codec is
  /// crate-private. That question usually has its answer in the response's
  /// CONTENT: §15.5.22's `426` describes the protocol it wants, and RFC 9110
  /// §11.7's `407` carries the `Proxy-Authenticate` challenge a client has to
  /// read before it can retry. `leftover` is where those octets begin.
  ///
  /// **What `leftover` is, and what it is not.** It is the suffix of the offer
  /// the head did not cover, verbatim — the same contract every other variant
  /// keeps, so a driver advances its buffer by the same arithmetic whatever the
  /// answer was. It is NOT a framed body: this core does not decode a refusal's
  /// content (see the module doc), so how far the body extends is the CALLER's
  /// to work out from the head it was just handed — a `Content-Length` counts
  /// the octets (RFC 9112 §6.3 item 6), a `Transfer-Encoding: chunked` delimits
  /// them (item 4), and neither field means item 8's close-delimited body, which
  /// is however many octets arrive before the connection ends. A caller that
  /// wants the body framed FOR it asks over a [`General`](super::General)
  /// connection instead.
  Refused {
    /// The refusing head.
    head: HeadView<'a>,
    /// Its status-line, as this core parsed it (RFC 9112 §4).
    status: StatusLine<'a>,
    /// The bytes after that head, verbatim — the first of them is the first
    /// octet of whatever content the refusal carries. Unframed: see the variant
    /// doc.
    leftover: &'a [u8],
  },
  /// The head has not all arrived. Consumes 0 — offer the same bytes again with
  /// more behind them.
  NeedMore,
}

/// Server-side classification of a tunnel request. `leftover` is REQUIRED here
/// too: after a CONNECT head the client may already have sent tunnel bytes, and
/// after an upgrade request it may have pipelined frames of the protocol it is
/// switching to.
///
/// Both classifications carry the parsed [`RequestLine`] beside the head. The
/// decisions this core DELEGATES upward need it — which method arrived (§7.8
/// scopes an offer to the fields, not to GET, so a WebSocket layer enforcing
/// GET reads it here), and which destination a CONNECT named — and the §3 codec
/// that produces one is crate-private, so a consumer that was handed only the
/// head could not read a request-target at all.
///
/// `#[non_exhaustive]` for the same reason [`ClientTunnelOutcome`] is: these are
/// classifications this core reports, not a set the RFCs closed.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServerTunnelRequest<'a> {
  /// RFC 9110 §7.8: a bodiless request stating both halves of an upgrade offer.
  /// Which protocol to switch to — and whether to switch at all, which §7.8
  /// leaves a MAY — is the caller's, out of `head`.
  Upgrade {
    /// The request head.
    head: HeadView<'a>,
    /// Its request-line, as this core parsed it (RFC 9112 §3).
    request: RequestLine<'a>,
    /// The bytes after it, verbatim: what the client pipelined behind its offer.
    leftover: &'a [u8],
  },
  /// RFC 9110 §9.3.6: a CONNECT naming its tunnel destination in the RFC 9112
  /// §3.2.3 `uri-host ":" port` form.
  Connect {
    /// The request head.
    head: HeadView<'a>,
    /// Its request-line, whose [`Target::Authority`] names the tunnel
    /// destination the driver is being asked to reach.
    request: RequestLine<'a>,
    /// The bytes after it, verbatim: tunnel data the client sent early.
    leftover: &'a [u8],
  },
  /// The head has not all arrived. Consumes 0.
  NeedMore,
  /// The client's write side ended at a message boundary with nothing buffered:
  /// it closed without asking for a handshake.
  ///
  /// TERMINAL and NOT a fault — nothing was owed, so there is nothing to answer
  /// and nothing to latch. Only reachable once
  /// [`handle_eof`](Connection::handle_eof) has reported the close; before that
  /// an empty offer is [`NeedMore`](Self::NeedMore), because more may come.
  ///
  /// Consumes 0, and re-offering says the same thing: the fact it reports is the
  /// transport's, and that does not change.
  Closed,
}

/// Where the ONE handshake this connection carries stands.
///
/// Small on purpose: a tunnel has no message state to keep, so what is left is
/// the phase and the two facts the answer turns on.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum TunnelPhase {
  /// Nothing has happened: a client has not written its request, a server has
  /// not read one.
  Idle,
  /// The handshake is under way — a client is reading the response to its
  /// request, a server owes the answer to a request it has classified.
  Handshaking(Handshake),
  /// TERMINAL: the switch happened and the stream belongs to the next protocol.
  ///
  /// # The one-takeover-no-close invariant
  ///
  /// **No path of this crate arms, makes, or accepts a protocol takeover — RFC
  /// 9110 §7.8's switch or §9.3.6's tunnel — on a connection whose CLOSE WAS
  /// STATED IN A MESSAGE, this end's or the peer's.** Stated here once because
  /// it spans four files and two modes, and four copies of one rule are four
  /// things that can drift apart.
  ///
  /// ONE UNQUALIFIED RULE, and §9.3.6's tunnel is not an exception to it —
  /// though reading `close` on a CONNECT 2xx as "no HTTP reuse once the tunnel
  /// ends" invites one. §9.6's text does not support that reading: it defines
  /// the option directly and unconditionally as an obligation to "close the
  /// connection after reading the response message containing" it, and does not
  /// key on whether anything is still owed — which is the distinction such an
  /// exemption would have to be built on. §9.3.6 has the same response
  /// switching to tunnel mode "immediately after the response header section".
  /// The two clauses name one instant and demand opposite things, so such a
  /// response is a self-contradiction rather than a working tunnel, and it is
  /// refused exactly as a close-bearing 101 is.
  ///
  /// "Stated in a message", not "either end has said it is closing", and the
  /// narrowing is deliberate rather than a weakening. A LOCAL
  /// [`close`](Connection::close) is an end saying it is closing, and it does
  /// NOT prevent a takeover: a 101 answering an offer that was already on the
  /// wire still switches, because the peer is blameless, its response is valid,
  /// and `close`'s own contract lets the exchange in flight finish. That corner
  /// is deliberate and tested. What the invariant governs is the option stated
  /// in a MESSAGE, which is what RFC 9112 §9.6 binds and what a takeover would
  /// contradict on the wire.
  ///
  /// EVERY takeover site reads one predicate, `validate::has_close_option`: the
  /// stated `close` option, or a `Connection` field this recipient could not
  /// read. It does NOT fold in §9.3's HTTP/1.0 non-persistence default, and the
  /// split is TAKEOVER-versus-MESSAGE rather than request-versus-response.
  ///
  /// The default answers "may another HTTP MESSAGE follow this one?", which is
  /// the right question for an interim or an ordinary response and the wrong one
  /// here: both takeovers end HTTP framing on the connection, so afterwards
  /// there is no such message for it to govern. Asking `ends_persistence` at a
  /// takeover refuses `HTTP/1.0 200 Connection Established` — a legal answer to
  /// an HTTP/1.1 CONNECT, and the classic form real proxies send — and throws
  /// away the tunnel bytes behind it; it refuses a 1.0 101 that has stated
  /// nothing too, which the constants' own wording ("after the peer STATED
  /// close") makes false.
  ///
  /// SPLITTING request-versus-response instead — the option on requests, the
  /// version default on responses — puts the two sides of one rule on different
  /// questions, which is the conflation this one predicate exists to stop. Two
  /// predicates that agree on most inputs are how such a split survives: the
  /// disagreement shows only at the input that separates them.
  ///
  /// RFC 9112 §9.6 binds both ends, and both halves are MUSTs. A server that
  /// SENDS the option "MUST initiate closure of the connection (see below) after
  /// it sends the response containing the close connection option"; a server that
  /// RECEIVES one "MUST initiate closure of the connection (see below) after it
  /// sends the final response to the request that contained the close connection
  /// option". A switch is the opposite promise — the connection continues, under
  /// another protocol — so a message stating both says two contradictory things
  /// about one connection.
  ///
  /// ## The rule that classifies a site, so a new one lands by construction
  ///
  /// The rule has TWO AXES, and the second is there because the first is blind
  /// to a whole shape of site. A site belongs to this invariant when it either:
  ///
  /// - **SPATIALLY** does one of three things — writes this variant, constructs
  ///   a [`Handshake`] for a §7.8 upgrade, or encodes a §7.8 switching head; or
  /// - **TEMPORALLY** changes the connection's fate while a switch is ARMED —
  ///   between the offer going out and the answer arriving, when the crate does
  ///   not yet know whether the transport will be HTTP's to close.
  ///
  /// Every such site is one of:
  ///
  /// - **GUARDED** — it asks the close question itself.
  /// - **GUARDED BY A CALLER** — an earlier gate makes the state unreachable, and
  ///   the site names which gate.
  /// - **STRUCTURALLY EXCLUDED** — the site cannot reach this state at all, and
  ///   says what stops it.
  ///
  /// A site that is none of the three is a defect, not a judgement call.
  ///
  /// **Why the second axis exists.** The spatial rule enumerates sites by what
  /// they DO to a switch, and [`close`](Connection::close) does none of those
  /// three things — it only moves the lifecycle, on a connection whose
  /// transport has no settled owner yet. A definition whose only axis is
  /// spatial cannot see such a site at all.
  ///
  /// `close` does not block the switch, and must not: its own contract is that
  /// "no further exchange BEGINS" while
  /// "the exchange in flight, if any, still finishes", and a switch is how THIS
  /// exchange finishes — so blocking it would both contradict that sentence and
  /// answer a blameless peer's valid 101 with a fault.
  ///
  /// ## Membership today
  ///
  /// | corner | site | verdict |
  /// |---|---|---|
  /// | originate | `open_request`'s offer branch (`Client, General`) | GUARDED — [`TAKEOVER_STATES_NO_CLOSE`] |
  /// | originate | [`open_upgrade`](Connection::open_upgrade) (`Client, Tunnel`) | GUARDED — [`TAKEOVER_STATES_NO_CLOSE`] |
  /// | receive | `classify`'s upgrade arm (`Server, Tunnel`) | GUARDED — [`HANDSHAKE_STATES_CLOSE`] |
  /// | receive | `into_tunnel`/`take_over` (`_, General`) | GUARDED BY A CALLER — `commit_head`'s `peer_close_effects` takes the lifecycle out of `Open`, and `take_over` refuses `TransitionRefused::NOT_OPEN` |
  /// | emit | [`accept`](Connection::accept)'s 101 branch (`Server, Tunnel`) | GUARDED — [`TAKEOVER_STATES_NO_CLOSE`] |
  /// | emit | `send_interim`/`send_response` (`Server, General`) | STRUCTURALLY EXCLUDED — a 101 is refused outright (`SWITCHING_NEEDS_TUNNEL`), so this mode cannot emit one |
  /// | accept | `inbound::switch_or_fault` (`Client, General`) | GUARDED — [`SWITCH_AFTER_CLOSE`](super::inbound::SWITCH_AFTER_CLOSE) |
  /// | accept | [`handle_response`](Connection::handle_response)'s 101 arm (`Client, Tunnel`) | GUARDED — [`SWITCH_AFTER_CLOSE`](super::inbound::SWITCH_AFTER_CLOSE) |
  ///
  /// ### The temporal axis, and why it needs no mechanism
  ///
  /// A site also belongs when it changes the connection's fate while a handover
  /// is still possible. That axis carries NO machinery of its own — no notice
  /// deferred, held, resolved and suppressed across producers, paths and modes,
  /// which is the shape it would otherwise take.
  ///
  /// What the driver should do with the transport is a LEVEL,
  /// derived on the ask by [`Connection::transport`](super::Connection::transport)
  /// from state this connection already holds, with
  /// [`Transport::HandedOver`](super::Transport::HandedOver) absorbing and
  /// checked ahead of every other arm. So a switch site has nothing to cancel:
  /// writing this variant IS the cancellation, and every channel that answers
  /// about the transport answers from the same projection. A mutation on a
  /// parked connection that a guard fails to refuse cannot change what a driver
  /// reads — so the failure mode this axis names is prevented structurally
  /// rather than policed.
  ///
  /// Four further sites sit ON a handshake without switching, and keep this rule
  /// already: both `send_interim`s refuse an interim stating `close`
  /// ([`INTERIM_STATES_NO_CLOSE`]), Tunnel's interim arm answers a
  /// persistence-ending 1xx with `Refused`, and General's `peer_close_effects`
  /// drains at the interim that carried the option.
  ///
  Switched,
  /// TERMINAL: the handshake ended without a switch.
  Refused,
  /// A server could not serve what arrived and owes exactly one answer, which
  /// [`reject`](Connection::reject) writes. A connection that cannot frame what
  /// it received answers once and closes (RFC 9112 §6.1's MUST), and nothing
  /// after that.
  RejectionOwed,
}

/// What the handshake in flight is, in the facts its answer depends on.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct Handshake {
  /// RFC 9110 §9.3.6's CONNECT tunnel rather than §7.8's protocol upgrade —
  /// which decides whether the answer is a 2xx or the 101, and which response
  /// the client end is waiting for.
  connect: bool,
  /// RFC 9110 §7.8's ordering MUST: the request carried BOTH an `Upgrade` field
  /// and the `100-continue` expectation, so the 100 has to go out before the
  /// 101. Server side only — a client's own request is the one it just wrote.
  interim_owed: bool,
  /// The version the REQUEST stated (RFC 9112 §2.3), which RFC 9110 §15.2 makes
  /// load-bearing for the server: no 1xx may be sent to a 1.0 client. A client
  /// records the 1.1 `head::encode` wrote.
  version: Version,
  /// WHICH request armed this handshake, as [`head_digest`] of its whole head
  /// block — what [`head_binding`](Connection::head_binding) answers from, so
  /// that a layer above this one can refuse a head the connection never read.
  ///
  /// NO ABSENT REPRESENTATION, and none is wanted: a CONNECT arm and a client's
  /// own [`begin`](Connection::begin) write a dead value, and every reader is
  /// already behind the guard that makes the field meaningful — a live
  /// handshake with `connect` false. See [`Exchange::head_digest`], whose value
  /// this is on the transitioned path, for the whole of that reasoning.
  ///
  /// [`Exchange::head_digest`]: super::Exchange::head_digest
  head_digest: u64,
}

#[cfg(test)]
impl Handshake {
  /// A handshake value for tests that need the PHASE rather than its contents —
  /// `transport`'s projection reads which variant the phase is and nothing
  /// inside it.
  pub(crate) const fn for_test() -> Self {
    Self {
      connect: false,
      interim_owed: false,
      version: Version::Http11,
      head_digest: 0,
    }
  }
}

/// How a caller-supplied head stands to the request a tunnel connection is
/// holding — what [`head_binding`](Connection::head_binding) answers.
///
/// The question exists because a layer above this one may be handed a head that
/// a DIFFERENT object read: a server that speaks ordinary HTTP first reads the
/// request on a [`General`] connection, keeps the head, and takes the mode edge
/// — so the head and the connection reach that layer as two separate values,
/// and pairing the wrong two is a mistake no signature can refuse. This is the
/// fact that lets it be refused at runtime instead.
///
/// Three values rather than a `bool`, because neither `bool` can be written
/// correctly: "no" for a connection that classified nothing would refuse
/// pre-validating a head against a THROWAWAY [`Connection::new`], which is the
/// recipe [`into_tunnel`](Connection::into_tunnel) documents and the only way to
/// validate before spending a one-way transition; "yes" for that same
/// connection would make a CONNECT-armed one answer vacuously, which is the
/// crossing this type exists to catch.
///
/// [`General`]: super::General
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HeadBinding {
  /// A live upgrade handshake, and `head` is the head that armed it.
  ///
  /// Digest equality, not byte equality — see
  /// [`head_binding`](Connection::head_binding) for what that does and does not
  /// claim.
  Matches,
  /// A live handshake that `head` did not arm — a different upgrade request, or
  /// a CONNECT, which no `Upgrade` offer produced.
  ///
  /// A CONNECT-armed connection answers this for EVERY head, its own included:
  /// the question is about the RFC 9110 §7.8 upgrade offer, and a CONNECT made
  /// none. A layer that answers §7.8 upgrades therefore has nothing here it can
  /// answer, whatever head it was handed.
  Mismatch,
  /// No handshake is in flight, so there is no armed request `head` could
  /// contradict.
  ///
  /// A fresh [`Connection::new`] answers this, which is what keeps the
  /// pre-validation recipe working, and so does a connection whose handshake is
  /// over. A connection whose lifecycle has FAILED answers it too, on the
  /// belt-and-braces [`owes_continue`](Connection::owes_continue) already uses:
  /// a failed connection with a live handshake is unreachable today, and a
  /// coincidence between today's writers is not a rule this type enforces.
  NoHandshake,
}

// `Ro` is free: nothing in this block — `live_phase`, `idle`, `handshake`,
// `head_end`, `handle_eof`, `fail` — reads `Role::IS_CLIENT`. A tunnel
// connection has no exchange and no receive/send FSM to tell a client and a
// server apart on (see the module doc); General's `handle_eof` is the one
// place that abandons a client's send side, and Tunnel's own `handle_eof`
// deliberately has no such line.
impl<Ro> Connection<Ro, Tunnel> {
  /// The phase, or the latch that has replaced it.
  ///
  /// A violation is handed back exactly once, by the call that found it; every
  /// call after that is caller-side misuse, exactly as in General mode.
  fn live_phase(&self) -> Result<TunnelPhase, Error> {
    if matches!(self.lifecycle, Lifecycle::Failed) {
      return Err(Error::InvalidState(FAILED));
    }
    Ok(self.tunnel)
  }

  /// Checks that no handshake has begun — the state the two `open` calls and the
  /// server's `handle_request` need.
  fn idle(&self) -> Result<(), Error> {
    match self.live_phase()? {
      TunnelPhase::Idle => Ok(()),
      _ => Err(Error::InvalidState(ONE_HANDSHAKE)),
    }
  }

  /// The handshake in flight, or the reason there is none.
  fn handshake(&self) -> Result<Handshake, Error> {
    match self.live_phase()? {
      TunnelPhase::Handshaking(handshake) => Ok(handshake),
      _ => Err(Error::InvalidState(NO_HANDSHAKE)),
    }
  }

  /// Delimits the head at the front of `input`, or reports that it has not all
  /// arrived.
  ///
  /// The General path's scanner over the General path's watermark, which is the
  /// one field a tunnel shares with it: repeated feeds over a growing buffer stay
  /// linear in total, and a head that has not terminated leaves `input` entirely
  /// to the caller. The watermark is cleared as soon as a head
  /// completes, because it belongs to ONE head — which is what lets a client scan
  /// the head after an interim response from its own first byte.
  fn head_end(&mut self, input: &[u8]) -> Result<Option<usize>, H1Error> {
    match find_head_end(input, self.watermark) {
      Ok(Some(end)) => {
        self.watermark = 0;
        Ok(Some(end))
      }
      Ok(None) => {
        // `max` rather than assignment, exactly as the General path does it: the
        // watermark is progress through ONE head and may never go backwards, so
        // an offer shorter than the last one cannot make the next scan restart
        // over bytes it has already looked at.
        self.watermark = self.watermark.max(input.len());
        Ok(None)
      }
      Err(error) => Err(error),
    }
  }

  /// Reports that the transport's read side has ended, so no further byte can
  /// arrive on this connection.
  ///
  /// Without it a Tunnel connection had no end-of-file operation at all —
  /// `Connection::handle_eof` is General mode's — so a driver holding a closed
  /// transport and a partial handshake response got `NeedMore` for ever and
  /// could never terminate the handshake.
  ///
  /// # WHAT this call decides, and what it leaves to the two `handle` calls
  ///
  /// One thing: the transport fact, latched. It is the same epistemic split the
  /// General path is built on, and for the same reason — the connection cannot
  /// see the DRIVER's buffer, so "the response was truncated" is not something
  /// this call knows. The octets that would complete the head may be sitting
  /// unoffered. Every conclusion that depends on the ABSENCE of further bytes is
  /// therefore drawn by [`handle_response`](Connection::handle_response) or
  /// [`handle_request`](Connection::handle_request), on the offer that runs out
  /// — which is exactly where `connection::inbound::no_more_input` draws
  /// General's.
  ///
  /// | Ordering | Result |
  /// |---|---|
  /// | EOF while idle — a client has not written its request, a server has read none | `read_closed`, and nothing else: no handshake was in flight to end |
  /// | EOF, then `handle_response` with a partial head | RFC 9112 §2.1: `CLOSED_MID_HEAD`, latched |
  /// | EOF, then `handle_response` with nothing buffered | RFC 9112 §9.5 with RFC 9110 §15.2: `CLOSED_BEFORE_RESPONSE`, latched — interim heads are not the answer, so this is the verdict after one too |
  /// | EOF, then `handle_request` with a partial head | `CLOSED_MID_HEAD`, latched, and NO rejection owed — the same call General makes, for the same reason: a 400 describing a request nobody finished sending answers no message |
  /// | EOF, then `handle_request` with nothing buffered | [`ServerTunnelRequest::Closed`]: the peer closed at a boundary, which is a clean ending and not a fault |
  /// | EOF while a rejection is owed | `read_closed`; the obligation stands and [`reject`](Connection::reject) still writes it |
  /// | EOF after the switch | `read_closed`; the bytes were the other protocol's already, and this core has nothing to say about their ending |
  /// | The same EOF reported twice | a no-op |
  ///
  /// Nothing here abandons a send, which is the one line General's `handle_eof`
  /// has that this does not need: RFC 9110 §9.3.6 gives CONNECT no content and
  /// every other message this mode writes is its head, so there is never an
  /// unwritten body for the peer's close to strand.
  ///
  /// Idempotent: a driver may report the same EOF twice.
  pub fn handle_eof(&mut self) -> Result<(), Error> {
    if matches!(self.lifecycle, Lifecycle::Failed) {
      return Err(Error::InvalidState(FAILED));
    }
    // INERT after a switch, not invalid — and the difference from General's
    // `handle_eof`, which answers `SWITCHED`, is deliberate rather than an
    // oversight. This mode's own contract for the case is already stated and
    // tested: "a connection that has left HTTP has nothing to say about the
    // ending", because the bytes were the other protocol's already. Refusing
    // would be a different API decision, and it is not this invariant's to make.
    //
    // What the invariant DOES require is that nothing happens here: latching
    // `read_closed` would rewrite a spent connection's state, and
    // `Connection::transport` reads that flag — so a spent connection could be
    // made to report on a transport it no longer owns. `HandedOver` is absorbing
    // and would win anyway; the call returns before the write regardless, since
    // rewriting a spent object is wrong even when nothing reads the difference.
    if matches!(self.tunnel, TunnelPhase::Switched) {
      return Ok(());
    }
    // Through the same routine General's goes through, so the transport fact has
    // ONE writer whatever mode the connection is in. What it means for the
    // driver is not decided here: `Connection::transport` reads this flag beside
    // the lifecycle and the phase, on the ask.
    latch_read_closed(&mut self.read_closed);
    Ok(())
  }

  /// Latches the connection on a wire violation and turns it into the error the
  /// call hands back.
  ///
  /// No `SendState` and no error-response bookkeeping: those are the General
  /// FSM's, and a tunnel's own single-answer rule lives in
  /// [`TunnelPhase::RejectionOwed`] instead.
  fn fail(&mut self, error: H1Error) -> Error {
    self.lifecycle = Lifecycle::Failed;
    Error::Protocol(error)
  }
}

impl Connection<Client, Tunnel> {
  /// The two conditions a handshake this end OPENS needs: no handshake has begun,
  /// and the transport can still bring an answer back.
  ///
  /// The second is General's [`READ_SIDE_ENDED`] rule, which the Tunnel EOF path
  /// did not inherit when it was added: `handle_eof` latched `read_closed` and
  /// the two openers went on checking only the phase, so a request was encoded
  /// and the handshake advanced although no response could ever arrive. The
  /// driver was left holding a written request and a phase that could never
  /// leave `Handshaking`.
  ///
  /// General's constant is reused rather than twinned because its wording is
  /// exactly this fact — "the connection can no longer receive a response" — and
  /// a handshake response is a response. One rule with one name in both modes is
  /// also what makes the two answers comparable to a driver that switches modes.
  ///
  /// Asked BEFORE the caller's headers are walked and before a byte is measured,
  /// so a refusal leaves the output buffer and the phase exactly as they were.
  fn openable(&self) -> Result<(), Error> {
    self.idle()?;
    if self.read_closed {
      return Err(Error::InvalidState(READ_SIDE_ENDED));
    }
    Ok(())
  }

  /// Encodes the RFC 9110 §7.8 upgrade request into `out` and begins the
  /// handshake, returning the bytes written.
  ///
  /// A GET, with the caller's fields. What this core checks is §7.8's own rule
  /// about the OFFER: "A sender of Upgrade MUST also send an `Upgrade`
  /// connection option in the Connection header field", and each protocol named
  /// is `protocol-name ["/" protocol-version]` — because an offer missing either
  /// half asks for a switch no conformant server will make. WHICH protocol is
  /// offered is the caller's field, and so is everything a specific handshake
  /// adds (a WebSocket key, a version, an extension list): they are ordinary
  /// fields to this core.
  ///
  /// The target takes RFC 9112 §3.2.1's origin-form or §3.2.2's absolute-form;
  /// §3.2.3's authority-form belongs to CONNECT and §3.2.4's asterisk-form to a
  /// server-wide OPTIONS, so neither addresses a resource this request could be
  /// answered for.
  ///
  /// The request is bodiless: this core has no body machinery in Tunnel mode, so
  /// a head announcing octets it will not write would leave the peer waiting for
  /// them (RFC 9112 §6.3 item 6). `Content-Length: 0` states exactly what this
  /// call does and is allowed.
  ///
  /// `headers` MUST satisfy RFC 9112 §3.2's three `Host` MUSTs, exactly as in
  /// General mode's [`open_request`](Connection::open_request): exactly one
  /// field line, whose value is a valid authority or EMPTY. §3.2's client MUST
  /// is unconditional over HTTP/1.1 requests and this is one, and the other two
  /// rules are unqualified by version at all. An empty value is the field §3.2
  /// asks for when the target authority is undefined; which authority a non-empty
  /// one names is the caller's, since only it holds the target URI.
  pub fn open_upgrade<H: Headers + ?Sized>(
    &mut self,
    target: &Target<'_>,
    headers: &H,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    self.openable()?;
    if matches!(target, Target::Authority { .. } | Target::Asterisk) {
      return Err(Error::InvalidState(SWITCH_TARGET_FORM));
    }
    let declared = declared(headers)?;
    requires_host(&declared)?;
    no_content(&declared)?;
    continue_needs_content(&declared, false)?;
    if !declared.offers_a_protocol() {
      return Err(Error::InvalidState(OFFER_NEEDS_BOTH_HALVES));
    }
    // The one-takeover-no-close invariant, originate corner — see
    // [`TunnelPhase::Switched`]. Offering a switch onto a connection this end has
    // just said it is ending asks for a 101 this connection's OWN receive path
    // refuses.
    if declared.close {
      return Err(Error::InvalidState(TAKEOVER_STATES_NO_CLOSE));
    }

    let written = encode_request_head(GET, target, headers, declared.digest, out)?;
    // Committed: the request is in the caller's buffer, so the handshake it
    // opened exists from here on.
    self.begin(false);
    Ok(written)
  }

  /// Encodes the RFC 9110 §9.3.6 CONNECT request into `out` and begins the
  /// handshake, returning the bytes written.
  ///
  /// `host_port` is the RFC 9112 §3.2.3 `authority-form = uri-host ":" port`
  /// target, and the port is not optional: "There is no default port; a client
  /// MUST send the port number even if the CONNECT request is based on a URI
  /// reference that contains an authority component with an elided port"
  /// (§9.3.6), whose server half is a MUST to reject one without it. The host
  /// itself is validated by the same §3.2 grammar the receive side parses a
  /// target with.
  ///
  /// Bodiless, and here that is the specification's own words: "A CONNECT
  /// request message does not have content."
  ///
  /// `headers` MUST NOT carry an `Upgrade` field. A CONNECT already states RFC
  /// 9110 §9.3.6's takeover, and §7.8's field would invite a second one this
  /// handshake has no answer for: [`ClientTunnelOutcome`] represents a CONNECT's
  /// success as the 2xx tunnel, and a `101` — which a server may legally send
  /// once a protocol has been "indicated by the client in the corresponding
  /// request's Upgrade header field" — is condemned by
  /// [`handle_response`](Self::handle_response) on arrival. Refused before
  /// encoding rather than left to become that contradiction.
  ///
  /// `headers` MUST satisfy RFC 9112 §3.2's three `Host` MUSTs — one field line,
  /// valid authority or empty — exactly as the other two outbound request paths
  /// do. §3.2.3 gives CONNECT an authority-form target, which is not an
  /// exemption: §3.2's client MUST is stated over "all HTTP/1.1 request
  /// messages", and RFC 9110 §7.2 wants the authority in a field as well as in
  /// the target so an intermediary that rewrites one still forwards the other.
  pub fn open_connect<H: Headers + ?Sized>(
    &mut self,
    host_port: &str,
    headers: &H,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    self.openable()?;
    if !states_a_port(host_port) {
      return Err(Error::InvalidState(CONNECT_NEEDS_A_PORT));
    }
    let declared = declared(headers)?;
    requires_host(&declared)?;
    no_content(&declared)?;
    continue_needs_content(&declared, false)?;
    // §7.8's question, asked where `open_upgrade` asks its own — after the three
    // field rules both openers share — so the two sibling paths decide the same
    // thing at the same point. `open_upgrade` REQUIRES the offer here; this one
    // refuses it, because a CONNECT already states §9.3.6's takeover and this
    // mode has no answer that could carry §7.8's.
    if declared.indicates_a_protocol() {
      return Err(Error::InvalidState(CONNECT_INDICATES_NO_PROTOCOL));
    }
    // The one-takeover-no-close invariant, originate corner — see
    // [`TunnelPhase::Switched`]. RFC 9112 §9.6 makes this end close after the
    // message carrying the option, and RFC 9110 §9.3.6 makes a 2xx to this
    // request switch the connection to tunnel mode "immediately after the
    // response header section". Asking for a tunnel while stating that this
    // connection is ending asks for both at the same instant.
    if declared.close {
      return Err(Error::InvalidState(TAKEOVER_STATES_NO_CLOSE));
    }

    let written = encode_request_head(
      CONNECT,
      &Target::Authority { host_port },
      headers,
      declared.digest,
      out,
    )?;
    self.begin(true);
    Ok(written)
  }

  /// Reads the response to the handshake this client opened.
  ///
  /// `input` is the driver's buffer from its unconsumed start, and the outcome
  /// says what to do with it — see the module doc for the leftover contract. A
  /// head that has not all arrived is [`ClientTunnelOutcome::NeedMore`] and
  /// consumes nothing.
  ///
  /// The four answers, in the order the RFCs decide them:
  ///
  /// - `101` to an upgrade offer: RFC 9110 §15.2.2's switch. The head must state
  ///   both halves of §7.8 — the `upgrade` connection option and an `Upgrade`
  ///   field naming the protocol — and a 101 that does not is a protocol
  ///   violation that latches the connection, because every byte behind it would
  ///   be read under a protocol nobody named. Whether the protocol it names is
  ///   the one that was OFFERED is the caller's check: only the caller knows the
  ///   offer, and [`Switched`](ClientTunnelOutcome::Switched) hands it the head.
  /// - `101` to a CONNECT: §7.8 makes a server switching to a protocol "not
  ///   indicated by the client" a MUST NOT, and a CONNECT indicates none — a
  ///   violation. That a CONNECT indicates none is enforced rather than assumed:
  ///   [`open_connect`](Self::open_connect) refuses a section carrying an
  ///   `Upgrade` field, so this verdict cannot be reached against a server that
  ///   acted on a field this end wrote.
  /// - Any 2xx to a CONNECT: §9.3.6's tunnel.
  /// - Any other 1xx: §15.2's interim response. The head is consumed and the
  ///   handshake stays open.
  /// - Anything else: refused, and terminal.
  ///
  /// The framing fields of the response are not read. On a 101 and on a 2xx to
  /// CONNECT there is no body to frame — §9.3.6 makes ignoring them a client
  /// MUST — and on a refusal this core does not frame one, though it does report
  /// where it starts (module doc).
  pub fn handle_response<'a>(&mut self, input: &'a [u8]) -> Result<ClientTunnelOutcome<'a>, Error> {
    let handshake = self.handshake()?;
    let end = match self.head_end(input) {
      Ok(Some(end)) => end,
      // The head has not all arrived — which means "ask again after a read" only
      // while a read can still produce something. With the transport's read side
      // ended, this offer is everything the server will ever say, and which
      // ending it is depends on how far the head got. See `handle_eof`'s table.
      Ok(None) if self.read_closed => {
        // RFC 9112 §2.1: a head that never terminated is a message the peer
        // stopped mid-sentence. Asked first, because it is the sharper
        // diagnosis — the server did start a response.
        let error = if self.watermark > 0 {
          CLOSED_MID_HEAD
        } else {
          // RFC 9112 §9.5 with RFC 9110 §15.2: the request went out and no FINAL
          // response came back. Interim heads do not count as one, and the
          // watermark is cleared by each head that completes, so this is the
          // verdict after any number of them.
          CLOSED_BEFORE_RESPONSE
        };
        return Err(self.fail(H1Error::Framing(error)));
      }
      Ok(None) => return Ok(ClientTunnelOutcome::NeedMore),
      Err(error) => return Err(self.fail(error)),
    };
    let head = input.get(..end).unwrap_or_default();
    let leftover = input.get(end..).unwrap_or_default();

    let view = match scan_head(head) {
      Ok(view) => view,
      Err(error) => return Err(self.fail(error)),
    };
    let status = match parse_status_line(view.start_line_bytes()) {
      Ok(status) => status,
      Err(error) => return Err(self.fail(error)),
    };
    // Every condemnation of the head, from the SAME check General mode applies.
    // A head is a fault or it is not; which mode is reading it cannot change
    // that, and two recipients disagreeing about the same bytes is what RFC 9112
    // §11.1 is. A Tunnel deciding alone would accept heads General fails — an
    // `HTTP/1.0` response carrying `Transfer-Encoding` (§6.1) among them — after
    // which the connection goes on being parsed as a live handshake.
    //
    // `req_method_head` is false by construction: this mode writes GET or
    // CONNECT and never HEAD. `req_connect` comes from the handshake, so §6.3
    // item 2's exemption for a 2xx to CONNECT applies here exactly as it does in
    // General mode.
    //
    // What is NOT taken from there is the framing DECISION: Tunnel frames no
    // bodies, and every message it reads is its head.
    if let Err(error) = check_response_head(&status, &view, false, handshake.connect) {
      return Err(self.fail(error));
    }

    match (status.code, handshake.connect) {
      (SWITCHING_PROTOCOLS, false) => {
        // RFC 9112 §9.6, asked of the head IN HAND: a peer that ends the
        // connection's persistence in the very response that would switch has
        // committed to closing, so it has nothing to continue INTO. The interim
        // arm below asks the same question, and BOTH must: the mode that OWNS
        // the handshake switching on a head General's own gate refuses is the
        // recipient disagreement §11.1 is about.
        //
        // Same predicate, same constant, same disposition as
        // `inbound::switch_or_fault` step 3: one rule about one fact. The accept
        // corner of the one-takeover-no-close invariant — see
        // [`TunnelPhase::Switched`] for every corner and its verdict.
        //
        // `has_close_option`, NOT `ends_persistence` — the names are the
        // distinction: §9.3's HTTP/1.0 default asks whether another HTTP MESSAGE
        // may follow, and a 101 ends HTTP framing, so there is none for it to
        // govern. A 1.0 101 that carries no `close` has STATED nothing, which is
        // what this constant's message says.
        if has_close_option(&view) {
          return Err(self.fail(H1Error::Framing(SWITCH_AFTER_CLOSE)));
        }
        if !names_a_protocol(&view) {
          return Err(self.fail(H1Error::Framing(SWITCH_NEEDS_BOTH_HALVES)));
        }
        // The transport is the driver's from here, and writing the phase IS
        // saying so: `Connection::transport` reads `Switched` as
        // `Transport::HandedOver`, absorbing and ahead of every other arm. So
        // there is no cancel routine to call and no cancel site to keep in
        // step.
        self.tunnel = TunnelPhase::Switched;
        Ok(ClientTunnelOutcome::Switched {
          head: view,
          leftover,
        })
      }
      (SWITCHING_PROTOCOLS, true) => Err(self.fail(H1Error::Framing(SWITCH_WAS_NEVER_OFFERED))),
      // RFC 9110 §15.2, and it is checked before the CONNECT rule below because a
      // 1xx is never the final response that forms the tunnel.
      (100..=199, _) => {
        // …but a 1xx that ENDS THE CONNECTION'S PERSISTENCE ends the handshake
        // rather than continuing it. §9.6 makes a sender of the `close` option
        // close "after it sends the response containing" it, and a 1xx is a
        // response message — so this peer has committed to closing, and the 101
        // or the CONNECT 2xx that would switch is not a legal continuation.
        // Reported as the terminal refusal it is, so a driver cannot go on
        // waiting for a switch that may not come.
        //
        // Asked through `validate::ends_persistence`, which is the SAME
        // predicate General mode's directives are built from — not a copy of the
        // expression. Reading `KeyFields::connection_close` directly answered
        // only half of it: §9.3 also makes an HTTP/1.0 message non-persistent
        // unless it carries `keep-alive`, so an `HTTP/1.0 100` without one left
        // the handshake looking live on a connection that was already over.
        if ends_persistence(status.version, &view) {
          self.tunnel = TunnelPhase::Refused;
          return Ok(ClientTunnelOutcome::Refused {
            head: view,
            status,
            leftover,
          });
        }
        Ok(ClientTunnelOutcome::Interim {
          head: view,
          status,
          leftover,
        })
      }
      (200..=299, true) => {
        // The one-takeover-no-close invariant, accept corner, asked of the head
        // in hand exactly as the 101 arm asks it — see [`TunnelPhase::Switched`].
        //
        // RFC 9112 §9.6 obliges a client that receives the option to "close the
        // connection after reading the response message containing" it; RFC 9110
        // §9.3.6 makes this response switch the connection to tunnel mode
        // "immediately after the response header section". The two clauses name
        // the same instant and demand opposite things, so a 2xx carrying `close`
        // is not a tunnel this end can enter — it is a self-contradiction, and
        // the same fault the 101 arm reports, under the same constant.
        //
        // THE STATED OPTION ONLY. Reading §9.3's HTTP/1.0 default here refuses
        // `HTTP/1.0 200 Connection Established` — a legal answer to an HTTP/1.1
        // CONNECT, and the classic form real proxies send — and throws away the
        // tunnel bytes that follow it in the same read. §9.3.6 establishes the
        // tunnel immediately after the header section whatever version the
        // response states, and the request side already treats HTTP persistence
        // as moot after a CONNECT; applying the opposite rule here would be an
        // asymmetry between the two.
        if has_close_option(&view) {
          return Err(self.fail(H1Error::Framing(SWITCH_AFTER_CLOSE)));
        }
        self.tunnel = TunnelPhase::Switched;
        Ok(ClientTunnelOutcome::Tunneled {
          head: view,
          status,
          leftover,
        })
      }
      _ => {
        self.tunnel = TunnelPhase::Refused;
        Ok(ClientTunnelOutcome::Refused {
          head: view,
          status,
          leftover,
        })
      }
    }
  }

  /// Records the handshake a written request opened.
  fn begin(&mut self, connect: bool) {
    self.tunnel = TunnelPhase::Handshaking(Handshake {
      connect,
      // A client owes no interim response; the ordering MUST is the server's.
      interim_owed: false,
      // What `head::encode` just wrote (RFC 9112 §2.3).
      version: Version::Http11,
      // A dead value: `head_binding` is a server-side question about a head
      // somebody else read, and this end wrote its own request. See
      // `Handshake::head_digest`.
      head_digest: 0,
    });
  }
}

impl Connection<Server, Tunnel> {
  /// Classifies the request this tunnel connection was opened for.
  ///
  /// `input` is the driver's buffer from its unconsumed start; a head that has
  /// not all arrived is [`ServerTunnelRequest::NeedMore`] and consumes nothing.
  /// RFC 9112 §2.2's leading empty lines are skipped as they are for a General
  /// server, and the same bound applies.
  ///
  /// Two shapes classify, and both are checked with the receive side's own
  /// validation (RFC 9112 §3.2's `Host` rules and the §3.2.3/§3.2.4 target-method
  /// pairing among them):
  ///
  /// - A CONNECT, whose §3.2.3 authority-form target states a port — RFC 9110
  ///   §9.3.6: "A server MUST reject a CONNECT request that targets an empty or
  ///   invalid port number".
  /// - A request stating both halves of an RFC 9110 §7.8 upgrade offer. The
  ///   METHOD is not constrained: §7.8 makes the offer a property of the fields
  ///   and names OPTIONS explicitly ("an OPTIONS request can be honored by any
  ///   protocol"), so a WebSocket handshake's GET-only rule belongs to the layer
  ///   that knows it is a WebSocket handshake. An HTTP/1.0 request never
  ///   classifies: §7.8 makes ignoring its `Upgrade` field a MUST, which leaves
  ///   an ordinary 1.0 request.
  ///
  /// Neither shape carries content — RFC 9110 §9.3.6 says so for CONNECT, and an
  /// upgrade request with a body would have to be read to its end before the
  /// switch (§7.8: "A client cannot begin using an upgraded protocol on the
  /// connection until it has completely sent the request message"), which is
  /// body machinery a tunnel does not have.
  ///
  /// Anything else is a request this connection cannot serve. It latches like
  /// any other violation, and leaves the server owing exactly one answer, which
  /// [`reject`](Self::reject) writes.
  pub fn handle_request<'a>(&mut self, input: &'a [u8]) -> Result<ServerTunnelRequest<'a>, Error> {
    self.idle()?;
    // The bytes are NOT consumed here: they go out with the head they precede,
    // so the bound stays cumulative over a head that has not terminated.
    let skip = match skip_leading_empty_lines(input) {
      Ok(skip) => skip,
      Err(error) => return Err(self.refuse(error)),
    };
    let region = input.get(skip..).unwrap_or_default();
    let end = match self.head_end(region) {
      Ok(Some(end)) => end,
      Ok(None) if self.read_closed => {
        if self.watermark == 0 {
          // A boundary with nothing behind it: the client closed without asking
          // for a handshake. Not a fault, and nothing is owed — the §9.2 stray
          // empty lines `skip` covers are discardable, so a peer that sent only
          // those ended just as cleanly.
          return Ok(ServerTunnelRequest::Closed);
        }
        // gate-exempt: answerable = false — a Rust flag value, not RFC 9112 grammar
        // RFC 9112 §2.1 again, and through `fail` rather than `refuse`: a
        // truncated request creates NO answer to owe. That is the same call
        // General's `truncated` makes with `answerable = false`, and for the
        // reason stated there — a 400 describing a request nobody finished
        // sending answers no message. An obligation this connection ALREADY had
        // is untouched, because a phase owing one never reaches this call.
        return Err(self.fail(H1Error::Framing(CLOSED_MID_HEAD)));
      }
      Ok(None) => return Ok(ServerTunnelRequest::NeedMore),
      Err(error) => return Err(self.refuse(error)),
    };
    let head = region.get(..end).unwrap_or_default();
    let leftover = region.get(end..).unwrap_or_default();

    let (view, request, handshake) = match classify(head) {
      Ok(classified) => classified,
      Err(error) => return Err(self.refuse(error)),
    };
    self.tunnel = TunnelPhase::Handshaking(handshake);
    Ok(if handshake.connect {
      ServerTunnelRequest::Connect {
        head: view,
        request,
        leftover,
      }
    } else {
      ServerTunnelRequest::Upgrade {
        head: view,
        request,
        leftover,
      }
    })
  }

  /// Whether RFC 9110 §7.8's ordering MUST is still outstanding: the classified
  /// request carried `Expect: 100-continue` beside its `Upgrade`, so a `100
  /// (Continue)` has to go out before the 101 and [`accept`](Self::accept)
  /// refuses the switch until [`send_interim`](Self::send_interim) has sent one.
  ///
  /// A driver that could not ask would parse `Expect` itself to find out. That
  /// rule is this core's, answered here from the head this connection already
  /// classified, and a second implementation of it would be free to disagree
  /// with the gate that actually refuses the switch.
  ///
  /// `false` for a handshake that never owed one, once a 100 has discharged it,
  /// and in every phase that is not a live handshake — before classification,
  /// after the switch, and on a connection whose remaining answer is a rejection.
  pub const fn owes_continue(&self) -> bool {
    match self.tunnel {
      // A FAILED connection is excluded on the same terms `live_phase` sets: its
      // one remaining answer is the rejection, so there is no 101 left for a 100
      // to be ordered before. Belt-and-braces, as at `reject`'s own phase match —
      // classification failure moves the phase to `RejectionOwed`, and no call
      // reachable from a live handshake latches.
      TunnelPhase::Handshaking(handshake) => {
        handshake.interim_owed && !matches!(self.lifecycle, Lifecycle::Failed)
      }
      TunnelPhase::Idle
      | TunnelPhase::Switched
      | TunnelPhase::Refused
      | TunnelPhase::RejectionOwed => false,
    }
  }

  /// Whether `head` is the head that armed the handshake this connection is
  /// holding — the identity the type system cannot state, answered at runtime.
  ///
  /// A layer that answers RFC 9110 §7.8 upgrades on a connection it did not
  /// read the request on holds two values per exchange, the head and the
  /// connection, and nothing in either one's type says they belong together. A
  /// lifetime cannot say it: [`into_tunnel`](Connection::into_tunnel) CONSUMES
  /// the connection a brand would be tied to, while the head borrows the
  /// driver's buffer and outlives it. [`ExchangeId`](crate::ExchangeId) cannot
  /// say it either — the transition resets the counter to 1, by design. So the
  /// connection keeps a digest of the block instead, and this is the question it
  /// answers.
  ///
  /// # What this claims, and what it does not
  ///
  /// [`Matches`](HeadBinding::Matches) is DIGEST equality, so it is a
  /// probabilistic answer and it is worth being exact about which direction the
  /// guarantee runs in. Against an accidental mispairing — an application
  /// holding two heads and passing the wrong one — the miss probability is
  /// 2⁻⁶⁴ per event. Against ADVERSARIALLY shaped traffic it detects nothing:
  /// head content is peer-controlled and arbitrary field lines are free padding,
  /// and the FNV-1a digest behind this answer is invertible per byte-step, so a
  /// colliding pair is constructible offline. It is therefore a caller-error
  /// check and not a security boundary, and a caller that can let the connection
  /// read its own head ([`handle_request`](Self::handle_request)) should still
  /// do that instead.
  ///
  /// Nor does it defend against a head from a DIFFERENT connection that happens
  /// to be byte-identical — that case answers a request with facts identical to
  /// its own.
  pub fn head_binding(&self, head: &HeadView<'_>) -> HeadBinding {
    // A FAILED connection is excluded on the terms `live_phase` sets and
    // `owes_continue` restates, and on the same belt-and-braces footing: its one
    // remaining answer is the rejection, so there is no switch left for a head
    // to be bound to.
    if matches!(self.lifecycle, Lifecycle::Failed) {
      return HeadBinding::NoHandshake;
    }
    match self.tunnel {
      // RFC 9110 §9.3.6's takeover made no §7.8 offer, so no head is the head
      // that offered one — its own included. The digest is not read on this arm
      // at all, which is what lets a CONNECT write a dead one.
      TunnelPhase::Handshaking(handshake) if handshake.connect => HeadBinding::Mismatch,
      TunnelPhase::Handshaking(handshake) => {
        if head_digest(head.block()) == handshake.head_digest {
          HeadBinding::Matches
        } else {
          HeadBinding::Mismatch
        }
      }
      TunnelPhase::Idle
      | TunnelPhase::Switched
      | TunnelPhase::Refused
      | TunnelPhase::RejectionOwed => HeadBinding::NoHandshake,
    }
  }

  /// Encodes an interim (1xx) response into `out`, returning the bytes written.
  ///
  /// RFC 9110 §15.2 lets any number of them precede the final answer, and none
  /// of them ends the handshake. The one this core is strict about is the `100
  /// (Continue)` §7.8 requires: "If a server receives both an Upgrade and an
  /// Expect header field with the `100-continue` expectation, the server MUST
  /// send a 100 (Continue) response before sending a 101 (Switching Protocols)
  /// response" — sending it here is what discharges that order, and
  /// [`accept`](Self::accept) refuses the switch until it has been.
  ///
  /// `101` is REFUSED: it is not something said while the handshake is being
  /// decided, it IS the decision, and it goes through [`accept`](Self::accept).
  /// A final status is refused for the mirror reason.
  ///
  /// An HTTP/1.0 request gets no interim response at all (§15.2: "Since HTTP/1.0
  /// did not define any 1xx status codes, a server MUST NOT send a 1xx response
  /// to an HTTP/1.0 client"), no framing field belongs in one (RFC 9112 §6.1,
  /// RFC 9110 §8.6), and neither does `Connection: close` — §9.6 binds that
  /// option to the response carrying it, which would end the connection under
  /// the handshake this call is still deciding.
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
    let handshake = self.handshake()?;
    if code == SWITCHING_PROTOCOLS {
      return Err(Error::InvalidState(SWITCH_THROUGH_ACCEPT));
    }
    if !matches!(code, 100..=199) {
      return Err(Error::InvalidState(NOT_INTERIM));
    }
    if matches!(handshake.version, Version::Http10) {
      return Err(Error::InvalidState(INTERIM_NEEDS_HTTP_11));
    }
    let declared = declared(headers)?;
    if declared.transfer_encoding > 0 || declared.content_length_lines > 0 {
      return Err(Error::InvalidState(INTERIM_HAS_NO_FRAMING));
    }
    // RFC 9112 §9.6 binds the option to the response CARRYING it, and a 1xx is a
    // response message — so an interim stating `close` would commit this end to
    // closing before the switch it is still deciding. The identical rule General
    // mode's `send_interim` applies, in the identical words.
    if declared.close {
      return Err(Error::InvalidState(INTERIM_STATES_NO_CLOSE));
    }

    let written = encode_status_head(code, b"", headers, declared.digest, out)?;
    // Committed. The handshake does not move — an interim response is a fact
    // about one still being decided — except that a 100 discharges §7.8's order.
    if code == CONTINUE {
      self.tunnel = TunnelPhase::Handshaking(Handshake {
        interim_owed: false,
        ..handshake
      });
    }
    Ok(written)
  }

  /// Encodes the response that makes the switch into `out`, returning the bytes
  /// written.
  ///
  /// WHICH response is decided by the request that was classified, not by an
  /// argument: RFC 9110 §15.2.2's `101 Switching Protocols` for an upgrade offer,
  /// and §9.3.6's `200 Connection Established` for a CONNECT. A caller that wants
  /// to answer anything else is refusing the handshake, which is
  /// [`reject`](Self::reject).
  ///
  /// For the 101 the head must state both halves of §7.8 — §15.2.2 makes the
  /// `Upgrade` field a MUST ("The server MUST generate an Upgrade header field
  /// in the response that indicates which protocol(s) will be in effect after
  /// this response") and §7.8 requires the connection option beside it. THAT the
  /// protocol named is one the client offered is the caller's check, for the
  /// same reason it is on the client side: only the caller read the offer.
  ///
  /// Neither response carries a framing field, not even `Content-Length: 0`: RFC
  /// 9112 §6.1 and RFC 9110 §8.6 forbid both in a 1xx, and §9.3.6 forbids both in
  /// a 2xx to CONNECT. What follows the head is not a body.
  ///
  /// TERMINAL. The bytes after this head are the next protocol's, so every
  /// further call on this connection is [`Error::InvalidState`] — including
  /// another `accept`.
  pub fn accept<H: Headers + ?Sized>(
    &mut self,
    headers: &H,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    let handshake = self.handshake()?;
    // The ordering MUST, checked before anything is written or validated: it is
    // a fact about the conversation rather than about this head.
    if handshake.interim_owed {
      return Err(Error::InvalidState(CONTINUE_BEFORE_SWITCH));
    }
    let declared = declared(headers)?;
    if declared.transfer_encoding > 0 || declared.content_length_lines > 0 {
      return Err(Error::InvalidState(SWITCH_HAS_NO_FRAMING));
    }

    // The one-takeover-no-close invariant, emit corner, on BOTH branches — see
    // [`TunnelPhase::Switched`]. §9.6 makes a server that sends the option close
    // after the response carrying it, so a takeover response stating `close`
    // promises to end the connection it is handing over. That is as true of
    // §9.3.6's 2xx as of §7.8's 101: "immediately after the response header
    // section" and "after reading the response message containing the close
    // connection option" name the same instant and demand opposite things.
    if declared.close {
      return Err(Error::InvalidState(TAKEOVER_STATES_NO_CLOSE));
    }
    let written = if handshake.connect {
      encode_status_head(
        CONNECTION_ESTABLISHED,
        ESTABLISHED_REASON,
        headers,
        declared.digest,
        out,
      )?
    } else {
      if !declared.offers_a_protocol() {
        return Err(Error::InvalidState(SWITCH_NEEDS_BOTH_HALVES));
      }
      encode_status_head(
        SWITCHING_PROTOCOLS,
        SWITCHING_REASON,
        headers,
        declared.digest,
        out,
      )?
    };
    // Committed: the head is in the caller's buffer, so the connection is the
    // next protocol's from here on.
    self.tunnel = TunnelPhase::Switched;
    Ok(written)
  }

  /// Encodes the response that ends the handshake WITHOUT switching, returning
  /// the bytes written.
  ///
  /// Two callers, one message. A driver that declines a well-formed handshake
  /// answers its own status — RFC 9110 §15.5.22's `426 (Upgrade Required)` for an
  /// offer it will not take, §15.5.8's 407 for a tunnel it will not open — and a
  /// driver whose connection FAILED spends the single answer such a connection
  /// is left, typically with the code
  /// [`suggested_status`](crate::Error::suggested_status) named. Either way it is
  /// the last message on this connection.
  ///
  /// The head is the whole message: this core writes no body after it, so a
  /// `Content-Length` past zero or a `Transfer-Encoding` would leave the peer
  /// waiting for octets that never come (RFC 9112 §6.3 item 6). With no framing
  /// field at all the response is close-delimited (item 8), which is what the
  /// driver does next — a caller that wants the peer to know before the close
  /// says so with its own `Connection: close` (§9.6).
  ///
  /// A 1xx is refused: an interim response ends nothing, and this call has no
  /// second answer to leave owed. So is EVERY status that would make the switch
  /// instead of refusing it, which is decided by how the PEER would read it
  /// rather than by what this end concluded:
  ///
  /// - the `101`, on any handshake (RFC 9110 §15.2.2);
  /// - the whole 2xx class on a classified CONNECT, since §9.3.6 makes "any 2xx
  ///   (Successful) response" tunnel mode "immediately after the response header
  ///   section";
  /// - the whole 2xx class while a rejection is owed after a FAILED
  ///   classification — the request may have been a CONNECT that this core
  ///   refused for a reason of its own (no port, content), and a client that
  ///   sent one reads a 2xx as the tunnel either way. Independently: a phase
  ///   whose meaning is "a rejection is owed" has no success to state.
  ///
  /// A classified UPGRADE keeps its 2xx: only the 101 switches there, and §7.8
  /// lets a server answer the request ordinarily instead of upgrading.
  ///
  /// Those statuses go through [`accept`](Self::accept), which is the call that
  /// records the switch; written from here they would leave the peer tunnelling
  /// while this end had recorded a refusal, and the two would disagree about
  /// whether the connection is still HTTP.
  ///
  /// TERMINAL, and exactly once.
  pub fn reject<H: Headers + ?Sized>(
    &mut self,
    code: u16,
    reason: &[u8],
    headers: &H,
    out: &mut [u8],
  ) -> Result<usize, Error> {
    // Whether a 2xx written from this phase would be read as the SWITCH rather
    // than as the refusal it is meant to be.
    let switches_on_2xx = match self.tunnel {
      // The single owed answer — and the conservative arm, for two
      // independent reasons.
      //
      // (1) Classification FAILED, so this phase does not know which method
      // arrived; it may well have been a CONNECT this core refused for a reason
      // of its own (no port, RFC 9112 §3.2.3; content, RFC 9110 §9.3.6). What
      // §9.3.6 binds is the PEER's reading: "Any 2xx (Successful) response
      // indicates that the sender … will switch to tunnel mode immediately after
      // the response header section". A client that sent CONNECT reads a 2xx
      // that way whatever this end's classifier concluded.
      //
      // (2) Independently of the method: a phase whose whole meaning is "a
      // rejection is owed" has no success class to state. The blanket costs
      // nothing — a 2xx is not an answer to a request this core could not serve.
      // General mode states reason (2) in the same words at its own rejection
      // site, `send_error_response`'s `NO_SUCCESS_TO_STATE`: one rule, two modes.
      TunnelPhase::RejectionOwed => true,
      // A classified handshake the driver declines. A CONNECT switches on any
      // 2xx; an UPGRADE does not — §7.8 lets "a server … ignore a received
      // Upgrade header field if it wishes to continue using the current
      // protocol", so answering the request ordinarily with a 200 is a legal
      // refusal and stays one. A failed connection never reaches this arm:
      // failing sets `RejectionOwed` above.
      TunnelPhase::Handshaking(handshake) if !matches!(self.lifecycle, Lifecycle::Failed) => {
        handshake.connect
      }
      TunnelPhase::Handshaking(_)
      | TunnelPhase::Idle
      | TunnelPhase::Switched
      | TunnelPhase::Refused => return Err(Error::InvalidState(NOTHING_TO_ANSWER)),
    };
    // The statuses that SWITCH rather than refuse: the 101 on any handshake
    // (RFC 9110 §15.2.2), and the whole 2xx class wherever a 2xx would be read
    // as §9.3.6's tunnel. Spelled as a class rather than as the one code
    // `accept` writes, because it is the RECIPIENT's rule.
    if code == SWITCHING_PROTOCOLS || (switches_on_2xx && matches!(code, 200..=299)) {
      return Err(Error::InvalidState(SWITCH_THROUGH_ACCEPT));
    }
    if matches!(code, 100..=199) {
      return Err(Error::InvalidState(NOT_INTERIM));
    }
    let declared = declared(headers)?;
    no_content(&declared)?;

    let written = encode_status_head(code, reason, headers, declared.digest, out)?;
    // Committed, and spent: the handshake is over either way.
    self.tunnel = TunnelPhase::Refused;
    Ok(written)
  }

  /// Latches on a request this connection cannot serve, leaving the single
  /// answer owed.
  ///
  /// The single-answer rule in a tunnel's shape: the phase records the owed
  /// answer, so [`reject`](Self::reject) stays callable on a failed connection
  /// and nothing else does.
  fn refuse(&mut self, error: H1Error) -> Error {
    self.tunnel = TunnelPhase::RejectionOwed;
    self.fail(error)
  }
}

// `into_tunnel`'s `Err` pairs a whole `Connection` with `TransitionRefused`,
// which is the pair `clippy::result_large_err` measures on the `#[allow]`
// below — not the bare `Connection` that `connection::mod`'s own size asserts
// cover. Proven here rather than merely claimed in the comment beside it.
const _: () =
  assert!(core::mem::size_of::<(Connection<Server, General>, TransitionRefused)>() <= 256);

/// The mode EDGE: a General server that has read an upgrade request, turning
/// into the tunnel that answers it.
impl Connection<Server, General> {
  /// Answers an upgrade request by switching (RFC 9110 §7.8), turning this
  /// connection into the tunnel that writes the 101.
  ///
  /// A General server refuses an inbound takeover where it ARRIVES — the mode is
  /// not something a peer talks this end into — so the switch is a decision this
  /// end takes, once, with the request already in hand. What comes back is the
  /// [`Tunnel`] connection at the same point [`handle_request`] leaves one: the
  /// handshake is classified and its answer is owed, so
  /// [`accept`](Connection::accept) writes the 101 and
  /// [`reject`](Connection::reject) declines it.
  ///
  /// The transition is CONSUMING because it is not reversible: the General state
  /// — the exchange, the receive FSM, the keep-alive gate — has no meaning after
  /// the 101, where RFC 9110 §7.8 has the "data stream" switch to the new
  /// protocol, and a connection that could switch back would be offering an API
  /// for bytes that are no longer HTTP.
  ///
  /// What it does NOT do is read the request: that already happened, through the
  /// General pump, and the two facts the answer turns on — the RFC 9110 §7.8
  /// offer and §10.1.1's outstanding expectation — travel on the exchange the
  /// pump minted rather than being re-derived from a head this call no longer
  /// has.
  ///
  /// # A capability the native path does not have
  ///
  /// [`handle_request`] refuses an upgrade request that carries content, because
  /// a tunnel has no body machinery to drain it with. This edge accepts one: by
  /// the time it runs, the General pump HAS drained the body, and §7.8 asks for
  /// exactly that: "A client cannot begin using an upgraded protocol on the
  /// connection until it has completely sent the request message".
  ///
  /// # Decide before spending the connection
  ///
  /// The gates below are HTTP's, and they are all this call can check. A request
  /// that passes every one of them may still be invalid to the protocol layered
  /// on top — RFC 6455 §4.2.1's key, version and resource-name rules are that
  /// layer's, not §7.8's — and the transition is one-way, so a caller that
  /// switches first and validates second is holding a tunnel on a request it has
  /// to reject, with no keep-alive HTTP connection left to reject it on.
  ///
  /// Validate first, then switch. The upgrade layer's own validation runs
  /// against a THROWAWAY [`Connection<Server, Tunnel>::new`](Connection::new):
  /// it reads the head the General pump produced and settles nothing on this
  /// connection, so a request it turns down leaves this one General and
  /// answerable. Take the transition only once the answer is yes; a refusal
  /// before it is an ordinary response like any other.
  ///
  /// # Errors
  ///
  /// Returns the connection unchanged beside the failed gate. The caller still
  /// owes its peer a response — RFC 6455 §4.2.1 requires one — so the connection
  /// must come back: a refused switch is a reason to answer differently, not a
  /// reason to lose the ability to answer at all.
  ///
  /// [`handle_request`]: Connection::handle_request
  // The large `Err` IS the signature's point rather than an oversight: a refused
  // switch hands the connection back because the response it owes its peer is
  // still owed. The lint's own remedy is a box, which is an allocation this
  // crate does not make on any tier. `connection::mod` const-asserts the
  // 256-byte budget for `Connection` alone, which covers the `Ok` side; the
  // assertion above covers the `Err` side — the pair the lint actually
  // measures — since a tuple is not a `Connection` that assert reaches.
  #[allow(clippy::result_large_err)]
  pub fn into_tunnel(self) -> Result<Connection<Server, Tunnel>, (Self, TransitionRefused)> {
    // The gates about the REQUEST first, then the gates about the CONNECTION:
    // see `take_over` for why the split is where it is.
    let handshake = match self.offered_switch() {
      Ok(handshake) => handshake,
      Err(refused) => return Err((self, refused)),
    };
    match take_over(&self, TunnelPhase::Handshaking(handshake)) {
      Ok(tunnel) => Ok(tunnel),
      Err(refused) => Err((self, refused)),
    }
  }

  /// The four gates that are about the REQUEST this server is holding, and the
  /// handshake they prove.
  ///
  /// Ordered, and the order is the reported reason: a request that offered
  /// nothing AND is still arriving fails both gate 2 and gate 3, so the one
  /// named has to be fixed rather than incidental.
  fn offered_switch(&self) -> Result<Handshake, TransitionRefused> {
    let Some(exchange) = self.exchange else {
      return Err(TransitionRefused::NO_EXCHANGE);
    };
    // RFC 9110 §7.8: "A server MUST NOT switch to a protocol that was not
    // indicated by the client in the corresponding request's Upgrade header
    // field." The fact is the REQUEST head's and was recorded when it arrived;
    // re-deriving it here is not an option, since the head is gone. Passing this
    // gate is also what re-establishes the classification invariant `accept`
    // trusts, which is why the fact itself does not travel on into the
    // `Handshake`.
    if !exchange.upgrade_offered {
      return Err(TransitionRefused::NO_UPGRADE_OFFERED);
    }
    // §7.8 again: the request must have been COMPLETELY sent. `AwaitingRearm` is
    // that fact — the inbound side of the exchange is through, whatever framing
    // delimited it — and it is the only receive state a live server exchange can
    // be in besides `Body`, since `settle` clears the exchange and the state
    // together.
    if !matches!(self.recv, RecvState::AwaitingRearm) {
      return Err(TransitionRefused::REQUEST_INCOMPLETE);
    }
    // The 101 IS this exchange's answer, so the answer must not have started.
    // `Owed` is the state that says the response head has not gone out (RFC 9110
    // §15.2 is why an interim response leaves it here: a 1xx is not the answer,
    // so a 100 already sent still passes this gate).
    if !matches!(self.send, SendState::Owed) {
      return Err(TransitionRefused::ANSWER_BEGUN);
    }
    Ok(Handshake {
      // RFC 9110 §9.3.6's takeover never reaches here: `inbound` refuses a
      // CONNECT request on a General connection (`CONNECT_NEEDS_TUNNEL`) before
      // it can open an exchange, so the only switch this edge can be carrying is
      // §7.8's.
      connect: false,
      // §7.8's ordering MUST, read off the durable fact for the reason
      // `Exchange::expect_unanswered` states: the transient copy in
      // `RecvState::Body` is gone by the time an answer is written, and the two
      // sends that discharge the ask cleared this one alongside it.
      interim_owed: exchange.expect_unanswered,
      // §6.1/§15.2 both turn on the version the REQUEST stated, which no
      // response can be read for.
      version: exchange.version,
      // WHICH request offered the switch, carried across for the reason
      // `interim_owed` is: the head is gone by the time the layer above
      // validates one, so a fact about it has to travel or be lost. The gate
      // above is what makes it meaningful — `upgrade_offered` is exactly the
      // condition `inbound` hashed under.
      head_digest: exchange.head_digest,
    })
  }
}

// Same reason as the server edge's own assertion above: this edge's `Err`
// pairs a whole `Connection` with `TransitionRefused`, which is its own pair
// for `clippy::result_large_err` to measure on the `#[allow]` below, and its
// own proof that the pair stays inside the crate's 256-byte budget.
const _: () =
  assert!(core::mem::size_of::<(Connection<Client, General>, TransitionRefused)>() <= 256);

/// The mode EDGE: an idle General client connection, turning into the tunnel
/// that carries a handshake it already knows it wants.
impl Connection<Client, General> {
  /// Turns an idle pooled connection into a tunnel, so a caller that already
  /// knows which upgrade it wants can carry the handshake on a connection kept
  /// warm by ordinary keep-alive exchanges, instead of opening a new one.
  ///
  /// Unlike the server edge, this is not an ANSWER: RFC 9110 §7.8's offer has
  /// not been written yet, and nothing about the connection says a switch is
  /// coming — it is the caller's own decision, made on a connection this end
  /// otherwise has nothing outstanding on. What comes back is the [`Tunnel`]
  /// connection at the point [`Connection::new`] leaves a fresh one at: the
  /// handshake has not begun, so either [`open_upgrade`](Connection::open_upgrade)
  /// or [`open_connect`](Connection::open_connect) may start it.
  ///
  /// The transition is CONSUMING for the reason it is on the server edge:
  /// General's message state has no meaning once the switch is committed, and
  /// a connection that could step back out of it would be offering an API for
  /// bytes a peer may already be reading as the new protocol's.
  ///
  /// # The two client-only gates this edge does not add
  ///
  /// `tail_unresolved` and `pending_cr` are RFC 9112 §9.2's barrier and its
  /// one-byte CR special case (§2.2) — fields only a client's own receive path
  /// writes. `take_over` gates on both already, so this edge does not re-check
  /// them: skipping the call instead would let
  /// [`open_upgrade`](Connection::open_upgrade) read a stale tail as the
  /// handshake's own response, exactly what
  /// [`open_request`](Connection::open_request) already refuses on the
  /// ordinary path.
  ///
  /// # Errors
  ///
  /// Returns the connection unchanged beside the failed gate: a caller that
  /// cannot switch this connection still has an ordinary General connection to
  /// go on using, or to return to its pool.
  // The large `Err` IS the signature's point here too — see the server edge's
  // `into_tunnel` for why, and the assertion above for the proof that applies
  // to this edge's own pair.
  #[allow(clippy::result_large_err)]
  pub fn into_tunnel(self) -> Result<Connection<Client, Tunnel>, (Self, TransitionRefused)> {
    if let Err(refused) = self.nothing_outstanding() {
      return Err((self, refused));
    }
    match take_over(&self, TunnelPhase::Idle) {
      Ok(tunnel) => Ok(tunnel),
      Err(refused) => Err((self, refused)),
    }
  }

  /// The three gates about the MESSAGE STATE this client itself is holding,
  /// checked before the connection gates `take_over` carries.
  ///
  /// The server edge reads its four off a REQUEST it is holding; this end
  /// has no request to read one off — a client decides to switch on its own,
  /// so the only facts available are the three that say whether anything is
  /// outstanding at all.
  fn nothing_outstanding(&self) -> Result<(), TransitionRefused> {
    // An outstanding exchange is a response this end is still OWED, not one it
    // owes. RFC 9112 §9.3.2 lets a client pipeline; keeping exactly one request
    // of its own in flight is THIS core's choice, and the same fact
    // `open_request`'s `ONE_REQUEST_AT_A_TIME` refuses a second request on. The
    // switch would silently discard the receive state that answer arrives into,
    // and the answer with it.
    if self.exchange.is_some() {
      return Err(TransitionRefused::EXCHANGE_IN_FLIGHT);
    }
    // On today's writers this can never be the reported reason: `recv` leaves
    // `Idle` only once `open_request` has minted an exchange, so the gate
    // above always fires first. Gated all the same, for the reason
    // `EVENT_UNDRAINED` is in `take_over` below — a coincidence between
    // today's writers is not a rule this type enforces.
    if !matches!(self.recv, RecvState::Idle) {
      return Err(TransitionRefused::RECV_NOT_IDLE);
    }
    // `send` can sit at `Abandoned` on an otherwise idle connection: a request
    // body this end was released from finishing when the peer's `close` or a
    // read EOF arrived mid-write. The release is RFC 9112 §9.6's
    // close-after-reading MUST, not its "cease sending", whose object is
    // requests. Abandoned is not idle — the switch would go on as if that write
    // had never mattered.
    if !matches!(self.send, SendState::Idle) {
      return Err(TransitionRefused::SEND_NOT_IDLE);
    }
    Ok(())
  }
}

/// The half of a mode transition that is the same at both ends: the gates about
/// the CONNECTION, and what the tunnel keeps of the General connection it
/// replaces.
///
/// ONE routine rather than one per edge, and that is load-bearing rather than
/// tidy. Each edge is proven by comparing it against its OWN native path — a
/// server that read its request through [`handle_request`](Connection::handle_request),
/// a client that opened its handshake through
/// [`open_upgrade`](Connection::open_upgrade) — and never against the other
/// edge, so two copies of this could drift apart with no test able to see it.
///
/// What the ROLE decides is left to the caller, because it is a question about
/// the MESSAGE in flight: a server holds a request it has read and a client is
/// waiting for a response it has not. Those gates therefore run first, in the
/// caller, and this one runs after with the phase the handshake begins in.
///
/// # What is inherited, and why the rest is not
///
/// `lifecycle`, `read_closed` and `peer_close` are facts about the CONNECTION,
/// and the connection is the thing that survives — a transition is not a new
/// connection, so a fact that was true of the transport a moment ago is still
/// true. Everything else is General's message state, which is why the gates
/// above prove it empty before it is dropped: no exchange, nothing owed, no
/// undrained notice. `next_exchange` goes back to `1` rather than being
/// carried over from `from`: a `Tunnel` connection mints no exchange, so the
/// count is not a fact worth preserving the way `lifecycle` is. `1` is the
/// crate's own invariant that an id never starts at `0`, and it is also the
/// value [`Connection::new`] already gives a fresh [`Tunnel`] connection —
/// carrying `from`'s own count instead would build a connection the native
/// path above never produces.
fn take_over<Ro>(
  from: &Connection<Ro, General>,
  tunnel: TunnelPhase,
) -> Result<Connection<Ro, Tunnel>, TransitionRefused> {
  // RFC 9110 §7.8's switch has already happened, so there is no HTTP connection
  // here to take over — the transport is the next protocol's, and a tunnel minted
  // over it would let `open_upgrade` write HTTP/1.1 bytes into a stream somebody
  // else is reading.
  //
  // UNREACHABLE, and named so rather than merely asserted. The client edge is the
  // only one that can present a switched connection — the phase's only writer is
  // the client's response path — and `nothing_outstanding` runs BEFORE this call
  // and refuses it with `EXCHANGE_IN_FLIGHT`, because the switch retains the
  // exchange: §7.8 leaves the server with "an outstanding request to satisfy
  // after the protocol has been changed". That is an invariant of ANOTHER
  // function and of the arm that writes the phase; gated here all the same, so
  // that a reorder of those gates cannot expose the path.
  if matches!(from.tunnel, TunnelPhase::Switched) {
    return Err(TransitionRefused::SWITCHED);
  }
  // RFC 9112 §9.6: `close` promises to end the connection BEHIND this exchange,
  // and a tunnel is the opposite promise. `Failed` and `Draining` land here too,
  // and for the same reason a live handshake needs an open connection.
  if !matches!(from.lifecycle, Lifecycle::Open) {
    return Err(TransitionRefused::NOT_OPEN);
  }
  // The transport fact, checked after the policy one because a peer that stated
  // `close` and then half-closed did both, and §9.6 makes the option the
  // stronger statement. A switched protocol whose peer can send nothing is a
  // tunnel with one end already gone.
  if from.read_closed {
    return Err(TransitionRefused::READ_CLOSED);
  }
  // §9.2's barrier and §2.2's undecided terminator. Both are bytes the General
  // side has not finished accounting for, and the tunnel would hand them to the
  // next protocol as its own.
  //
  // Neither can be the FIRST failure on the server edge: both are written on
  // client paths alone (`inbound::idle_client_bytes`, and the `|= is_client`
  // that sets the tail), so a server reaches this call with both false. They are
  // gated anyway, because that is a fact about today's writers rather than a
  // rule — and the client edge can reach both.
  if from.tail_unresolved {
    return Err(TransitionRefused::TAIL_UNRESOLVED);
  }
  if from.pending_cr {
    return Err(TransitionRefused::PENDING_CR);
  }
  // Last, and it can never be the first failure today: every writer of `event`
  // or `aborted` also moves the lifecycle off `Open` or latches `read_closed`,
  // so the gate above it always fires first. Gated all the same, for the reason
  // the two above are — a coincidence between today's writers is not a rule.
  if from.aborted.is_some() {
    return Err(TransitionRefused::EVENT_UNDRAINED);
  }
  // Field by field rather than from `new()` with the differences applied: a
  // field added to `Connection` is then a compile error HERE, which is where the
  // decision to carry it or drop it belongs.
  Ok(Connection {
    consumed: 0,
    watermark: 0,
    next_exchange: 1,
    recv: RecvState::Idle,
    exchange: None,
    send: SendState::Idle,
    // Inherited rather than reset to the open state the gates just proved: the
    // gate is what makes the two the same today, and reading the connection is
    // what keeps that true if one is ever relaxed.
    lifecycle: from.lifecycle,
    read_closed: from.read_closed,
    peer_close: from.peer_close,
    tail_unresolved: false,
    aborted: None,
    tunnel,
    pending_cr: false,
    idle_crlfs: 0,
    // CARRIED, and the decision is recorded here because this build is what
    // forces it: the ceilings and the opportunistic-upgrade permission are
    // properties of the CONNECTION, not of the message framing that stops
    // applying at the switch. Nothing reads them in Tunnel mode — RFC 9110
    // §9.3.6 gives CONNECT no content and this core refuses content on a
    // handshake, and a tunnel has no further ORDINARY exchange left to offer an
    // upgrade on — so they are inert here, and what bounds the protocol on the
    // far side of the switch is that protocol's own limits.
    max_body: from.max_body,
    max_chunk_framing: from.max_chunk_framing,
    opportunistic_upgrade: from.opportunistic_upgrade,
    shape: PhantomData,
  })
}

/// Classifies a complete request head as one of the two takeovers, or says why
/// it is neither.
///
/// The receive side's own validation runs first (RFC 9112 §3.2's `Host` rules,
/// the §3.2.3/§3.2.4 target-method pairing, the §6.3 framing decision), so a
/// request that is malformed as a REQUEST is diagnosed as that rather than as a
/// handshake fault.
fn classify(head: &[u8]) -> Result<(HeadView<'_>, RequestLine<'_>, Handshake), H1Error> {
  let view = scan_head(head)?;
  let request = parse_request_line(view.start_line_bytes())?;
  let (framing, directives) = validate_request(&request, &view)?;
  // Every handshake message here is its head — see `HANDSHAKE_HAS_NO_CONTENT`.
  //
  // `Content-Length: 0` announces no octets, so it states the SAME message: RFC
  // 9110 §8.6 makes it the way a message says it has no content, and the §6.3
  // decision therefore reports `ContentLength(0)` rather than `None` for a head
  // that spelled it out. Both are the bodiless shape a handshake is, and
  // refusing the explicit one would refuse this core's own client — `open_upgrade`
  // and `open_connect` both permit it (`no_content`), so a request written by
  // one end of this crate has to be classifiable by the other.
  if !matches!(framing, BodyFraming::None | BodyFraming::ContentLength(0)) {
    return Err(H1Error::Framing(HANDSHAKE_HAS_NO_CONTENT));
  }

  if request.method == CONNECT {
    // Validation's §3.2.3 pairing has already proven the target is the
    // authority-form; reading it back through the pattern keeps that checked
    // rather than assumed.
    let Target::Authority { host_port } = request.target else {
      return Err(malformed(target_at(request.method), CONNECT_TARGET_FORM));
    };
    if !states_a_port(host_port) {
      return Err(malformed(
        target_at(request.method),
        CONNECT_TARGET_NEEDS_A_PORT,
      ));
    }
    // The one-takeover-no-close invariant, receive corner — see
    // [`TunnelPhase::Switched`]. §9.6's other MUST binds a server that RECEIVES
    // the option to close after the final response to the request carrying it,
    // and §9.3.6 makes the 2xx that answers a CONNECT the start of a tunnel
    // rather than the end of anything. A server cannot do both.
    //
    // THE STATED OPTION, not `ends_persistence`, and the request side is where
    // that distinction bites. §9.3 makes an HTTP/1.0 message non-persistent
    // without `keep-alive`, but a 1.0 peer that sent a CONNECT has SAID nothing
    // about closing — and §9.3.6 puts no version on CONNECT, which this crate
    // already relies on. Reading the version default here would refuse every
    // 1.0 CONNECT, which is a rule no RFC states. The RESPONSE side does ask
    // `ends_persistence`, and rightly: there the question is whether the
    // connection continues at all, and a non-persistent message ends it however
    // it was spelled.
    if has_close_option(&view) {
      return Err(H1Error::Framing(HANDSHAKE_STATES_CLOSE));
    }
    return Ok((
      view,
      request,
      Handshake {
        connect: true,
        // RFC 9110 §7.8's ordering MUST is about the 101, and a CONNECT is not
        // answered with one.
        interim_owed: false,
        version: request.version,
        // A dead value, and unreadable: a CONNECT made no §7.8 offer, so
        // `head_binding` answers `Mismatch` for every head on this phase
        // WITHOUT reading the digest. See `Handshake::head_digest`.
        head_digest: 0,
      },
    ));
  }

  // `has_upgrade` is already both halves of §7.8 and already HTTP/1.1-only
  // (validation applies the 1.0 MUST-ignore); what is left is whether the field
  // names a protocol at all. A malformed list names none, which is the same
  // thing as not offering: §7.8 lets a server ignore an `Upgrade` field it does
  // not act on, so this is a classification rather than a violation.
  if directives.has_upgrade && names_a_protocol(&view) {
    // The one-takeover-no-close invariant, receive corner — see
    // [`TunnelPhase::Switched`]. RFC 9112 §9.6 makes a server that RECEIVES the
    // option close after the final response to the request carrying it, and a
    // switch is the opposite promise. Read from the SAME `directives` the two
    // facts above come from: General's `commit_head` accumulates the same
    // `close` and refuses the transition, so a path that read past it here would
    // give one wire request two answers.
    if has_close_option(&view) {
      return Err(H1Error::Framing(HANDSHAKE_STATES_CLOSE));
    }
    return Ok((
      view,
      request,
      Handshake {
        connect: false,
        interim_owed: directives.expect_continue,
        version: request.version,
        // The one arm on this path that hashes, and it is behind both halves of
        // the offer above — the native mirror of what `inbound` records for a
        // General exchange, so the transition and this path arm a connection
        // with the same fact about the same bytes.
        head_digest: head_digest(view.block()),
      },
    ));
  }
  Err(H1Error::Framing(NOT_A_HANDSHAKE))
}

/// Where the request-target begins within a head: one SP past the method, which
/// starts at byte 0 of the block (RFC 9112 §3).
fn target_at(method: &str) -> usize {
  method.len().saturating_add(1)
}

/// Whether a scanned head states BOTH halves of RFC 9110 §7.8 — the `upgrade`
/// connection option and an `Upgrade` field naming at least one protocol.
///
/// Both directions ask this of a head: a client of the 101 it receives (§15.2.2
/// makes the field a MUST there), a server of the offer it classifies. The
/// token facts come from the scan, which folded them across every line of the
/// field (RFC 9110 §5.2), and only the protocol grammar re-reads the block —
/// through [`lists_a_protocol`], which folds the `Upgrade` lines the same way
/// rather than asking each of them to satisfy the whole list grammar alone.
pub(crate) fn names_a_protocol(view: &HeadView<'_>) -> bool {
  let key = view.key_fields();
  !key.connection_malformed
    && key.connection_upgrade
    && key.has_upgrade_field
    && lists_a_protocol(view.header_all(UPGRADE))
}

/// Whether an authority states a port CONNECT can actually be tunnelled to:
/// RFC 9112 §3.2.3's `authority-form = uri-host ":" port`, which RFC 9110
/// §9.3.6 makes a MUST in both directions.
///
/// The authority GRAMMAR is not re-implemented here — RFC 3986 §3.2.2 makes the
/// port optional and `is_valid_authority` (through the §3.2 target parser, in
/// both directions) has already accepted or refused the whole string. This adds
/// the two things that grammar deliberately does not decide, and reads the port
/// the way it does: an IP-literal's own colons are the address's, so the port is
/// what follows the `]`.
///
/// PRESENCE — §9.3.6 states it outright: "There is no default port; a client
/// MUST send the port number" — and the NUMBER, which is the same section's
/// server-side MUST: "A server MUST reject a CONNECT request that targets an
/// empty or invalid port number". RFC 3986 spells `port = *DIGIT` because a URI
/// scheme decides what its port means; here the port is the TCP port of the
/// tunnel's far end, so [`port_number`] is what "invalid" is measured against.
fn states_a_port(host_port: &str) -> bool {
  let tail = match host_port.strip_prefix('[') {
    Some(literal) => match literal.split_once(']') {
      Some((_address, tail)) => tail,
      None => return false,
    },
    None => host_port,
  };
  match tail.rsplit_once(':') {
    Some((_host, port)) => port_number(port).is_some(),
    None => false,
  }
}

/// The TCP port an RFC 9112 §3.2.3 authority-form target names, or `None` when
/// it names none this core will open a tunnel to.
///
/// Three refusals, and the last is a policy decision recorded rather than
/// implied:
///
/// - EMPTY, or anything that is not `1*DIGIT`. RFC 3986 §3.2.3's `port = *DIGIT`
///   admits the empty string; RFC 9110 §9.3.6 does not, and names an "empty …
///   port number" as the first thing a server MUST reject.
/// - PAST 65535. A TCP port is 16 bits, so a longer number addresses nothing —
///   §9.3.6's "invalid port number", and the reason this parses rather than
///   merely counting digits. Leading zeros are digits like any other, so `00080`
///   is port 80 and a string of zeros no length makes overflow.
/// - ZERO. `0` is a valid 16-bit integer and not a routable destination: it is
///   the "let the kernel choose" port of a local bind, which is not something a
///   peer can be asked to connect TO. A CONNECT naming it is a request no
///   driver could honour, so it is refused here rather than passed on for a
///   connect() to fail on — the same "invalid port number" §9.3.6 covers.
fn port_number(port: &str) -> Option<u16> {
  // `1*DIGIT` first, so the parse below is only asked about a value it could
  // read: `str::parse` accepts a leading `+`, which the `port` production does
  // not, and this core does not accept a spelling its own grammar refuses.
  if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
    return None;
  }
  port.parse::<u16>().ok().filter(|&port| port != 0)
}

/// Refuses a head that announces octets this core is not about to write.
///
/// RFC 9110 §9.3.6 states it for the CONNECT request ("A CONNECT request message
/// does not have content"), and every other message this module writes is its
/// head for the same reason: Tunnel mode has no body machinery, so an announced
/// body would leave the peer waiting for octets that never come (RFC 9112 §6.3
/// item 6). `Content-Length: 0` announces none, so it is allowed — and
/// [`classify`] accepts the same head, so a request one end of this crate writes
/// is one the other end classifies (`open_upgrade` → `handle_request`,
/// `open_connect` → `handle_request`).
fn no_content(declared: &Declared) -> Result<(), Error> {
  if declared.transfer_encoding > 0 || announces_octets(declared) {
    return Err(Error::InvalidState(HANDSHAKE_HAS_NO_CONTENT));
  }
  Ok(())
}
