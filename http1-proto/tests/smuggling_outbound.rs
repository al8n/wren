//! The OUTBOUND half of the anti-smuggling corpus: what this core refuses to
//! WRITE, driven through the public send API.
//!
//! `tests/smuggling.rs` is the receive side — bytes a hostile peer sends, and
//! what this recipient does with them. This file is its mirror, and the mirror
//! is not optional. RFC 9112 §11.1 (response splitting) and §11.2 (request
//! smuggling) are both defined as two recipients disagreeing about where a
//! message ends, and NOTHING in that definition says the disagreement has to be
//! the peer's fault. A message this core encodes that announces one framing and
//! carries another produces exactly the same disagreement — between our peer and
//! whatever sits behind it — with the vulnerability originating here.
//!
//! The absence of this half is a structural gap: every framing rule had a
//! receive-side vector and the send side had scattered unit tests, so a send
//! path that emitted an unframable message could pass every suite in the tree.
//!
//! # What a vector states
//!
//! Each one is a `(head, plan)` combination a caller could plausibly hand a send
//! call, together with the EXACT refusal it must earn — not merely that the call
//! failed. The refusal strings are the crate's own `Error::InvalidState`
//! payloads, spelled out here because they are `pub(crate)` on the far side of an
//! integration test's crate boundary. That is a feature: a reworded refusal reds
//! the vector that depends on it, and two vectors that started failing for one
//! another's reason cannot silently pass.
//!
//! Every refusal is also checked to be INERT — `out` is untouched and the
//! connection has not moved, so the caller retries with a corrected message.
//! RFC 9112 §2.1 makes a message one thing: there is no half-sent head to unsend,
//! and a refusal that had already written bytes would be a partial message on the
//! wire.

use core::cell::Cell;

use http1_proto::{
  BodyPlan, Client, Connection, Error, General, Headers, NO_TRAILERS, Server, Target, Tunnel,
};

/// The RFC 9112 §3.2.1 origin-form target every request here uses.
const ORIGIN: Target<'static> = Target::Origin {
  path_and_query: "/r",
};

/// The one field RFC 9112 §3.2 makes a client MUST on every HTTP/1.1 request.
const HOST: &[(&str, &[u8])] = &[("Host", b"h")];

/// No field lines at all.
const NONE: &[(&str, &[u8])] = &[];

/// What a bodiless response on a connection that stays open announces: RFC 9112
/// §6.3 item 8 makes a response carrying NO framing field close-delimited, which
/// is not what a keep-alive answer means.
const LENGTH_0: &[(&str, &[u8])] = &[("Content-Length", b"0")];

/// The destination of the CONNECT vectors, in the §3.2.3 `uri-host ":" port`
/// form RFC 9110 §9.3.6 makes a client MUST send.
const DESTINATION: &str = "example.com:443";

/// A `Host` for that destination (RFC 9110 §7.2 wants the authority in a field
/// as well as in the target).
const CONNECT_HOST: &[(&str, &[u8])] = &[("Host", b"example.com:443")];

/// Both halves of an RFC 9110 §7.8 upgrade offer.
const OFFER: &[(&str, &[u8])] = &[
  ("Host", b"h"),
  ("Connection", b"Upgrade"),
  ("Upgrade", b"websocket"),
];

/// The refusal constants these vectors name, mirroring the crate's own
/// `&'static str` payloads.
///
/// Spelled out because they are `pub(crate)`; see the module doc for why that is
/// the point rather than a workaround.
mod why {
  // ── framing agreement (`connection::outbound`) ────────────────────────────
  /// RFC 9112 §6.2 / §6.3 item 3: both framing fields in one message.
  pub const BOTH_FRAMINGS: &str = "Content-Length and Transfer-Encoding disagree";
  /// RFC 9110 §8.6's production, as a SENDER: one field line, one decimal value.
  /// Item 5's identical-list exception is the RECIPIENT's excuse, not ours.
  pub const LENGTH_IS_ONE_VALUE: &str = "Content-Length is one line with one 1*DIGIT value";
  /// RFC 9110 §5.6.1.1: "a sender MUST NOT generate empty list elements."
  pub const SENDER_LIST_EMPTY_ELEMENT: &str = "a list field states no empty element";
  /// Every field this core INTERPRETS is written in its own grammar, whether or
  /// not the framing decision happens to consult it.
  pub const FIELD_STATES_ITS_GRAMMAR: &str = "an interpreted field states its own grammar";
  /// RFC 9110 §10.1.1: "A client MUST NOT generate a 100-continue expectation in
  /// a request that does not include content."
  pub const CONTINUE_NEEDS_CONTENT: &str = "100-continue states a request with content";
  /// RFC 9112 §6.3 item 4: a `Transfer-Encoding` announcing a body the plan does
  /// not write.
  pub const TE_WITHOUT_CHUNKED: &str = "Transfer-Encoding announces a body the plan does not send";
  /// RFC 9112 §6.3 item 6: the announced length is not the plan's.
  pub const LENGTH_DISAGREES: &str = "Content-Length disagrees with the body plan";
  /// A chunked body whose head does not say so (§6.3 item 4 versus item 8).
  pub const CHUNKED_UNANNOUNCED: &str = "a chunked body needs a Transfer-Encoding field";
  /// RFC 9112 §7.1: the sender applies exactly one coding, so the declaration
  /// has to be a lone, final, unparameterized `chunked`.
  pub const CHUNKED_DECLARATION: &str = "Transfer-Encoding does not declare a lone chunked coding";
  /// RFC 9112 §6.3 item 8: a response with a body and no framing field would be
  /// close-delimited, which a connection staying open is not about to do.
  pub const UNFRAMED_RESPONSE: &str = "a response with a body plan needs a framing field";
  /// Item 8 is the list's "otherwise", so the ABSENCE of both fields declares it.
  pub const CLOSE_DELIMITED_IS_UNFRAMED: &str = "a close-delimited body carries no framing field";
  /// The note under item 8: a request is never close-delimited.
  pub const REQUEST_IS_NEVER_CLOSE_DELIMITED: &str = "a request is never close-delimited";
  /// RFC 9112 §6.1: no `Transfer-Encoding` to a peer that spoke HTTP/1.0.
  pub const TE_NEEDS_HTTP_11: &str = "Transfer-Encoding requires an HTTP/1.1 request";
  /// RFC 9110 §15.2: no 1xx to an HTTP/1.0 client.
  pub const INTERIM_NEEDS_HTTP_11: &str = "a 1xx response requires an HTTP/1.1 request";
  /// RFC 9112 §6.3 item 1: this status is bodiless whatever the head says.
  pub const BODILESS_TAKES_NO_BODY: &str = "this status can carry no body";
  /// RFC 9112 §6.1 with RFC 9110 §8.6: a 1xx or 204 carries neither field.
  pub const BODILESS_STATUS_FRAMING: &str = "a 1xx or 204 carries no framing field";
  /// RFC 9110 §15.2: an interim response ends no exchange.
  pub const INTERIM_NOT_FINAL: &str = "a 1xx response is interim, not final";
  /// A phase owing a rejection has no success class to state.
  pub const NO_SUCCESS_TO_STATE: &str = "an error response states no 2xx";
  /// RFC 9110 §5.3: the injected `close` and a caller's own `Connection` line
  /// would be ONE field saying two things.
  pub const CALLER_STATED_CONNECTION: &str = "send_error_response states Connection itself";
  /// RFC 9112 §3.2's client MUST.
  pub const REQUEST_NEEDS_HOST: &str = "an HTTP/1.1 request states its Host";
  /// §3.2's second `Host` MUST, scoped to "any request message".
  pub const ONE_HOST_LINE: &str = "a request states exactly one Host field line";
  /// §3.2's third, over the value the recipient reads.
  pub const HOST_NOT_AUTHORITY: &str = "the Host field value is not an authority";
  /// RFC 9112 §3.2.3: the authority-form is CONNECT's and no other method's.
  pub const AUTHORITY_FORM_NEEDS_CONNECT: &str =
    "authority-form request-target from a method other than CONNECT";
  /// RFC 9112 §3.2.4: the asterisk-form is the server-wide OPTIONS request's.
  pub const ASTERISK_FORM_NEEDS_OPTIONS: &str =
    "asterisk-form request-target from a method other than OPTIONS";
  /// RFC 9110 §9.3.6: takeover needs `Tunnel` mode.
  pub const CONNECT_NEEDS_TUNNEL: &str = "CONNECT requires a Tunnel-mode connection";
  /// The same, from the response side.
  pub const SWITCHING_NEEDS_TUNNEL: &str = "101 requires a Tunnel-mode connection";

  // ── body writing (`connection::outbound`, `body::encode`) ─────────────────
  /// RFC 9112 §6.3 item 6: an octet past the count belongs to the next message.
  pub const OVER_SEND: &str = "body exceeds the declared Content-Length";
  /// The same rule from the other end.
  pub const BODY_INCOMPLETE: &str = "body is shorter than the declared Content-Length";
  /// RFC 9112 §7.1.2 gives the trailer section to the chunked coding alone.
  pub const UNCHUNKED_HAS_NO_TRAILERS: &str = "only a chunked body carries trailers";
  /// RFC 9110 §6.5.1's sender MUST NOT, over the narrow set this core decides.
  pub const FORBIDDEN_TRAILER: &str =
    "this field name cannot be sent in a trailer section (RFC 9110 §6.5.1)";
  /// The `Headers` idempotence contract, enforced over the section's CONTENT: a
  /// supplier that shows one section to the walk that frames the message and
  /// another to the walks that write it.
  pub const DRIFTED: &str = "outbound headers changed between the walks that frame and write them";

  // ── tunnel handshakes (`connection::tunnel`) ──────────────────────────────
  /// RFC 9110 §9.3.6: "A CONNECT request message does not have content", and no
  /// message this mode writes has one.
  pub const HANDSHAKE_HAS_NO_CONTENT: &str = "a tunnel handshake message carries no content";
  /// RFC 9112 §6.1 with RFC 9110 §8.6 and §9.3.6: the head that switches frames
  /// nothing.
  pub const SWITCH_HAS_NO_FRAMING: &str = "a response that switches carries no framing field";
  /// The same for a 1xx.
  pub const INTERIM_HAS_NO_FRAMING: &str = "a 1xx carries no framing field";
  /// RFC 9110 §7.8: an offer states both halves.
  pub const OFFER_NEEDS_BOTH_HALVES: &str =
    "an upgrade offer states Connection: upgrade and an Upgrade protocol list";
  /// RFC 9110 §15.2.2 with §7.8: so does the 101 that answers it.
  pub const SWITCH_NEEDS_BOTH_HALVES: &str =
    "a 101 states Connection: upgrade and an Upgrade protocol list";
  /// The statuses that MAKE the switch go through `accept`.
  pub const SWITCH_THROUGH_ACCEPT: &str = "the response that switches goes through accept";
  /// RFC 9110 §15.2: only a 1xx is interim.
  pub const NOT_INTERIM: &str = "only a 1xx response is interim";
  /// RFC 9110 §9.3.6: "a client MUST send the port number", and one that
  /// addresses a TCP port — the section's own "empty or invalid port number".
  pub const CONNECT_NEEDS_A_PORT: &str = "a CONNECT target states host and a port in 1-65535";
  /// RFC 9112 §3.2.3/§3.2.4: an offer takes an origin- or absolute-form target.
  pub const SWITCH_TARGET_FORM: &str = "an upgrade offer takes an origin- or absolute-form target";
}

/// A destination pre-filled with a sentinel, so "wrote nothing" is checkable
/// rather than assumed.
const SENTINEL: u8 = 0xAA;

/// Asserts that `outcome` is exactly the refusal `expected` names, and that the
/// call was INERT — `out` still holds nothing but sentinel bytes.
///
/// RFC 9112 §2.1 makes a message one thing, so a refused encode may not have put
/// part of one in the caller's buffer: there is nothing to unsend, and a peer
/// handed a partial head frames the connection somewhere the sender never did.
#[track_caller]
fn refuses(name: &str, outcome: Result<usize, Error>, expected: &str, out: &[u8]) {
  match outcome {
    Err(Error::InvalidState(why)) => assert_eq!(
      why, expected,
      "{name}: refused for a different rule than the vector states"
    ),
    other => panic!("{name}: expected a refusal stating {expected:?}, got {other:?}"),
  }
  assert!(
    out.iter().all(|&byte| byte == SENTINEL),
    "{name}: a refused encode wrote into the caller's buffer"
  );
}

/// A server with a request parsed and its response owed.
fn owed(request: &[u8]) -> Connection<Server, General> {
  let mut connection = Connection::<Server, General>::new();
  {
    let mut items = connection.handle(request);
    while items
      .next()
      .expect("the fixture requests are all well formed")
      .is_some()
    {}
  }
  assert!(connection.is_awaiting_send());
  connection
}

/// The ordinary HTTP/1.1 GET the response vectors answer.
const GET_11: &[u8] = b"GET /r HTTP/1.1\r\nHost: h\r\n\r\n";

/// An HTTP/1.0 GET, which RFC 9112 §6.1 and RFC 9110 §15.2 both make
/// load-bearing for what may be sent back.
const GET_10: &[u8] = b"GET /r HTTP/1.0\r\nHost: h\r\n\r\n";

/// A HEAD request, whose response RFC 9112 §6.3 item 1 makes bodiless.
const HEAD_11: &[u8] = b"HEAD /r HTTP/1.1\r\nHost: h\r\n\r\n";

// ── a supplier that lies to the walk that frames the message ──────────────────

/// A `Headers` supplier that shows one section to the FIRST walk and another to
/// every walk after it, with both sections the same length.
///
/// The send side walks a caller's section three times: once to decide how the
/// message is framed, then twice to size and write it. This is what a caller
/// gets wrong by accident — a field rebuilt from mutable state, a value read
/// from a cell that something else advances — and it is the shape a byte-COUNT
/// check cannot see, because the two sections encode to the same number of
/// bytes.
///
/// RFC 9112 §6.3 item 6 is what makes it matter: the peer frames the body at the
/// length the WIRE states. A core that committed its send FSM to the length it
/// was shown first would count down 5 octets behind a head announcing 6, and the
/// peer would read the next message's first octet as the last of this one —
/// §11.2's primitive, produced here rather than by a peer.
struct SameLengthDrift {
  /// Whether the framing walk has already happened.
  walked: Cell<bool>,
  /// The value that walk is shown.
  first: &'static [u8],
  /// The value every later walk is shown. Same length as `first`.
  then: &'static [u8],
}

impl SameLengthDrift {
  /// A supplier that shows `first`, then `then`. Their lengths are asserted
  /// equal, since a length difference would be caught by the older check and the
  /// vector would stop testing what it names.
  fn new(first: &'static [u8], then: &'static [u8]) -> Self {
    assert_eq!(
      first.len(),
      then.len(),
      "the vector must drift without changing the byte count"
    );
    Self {
      walked: Cell::new(false),
      first,
      then,
    }
  }

  /// The value this walk is shown.
  fn value(&self) -> &'static [u8] {
    if self.walked.replace(true) {
      self.then
    } else {
      self.first
    }
  }
}

impl Headers for SameLengthDrift {
  fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), Error> {
    f("Host", b"h");
    f("Content-Length", self.value());
    Ok(())
  }
}

/// The same shape over a TRAILER section, where the pre-walk's verdict is not a
/// length but a NAME: `body::encode` refuses four field names outright (RFC 9110
/// §6.5.1), and `Host` is four characters long — so a four-character name it
/// does allow is an equal-length substitution for one it does not.
struct SameLengthTrailerDrift {
  /// Whether the forbidden-name walk has already happened.
  walked: Cell<bool>,
}

impl Headers for SameLengthTrailerDrift {
  fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), Error> {
    if self.walked.replace(true) {
      f("Host", b"evil.example");
    } else {
      f("Xyzw", b"evil.example");
    }
    Ok(())
  }
}

// The `Headers` contract enforced over CONTENT rather than over length, on every
// path that takes a caller's section: a decision made on one walk may not be
// carried into a message written from another.
//
// Each case asserts three things — the exact refusal, that `out` was not written
// into, and that NOTHING was committed: the connection is exactly where it was,
// so a caller whose supplier was merely buggy corrects it and retries.
#[test]
fn a_same_length_drift_is_caught_before_anything_commits() {
  // The drift: `Content-Length: 5` to the framing walk, `6` to both encoder
  // walks, against a plan of 5.
  let mut connection = Connection::<Client, General>::new();
  let mut out = [SENTINEL; 192];
  refuses(
    "a request whose length drifts by one digit",
    connection.open_request(
      "POST",
      &ORIGIN,
      &SameLengthDrift::new(b"5", b"6"),
      BodyPlan::ContentLength(5),
      &mut out,
    ),
    why::DRIFTED,
    &out,
  );
  // Nothing committed: the exchange never opened, so a corrected request goes
  // out on this same connection — and the FSM is not counting down a body.
  assert!(
    connection
      .open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_ok(),
    "a drifted open spent the exchange"
  );

  // The response side of the same path, where the drift would frame the body the
  // PEER reads (RFC 9112 §11.1).
  let mut connection = owed(GET_11);
  let mut out = [SENTINEL; 192];
  refuses(
    "a response whose length drifts by one digit",
    connection.send_response(
      200,
      b"OK",
      &SameLengthDrift::new(b"5", b"6"),
      BodyPlan::ContentLength(5),
      &mut out,
    ),
    why::DRIFTED,
    &out,
  );
  // The response is still owed, so the driver answers again rather than being
  // left with a half-framed exchange.
  assert!(connection.is_awaiting_send());
  assert!(
    connection
      .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
      .is_ok(),
    "a drifted response spent the exchange"
  );

  // The trailer section, whose pre-walk decides a NAME rather than a length:
  // RFC 9110 §6.5.1's forbidden set is checked on walk one, and a same-length
  // substitution would put `Host` in a trailer section past a check that had
  // already said yes.
  let (mut connection, mut out) = chunked();
  let mut sink = [SENTINEL; 192];
  refuses(
    "a trailer name that drifts into a forbidden one",
    connection.finish_body(
      Some(&SameLengthTrailerDrift {
        walked: Cell::new(false),
      }),
      &mut sink,
    ),
    why::DRIFTED,
    &sink,
  );
  // The body is still in flight, so the message can still be ended correctly.
  let n = connection
    .finish_body(NO_TRAILERS, &mut out)
    .expect("a drifted trailer section did not end the body");
  assert_eq!(&out[..n], b"0\r\n\r\n");
}

// ── the round trip ────────────────────────────────────────────────────────────

/// Feeds `wire` to a fresh `Connection<Server, General>` and reports what the
/// first `Items::next` said: `Ok(())` when the request was accepted as a head.
///
/// The other half of "what this core reads, this core writes": a request that
/// leaves `open_request` and is then refused by this crate's own receive path is
/// a message this end had no business sending, since the peer — or an
/// intermediary behind it — runs those same rules.
fn served(wire: &[u8]) -> Result<(), Error> {
  let mut server = Connection::<Server, General>::new();
  let mut items = server.handle(wire);
  match items.next() {
    Ok(Some(_)) => Ok(()),
    Ok(None) => Err(Error::InvalidState(
      "the server read no head from these bytes",
    )),
    Err(error) => Err(error),
  }
}

// The ROUND TRIP, stated as a property rather than as a list of shapes: every
// request `open_request` accepts is one this crate's own server half accepts.
//
// RFC 9112 §3.2 (`Host`), §3.2.3/§3.2.4 (target-method pairing) and §6.3 (the
// framing decision) are all applied by `validate_request` on the way in, and the
// send path now asks the same questions with the same predicates. Nothing here
// is about a specific refusal — the tables below own those — it is about the two
// directions agreeing, which is the property a one-sided check breaks silently.
#[test]
fn every_request_open_request_writes_is_one_this_core_reads() {
  let empty_host: &[(&str, &[u8])] = &[("Host", b"")];
  let ported: &[(&str, &[u8])] = &[("Host", b"example.com:8080")];
  let literal: &[(&str, &[u8])] = &[("Host", b"[::1]:443")];
  let padded: &[(&str, &[u8])] = &[("Host", b"  h  ")];
  let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"5")];
  let chunked_fields: &[(&str, &[u8])] = &[("Host", b"h"), ("Transfer-Encoding", b"chunked")];
  let closing: &[(&str, &[u8])] = &[("Host", b"h"), ("Connection", b"close")];
  let expecting: &[(&str, &[u8])] = &[
    ("Host", b"h"),
    ("Content-Length", b"4"),
    ("Expect", b"100-continue"),
  ];

  for (name, method, target, fields, plan) in [
    // §6.3 item 7: neither framing field, so the message is its head.
    ("a bodiless GET", "GET", ORIGIN, HOST, BodyPlan::None),
    // §3.2's empty-value case, which is itself a client MUST.
    (
      "an empty Host value",
      "GET",
      ORIGIN,
      empty_host,
      BodyPlan::None,
    ),
    // RFC 3986 §3.2.2 authorities the receive side accepts.
    ("a Host with a port", "GET", ORIGIN, ported, BodyPlan::None),
    (
      "an IPv6 literal Host",
      "GET",
      ORIGIN,
      literal,
      BodyPlan::None,
    ),
    // RFC 9110 §5.5: OWS is no part of a value, so a padded one is the same
    // field on the wire and the server trims it back to `h`.
    (
      "a Host with OWS around it",
      "GET",
      ORIGIN,
      padded,
      BodyPlan::None,
    ),
    // §3.2.4: the asterisk-form, paired with the method it belongs to.
    (
      "a server-wide OPTIONS",
      "OPTIONS",
      Target::Asterisk,
      HOST,
      BodyPlan::None,
    ),
    // §3.2.2: the absolute-form, which a server MUST accept.
    (
      "an absolute-form target",
      "GET",
      Target::Absolute {
        uri: "http://example.com/r",
      },
      HOST,
      BodyPlan::None,
    ),
    // §6.3 item 6 and item 4, the two framings a request can carry.
    (
      "a counted POST",
      "POST",
      ORIGIN,
      counted,
      BodyPlan::ContentLength(5),
    ),
    (
      "a chunked POST",
      "POST",
      ORIGIN,
      chunked_fields,
      BodyPlan::Chunked,
    ),
    // §9.6 and RFC 9110 §10.1.1: fields the receive path READS rather than
    // merely carries, so they exercise the directive half of validation too.
    ("a closing request", "GET", ORIGIN, closing, BodyPlan::None),
    (
      "an expecting POST",
      "POST",
      ORIGIN,
      expecting,
      BodyPlan::ContentLength(4),
    ),
  ] {
    let mut connection = Connection::<Client, General>::new();
    let mut out = [SENTINEL; 256];
    let n = connection
      .open_request(method, &target, fields, plan, &mut out)
      .unwrap_or_else(|error| panic!("{name}: open_request refused a valid request: {error:?}"));
    served(&out[..n])
      .unwrap_or_else(|error| panic!("{name}: our own server refused what we wrote: {error:?}"));
  }
}

// ── open_request ──────────────────────────────────────────────────────────────

// The REFUSAL table for the message-level request rules, and the mirror of the
// round trip above: every shape here is one `open_request` used to write and
// this crate's own server half then refused.
//
// RFC 9112 §3.2's three `Host` MUSTs and §3.2.3/§3.2.4's target-method pairing.
// Each vector asserts the exact refusal, that nothing was written, and — through
// `served` — that the request it would have produced really is one this core
// rejects, so the vector cannot rot into testing a rule that stopped mattering.
#[test]
fn open_request_refuses_what_our_own_receive_path_would() {
  for (name, method, target, fields, expected, wire) in [
    (
      "an asterisk-form target from a method that is not OPTIONS",
      "GET",
      Target::Asterisk,
      HOST,
      why::ASTERISK_FORM_NEEDS_OPTIONS,
      b"GET * HTTP/1.1\r\nHost: h\r\n\r\n".as_slice(),
    ),
    (
      "an authority-form target from a method that is not CONNECT",
      "GET",
      Target::Authority {
        host_port: DESTINATION,
      },
      CONNECT_HOST,
      why::AUTHORITY_FORM_NEEDS_CONNECT,
      b"GET example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    ),
    (
      "two Host field lines",
      "GET",
      ORIGIN,
      &[("Host", b"a.example".as_slice()), ("Host", b"b.example")] as &[(&str, &[u8])],
      why::ONE_HOST_LINE,
      b"GET /r HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
    ),
    (
      // §3.2 counts LINES, so two that agree are still two.
      "two Host field lines that agree",
      "GET",
      ORIGIN,
      &[("Host", b"a.example"), ("Host", b"a.example")],
      why::ONE_HOST_LINE,
      b"GET /r HTTP/1.1\r\nHost: a.example\r\nHost: a.example\r\n\r\n",
    ),
    (
      "a Host value with a space in it",
      "GET",
      ORIGIN,
      &[("Host", b"bad host")],
      why::HOST_NOT_AUTHORITY,
      b"GET /r HTTP/1.1\r\nHost: bad host\r\n\r\n",
    ),
    (
      "a Host value that is not an authority",
      "GET",
      ORIGIN,
      &[("Host", b"http://example.com/")],
      why::HOST_NOT_AUTHORITY,
      b"GET /r HTTP/1.1\r\nHost: http://example.com/\r\n\r\n",
    ),
    (
      // RFC 9110 §5.5 admits obs-text in a field value; RFC 3986 §3.2.2 does
      // not admit it in an authority.
      "a Host value carrying obs-text",
      "GET",
      ORIGIN,
      &[("Host", b"caf\xC3\xA9.example")],
      why::HOST_NOT_AUTHORITY,
      b"GET /r HTTP/1.1\r\nHost: caf\xC3\xA9.example\r\n\r\n",
    ),
  ] {
    let mut connection = Connection::<Client, General>::new();
    let mut out = [SENTINEL; 192];
    refuses(
      name,
      connection.open_request(method, &target, fields, BodyPlan::None, &mut out),
      expected,
      &out,
    );
    // Inert: the exchange never opened, so a corrected request still goes out.
    assert!(
      connection
        .open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
        .is_ok(),
      "{name}: a refused open spent the exchange"
    );
    // And the refusal is not this core being fussy on its own: the bytes it
    // would have written are bytes its own server half rejects.
    assert!(
      served(wire).is_err(),
      "{name}: the receive path accepts what the send path refused"
    );
  }
}

// RFC 9112 §6.3, from the sending end: the head a client writes and the body it
// is about to write have to state the SAME message. A head that announces a
// framing this core will not produce is §11.2's primitive with the sender on our
// side of it, so the combination is refused before a byte is encoded.
#[test]
fn open_request_refuses_a_head_that_contradicts_its_plan() {
  for (name, fields, plan, expected) in [
    (
      "both framing fields",
      &[
        ("Host", b"h".as_slice()),
        ("Content-Length", b"3"),
        ("Transfer-Encoding", b"chunked"),
      ] as &[(&str, &[u8])],
      BodyPlan::Chunked,
      why::BOTH_FRAMINGS,
    ),
    (
      "two lengths that disagree",
      &[
        ("Host", b"h"),
        ("Content-Length", b"3"),
        ("Content-Length", b"4"),
      ],
      BodyPlan::ContentLength(3),
      why::LENGTH_IS_ONE_VALUE,
    ),
    (
      "a length that is not 1*DIGIT",
      &[("Host", b"h"), ("Content-Length", b"abc")],
      BodyPlan::ContentLength(3),
      why::LENGTH_IS_ONE_VALUE,
    ),
    (
      "a length that is not the plan's",
      &[("Host", b"h"), ("Content-Length", b"4")],
      BodyPlan::ContentLength(3),
      why::LENGTH_DISAGREES,
    ),
    (
      "a counted plan with no length at all",
      HOST,
      BodyPlan::ContentLength(3),
      why::UNFRAMED_RESPONSE,
    ),
    (
      "a chunked plan the head never announced",
      HOST,
      BodyPlan::Chunked,
      why::CHUNKED_UNANNOUNCED,
    ),
    (
      "chunked declared behind another coding",
      &[("Host", b"h"), ("Transfer-Encoding", b"gzip, chunked")],
      BodyPlan::Chunked,
      why::CHUNKED_DECLARATION,
    ),
    (
      "chunked declared with parameters",
      &[("Host", b"h"), ("Transfer-Encoding", b"chunked;a=b")],
      BodyPlan::Chunked,
      why::CHUNKED_DECLARATION,
    ),
    (
      "a transfer coding under a bodiless plan",
      &[("Host", b"h"), ("Transfer-Encoding", b"chunked")],
      BodyPlan::None,
      why::TE_WITHOUT_CHUNKED,
    ),
    (
      "a length under a bodiless plan",
      &[("Host", b"h"), ("Content-Length", b"5")],
      BodyPlan::None,
      why::LENGTH_DISAGREES,
    ),
    (
      // The note under §6.3 item 8: with neither field a request ends at its
      // head, so no server reads one this way and this end could not deliver it
      // — the close would have to come before the response it is waiting for.
      "a close-delimited request",
      HOST,
      BodyPlan::CloseDelimited,
      why::REQUEST_IS_NEVER_CLOSE_DELIMITED,
    ),
    (
      "a request that states no Host",
      NONE,
      BodyPlan::None,
      why::REQUEST_NEEDS_HOST,
    ),
    // RFC 9110 §5.6.1.1: "a sender MUST NOT generate empty list elements." The
    // recipient tolerance §5.6.1.2 requires is about what this core ACCEPTS, and
    // says nothing about what it may emit.
    (
      "a Content-Length with a trailing empty element",
      &[("Host", b"h"), ("Content-Length", b"5,")],
      BodyPlan::ContentLength(5),
      why::LENGTH_IS_ONE_VALUE,
    ),
    (
      "a Transfer-Encoding with a leading empty element",
      &[("Host", b"h"), ("Transfer-Encoding", b",chunked")],
      BodyPlan::Chunked,
      why::SENDER_LIST_EMPTY_ELEMENT,
    ),
    (
      "a Connection with a trailing empty element",
      &[("Host", b"h"), ("Connection", b"close,")],
      BodyPlan::None,
      why::SENDER_LIST_EMPTY_ELEMENT,
    ),
    (
      "a Connection with two commas in a row",
      &[("Host", b"h"), ("Connection", b"close,,keep-alive")],
      BodyPlan::None,
      why::SENDER_LIST_EMPTY_ELEMENT,
    ),
    (
      "two Content-Length lines that agree",
      &[
        ("Host", b"h"),
        ("Content-Length", b"5"),
        ("Content-Length", b"5"),
      ],
      BodyPlan::ContentLength(5),
      why::LENGTH_IS_ONE_VALUE,
    ),
  ] {
    let mut connection = Connection::<Client, General>::new();
    let mut out = [SENTINEL; 128];
    refuses(
      name,
      connection.open_request("POST", &ORIGIN, fields, plan, &mut out),
      expected,
      &out,
    );
    // Inert in the FSM as well as in the buffer: the exchange never opened, so
    // a corrected request still goes out on this connection.
    assert!(
      connection
        .open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
        .is_ok(),
      "{name}: a refused open spent the exchange"
    );
  }
}

// RFC 9110 §9.3.6 makes everything after a 2xx to CONNECT opaque octets, so a
// General connection that sent one would go on parsing a tunnel as HTTP.
// Refused at the caller's end, where the request is this end's own.
#[test]
fn open_request_refuses_connect() {
  let mut connection = Connection::<Client, General>::new();
  let mut out = [SENTINEL; 128];
  refuses(
    "CONNECT on a General connection",
    connection.open_request(
      "CONNECT",
      &Target::Authority {
        host_port: DESTINATION,
      },
      CONNECT_HOST,
      BodyPlan::None,
      &mut out,
    ),
    why::CONNECT_NEEDS_TUNNEL,
    &out,
  );
}

// ── send_response ─────────────────────────────────────────────────────────────

// The same agreement on the response side, plus the two rules that depend on the
// REQUEST rather than on this head: RFC 9112 §6.1's HTTP/1.0 `Transfer-Encoding`
// MUST NOT, and §6.3 item 1's bodiless statuses.
#[test]
fn send_response_refuses_a_head_that_contradicts_its_plan() {
  for (name, request, code, fields, plan, expected) in [
    (
      "both framing fields",
      GET_11,
      200u16,
      &[
        ("Content-Length", b"3".as_slice()),
        ("Transfer-Encoding", b"chunked"),
      ] as &[(&str, &[u8])],
      BodyPlan::Chunked,
      why::BOTH_FRAMINGS,
    ),
    (
      "two lengths that disagree",
      GET_11,
      200,
      &[("Content-Length", b"3"), ("Content-Length", b"4")],
      BodyPlan::ContentLength(3),
      why::LENGTH_IS_ONE_VALUE,
    ),
    (
      "a length list that disagrees with itself",
      GET_11,
      200,
      &[("Content-Length", b"3, 4")],
      BodyPlan::ContentLength(3),
      why::LENGTH_IS_ONE_VALUE,
    ),
    (
      "a length that is not the plan's",
      GET_11,
      200,
      &[("Content-Length", b"4")],
      BodyPlan::ContentLength(3),
      why::LENGTH_DISAGREES,
    ),
    (
      // §6.3 item 8: a response with a body and NEITHER field ends when the
      // connection does, which a connection that stays open is not about to do.
      "a body plan with no framing field",
      GET_11,
      200,
      NONE,
      BodyPlan::ContentLength(3),
      why::UNFRAMED_RESPONSE,
    ),
    (
      "a bodiless plan with no framing field",
      GET_11,
      200,
      NONE,
      BodyPlan::None,
      why::UNFRAMED_RESPONSE,
    ),
    (
      "a chunked plan the head never announced",
      GET_11,
      200,
      NONE,
      BodyPlan::Chunked,
      why::CHUNKED_UNANNOUNCED,
    ),
    (
      "chunked declared behind another coding",
      GET_11,
      200,
      &[("Transfer-Encoding", b"gzip, chunked")],
      BodyPlan::Chunked,
      why::CHUNKED_DECLARATION,
    ),
    (
      // Item 8 is the list's "otherwise": either field beside a close-delimited
      // body would have the peer ending the message where the close is not.
      "a close-delimited body with a length",
      GET_11,
      200,
      &[("Content-Length", b"3")],
      BodyPlan::CloseDelimited,
      why::CLOSE_DELIMITED_IS_UNFRAMED,
    ),
    (
      "a close-delimited body with a transfer coding",
      GET_11,
      200,
      &[("Transfer-Encoding", b"chunked")],
      BodyPlan::CloseDelimited,
      why::CLOSE_DELIMITED_IS_UNFRAMED,
    ),
    (
      // §6.1: the MUST NOT names the FIELD, so the head is refused even where
      // item 1 would make the recipient ignore it.
      "a chunked body to an HTTP/1.0 peer",
      GET_10,
      200,
      &[("Transfer-Encoding", b"chunked")],
      BodyPlan::Chunked,
      why::TE_NEEDS_HTTP_11,
    ),
    (
      "a transfer coding to an HTTP/1.0 peer under a counted plan",
      GET_10,
      200,
      &[("Transfer-Encoding", b"chunked"), ("Content-Length", b"3")],
      BodyPlan::ContentLength(3),
      why::TE_NEEDS_HTTP_11,
    ),
    (
      // Item 1, and the plan is what is wrong: a 204 is terminated by the empty
      // line that ends its head whatever the fields say.
      "a body under a 204",
      GET_11,
      204,
      &[("Content-Length", b"3")],
      BodyPlan::ContentLength(3),
      why::BODILESS_TAKES_NO_BODY,
    ),
    (
      "a body under a HEAD response",
      HEAD_11,
      200,
      &[("Content-Length", b"3")],
      BodyPlan::ContentLength(3),
      why::BODILESS_TAKES_NO_BODY,
    ),
    (
      // RFC 9112 §6.1 and RFC 9110 §8.6 name 204 specifically.
      "a framing field on a 204",
      GET_11,
      204,
      &[("Content-Length", b"0")],
      BodyPlan::None,
      why::BODILESS_STATUS_FRAMING,
    ),
    (
      // C3's class: item 1 tells the RECIPIENT to ignore these fields, which is
      // not a licence for the sender to write a §6.2 pair into them.
      "both framing fields on a HEAD response",
      HEAD_11,
      200,
      &[("Content-Length", b"5"), ("Transfer-Encoding", b"chunked")],
      BodyPlan::None,
      why::BOTH_FRAMINGS,
    ),
    (
      "an unreadable length on a HEAD response",
      HEAD_11,
      200,
      &[("Content-Length", b"3, 4")],
      BodyPlan::None,
      why::LENGTH_IS_ONE_VALUE,
    ),
    (
      "an unreadable length on a 304",
      GET_11,
      304,
      &[("Content-Length", b"abc")],
      BodyPlan::None,
      why::LENGTH_IS_ONE_VALUE,
    ),
    (
      "both framing fields on a 304",
      GET_11,
      304,
      &[("Content-Length", b"5"), ("Transfer-Encoding", b"chunked")],
      BodyPlan::None,
      why::BOTH_FRAMINGS,
    ),
    (
      // RFC 9110 §15.2: a 1xx is not the response that ends an exchange.
      "an interim status as the final response",
      GET_11,
      100,
      NONE,
      BodyPlan::None,
      why::INTERIM_NOT_FINAL,
    ),
    (
      // The same mode rule again, from the sending end.
      "a 101 on a General connection",
      GET_11,
      101,
      NONE,
      BodyPlan::None,
      why::SWITCHING_NEEDS_TUNNEL,
    ),
  ] {
    let mut connection = owed(request);
    let mut out = [SENTINEL; 128];
    refuses(
      name,
      connection.send_response(code, b"", fields, plan, &mut out),
      expected,
      &out,
    );
    // The response is still owed: a refusal costs the caller nothing but the
    // call, so a corrected message answers the same request.
    assert!(
      connection.is_awaiting_send(),
      "{name}: a refused response spent the exchange"
    );
  }
}

// ── field grammars, on the way out ────────────────────────────────────────────

// A field this core INTERPRETS is one it may only write in that field's own
// grammar. The receive side is deliberately tolerant — RFC 9110 §5.6.1.2 has a
// recipient "parse and ignore" empty elements, and §6.3 item 4 ¶2 has it
// close-delimit a `Transfer-Encoding` it cannot read — but none of that licenses
// a sender to GENERATE one. §5.6.1.1 states the sender's half in the opposite
// direction, and every rule below is that asymmetry applied to one more field.
//
// The hazard is specific: a value this end never fully parsed is one whose
// meaning at the recipient this end cannot predict, and framing is exactly the
// meaning that must not differ across the connection (§11.1, §11.2).
#[test]
fn every_interpreted_field_is_written_in_its_own_grammar() {
  for (name, fields, plan, expected) in [
    (
      // §7.6.1's `connection-option = token`: `@` is no token, so the value is
      // not a `Connection` header — and matching the `close` member of one that
      // does not parse would act on a field whose rest was never read.
      "a Connection option list with a member that is not a token",
      &[("Host", b"h".as_slice()), ("Connection", b"close,@")] as &[(&str, &[u8])],
      BodyPlan::None,
      why::FIELD_STATES_ITS_GRAMMAR,
    ),
    (
      "a Connection value that is nothing but a quoted string",
      &[("Host", b"h"), ("Connection", b"\"close\"")],
      BodyPlan::None,
      why::FIELD_STATES_ITS_GRAMMAR,
    ),
    (
      // §7.8's `protocol = protocol-name ["/" protocol-version]`.
      "an Upgrade list with a member that is not a protocol",
      &[("Host", b"h"), ("Upgrade", b"@")],
      BodyPlan::None,
      why::FIELD_STATES_ITS_GRAMMAR,
    ),
    (
      // §10.1.1's `expectation`, whose argument is a token or a quoted-string —
      // and an unterminated quote ends the value in the middle of one.
      "an Expect member with an unterminated quoted argument",
      &[
        ("Host", b"h"),
        ("Content-Length", b"3"),
        ("Expect", b"x=\"a"),
      ],
      BodyPlan::ContentLength(3),
      why::FIELD_STATES_ITS_GRAMMAR,
    ),
    (
      "an Expect member that is not a token at all",
      &[("Host", b"h"), ("Content-Length", b"3"), ("Expect", b"@")],
      BodyPlan::ContentLength(3),
      why::FIELD_STATES_ITS_GRAMMAR,
    ),
    (
      // `parameters` sits inside the optional group, so a parameter without an
      // argument is not an `expectation` — including on `100-continue` itself,
      // which §10.1.1 says has "no defined parameters".
      "an Expect member with a parameter and no argument",
      &[("Host", b"h"), ("Expect", b"100-continue;p=x")],
      BodyPlan::None,
      why::FIELD_STATES_ITS_GRAMMAR,
    ),
    (
      "another one, on an extension token",
      &[("Host", b"h"), ("Expect", b"ext;flag")],
      BodyPlan::None,
      why::FIELD_STATES_ITS_GRAMMAR,
    ),
    (
      // §5.6.6's `parameter` has no BWS around its `=`, unlike §7's
      // `transfer-parameter` — and §10.1.1's argument `=` has none either.
      "whitespace around an argument's equals",
      &[("Host", b"h"), ("Expect", b"ext = value")],
      BodyPlan::None,
      why::FIELD_STATES_ITS_GRAMMAR,
    ),
    (
      "whitespace around a parameter's equals",
      &[("Host", b"h"), ("Expect", b"ext=v;p = x")],
      BodyPlan::None,
      why::FIELD_STATES_ITS_GRAMMAR,
    ),
    (
      // §5.6.1.1's TRAILING empty, which escaped because two arms advanced past
      // a comma and only one of them recorded the element it opened.
      "a Transfer-Encoding list with a trailing empty element",
      &[("Host", b"h"), ("Transfer-Encoding", b"chunked,")],
      BodyPlan::Chunked,
      why::SENDER_LIST_EMPTY_ELEMENT,
    ),
    (
      "an empty element between two codings",
      &[("Host", b"h"), ("Transfer-Encoding", b"gzip,,chunked")],
      BodyPlan::Chunked,
      why::SENDER_LIST_EMPTY_ELEMENT,
    ),
    (
      // The same value split across §5.2's join, which is the same value.
      "a trailing empty element contributed by a second field line",
      &[
        ("Host", b"h"),
        ("Transfer-Encoding", b"chunked"),
        ("Transfer-Encoding", b""),
      ],
      BodyPlan::Chunked,
      why::SENDER_LIST_EMPTY_ELEMENT,
    ),
    (
      "a leading empty element contributed by the first field line",
      &[
        ("Host", b"h"),
        ("Transfer-Encoding", b""),
        ("Transfer-Encoding", b"chunked"),
      ],
      BodyPlan::Chunked,
      why::SENDER_LIST_EMPTY_ELEMENT,
    ),
    (
      // §5.6.1.1 again, on the field just added to the interpreted set.
      "an Expect list with an empty element",
      &[
        ("Host", b"h"),
        ("Content-Length", b"3"),
        ("Expect", b",100-continue"),
      ],
      BodyPlan::ContentLength(3),
      why::SENDER_LIST_EMPTY_ELEMENT,
    ),
    (
      // §10.1.1's own sender MUST NOT.
      "a 100-continue expectation on a request with no content",
      &[("Host", b"h"), ("Expect", b"100-continue")],
      BodyPlan::None,
      why::CONTINUE_NEEDS_CONTENT,
    ),
  ] {
    let mut connection = Connection::<Client, General>::new();
    let mut out = [SENTINEL; 160];
    refuses(
      name,
      connection.open_request("POST", &ORIGIN, fields, plan, &mut out),
      expected,
      &out,
    );
    // Inert in the FSM as well as in the buffer.
    assert!(
      connection
        .open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
        .is_ok(),
      "{name}: a refused open spent the exchange"
    );
  }

  // The WELL-FORMED twins, so what the rules refuse is the fault and not the
  // field: each of these carries the same field the vector above corrupted.
  for (name, fields, plan, wire) in [
    (
      "a Connection option list",
      &[("Host", b"h".as_slice()), ("Connection", b"close")] as &[(&str, &[u8])],
      BodyPlan::None,
      b"POST /r HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".as_slice(),
    ),
    (
      // A quoted-string is not a `connection-option`, but it IS a legal `Expect`
      // argument — the grammars differ, and so does what each field accepts.
      "an Expect member with a quoted argument",
      &[
        ("Host", b"h"),
        ("Content-Length", b"3"),
        ("Expect", b"x=\"a,b\""),
      ],
      BodyPlan::ContentLength(3),
      b"POST /r HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nExpect: x=\"a,b\"\r\n\r\n",
    ),
    (
      "a 100-continue expectation on a request that has content",
      &[
        ("Host", b"h"),
        ("Content-Length", b"3"),
        ("Expect", b"100-continue"),
      ],
      BodyPlan::ContentLength(3),
      b"POST /r HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n",
    ),
    (
      // §5.2 makes repeated lines ONE value, so a `quoted-string` argument may
      // legitimately span the join — the sender is checked over the combined
      // value for the same reason the recipient is, and the per-line check this
      // replaces refused a field that is perfectly well formed.
      "an Expect argument whose quoted-string spans two field lines",
      &[
        ("Host", b"h".as_slice()),
        ("Content-Length", b"3"),
        ("Expect", b"ext=\"a"),
        ("Expect", b"b\""),
      ],
      BodyPlan::ContentLength(3),
      b"POST /r HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nExpect: ext=\"a\r\nExpect: b\"\r\n\r\n"
        .as_slice(),
    ),
    (
      // `expectation = token [ "=" ( token / quoted-string ) parameters ]` puts
      // `parameters` INSIDE the optional group, so a member with a parameter
      // MUST carry an argument. This one does, and it is not the bare token
      // §10.1.1 defines — so it is written as the caller wrote it and read as no
      // ask at all.
      "a parameterised expectation with the argument its grammar requires",
      &[("Host", b"h"), ("Expect", b"ext=v;p=x")],
      BodyPlan::None,
      b"POST /r HTTP/1.1\r\nHost: h\r\nExpect: ext=v;p=x\r\n\r\n",
    ),
  ] {
    let mut connection = Connection::<Client, General>::new();
    let mut out = [SENTINEL; 160];
    let written = connection
      .open_request("POST", &ORIGIN, fields, plan, &mut out)
      .expect(name);
    assert_eq!(&out[..written], wire, "{name}");
  }
}

// The `Transfer-Encoding` case has its own test because it is the one where the
// old shape actually leaked: the coding list is READ by the chunked framing arm
// alone, so a response whose framing is settled by something else — RFC 9112
// §6.3 item 1's bodiless statuses, a HEAD's absent body — never asked whether
// the field parsed, and wrote it anyway. The recipient then takes item 4 ¶2's
// close-delimitation off a field this end never read, which is the two ends
// disagreeing about where the message stops.
#[test]
fn a_transfer_encoding_is_parsed_even_where_it_frames_nothing() {
  for (name, request, code, fields) in [
    (
      "a HEAD response, whose framing fields describe a body it does not send",
      HEAD_11,
      200u16,
      b"foo;p=\"a".as_slice(),
    ),
    (
      "a 304, where item 1 makes the recipient ignore the field",
      GET_11,
      304,
      b"chunked, @",
    ),
    ("a 200 with no body at all", GET_11, 200, b"gzip;\""),
  ] {
    let mut connection = owed(request);
    let mut out = [SENTINEL; 160];
    refuses(
      name,
      connection.send_response(
        code,
        b"",
        &[("Transfer-Encoding", fields)][..],
        BodyPlan::None,
        &mut out,
      ),
      why::FIELD_STATES_ITS_GRAMMAR,
      &out,
    );
    assert!(
      connection.is_awaiting_send(),
      "{name}: a refused response spent the exchange"
    );
  }

  // The well-formed twin on the same path: item 1 lets these fields describe the
  // body a different request would have received, so a PARSEABLE one still goes
  // out on a HEAD.
  let mut connection = owed(HEAD_11);
  let mut out = [SENTINEL; 160];
  let written = connection
    .send_response(
      200,
      b"OK",
      &[("Transfer-Encoding", b"chunked".as_slice())][..],
      BodyPlan::None,
      &mut out,
    )
    .expect("a well-formed coding list on a HEAD response");
  assert_eq!(
    &out[..written],
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
  );

  // And the twin that is only well formed once §5.2's lines are joined: a
  // `quoted-string` parameter spanning the join is a legal value, so the sender
  // check has to be over the COMBINED value here exactly as it is on the receive
  // side. Checked per line, this section was refused.
  let mut connection = owed(HEAD_11);
  let mut out = [SENTINEL; 192];
  let written = connection
    .send_response(
      200,
      b"OK",
      &[
        ("Transfer-Encoding", b"foo;p=\"a".as_slice()),
        ("Transfer-Encoding", b"b\", chunked"),
      ][..],
      BodyPlan::None,
      &mut out,
    )
    .expect("a coding list whose quoted parameter spans the join");
  assert_eq!(
    &out[..written],
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: foo;p=\"a\r\nTransfer-Encoding: b\", chunked\r\n\r\n"
  );
}

// ── send_interim ──────────────────────────────────────────────────────────────

// RFC 9112 §6.1 with RFC 9110 §8.6: a 1xx carries neither framing field, because
// there is nothing for one to frame — a recipient that read it would be framing
// the FINAL response's body off the interim's head. RFC 9110 §15.2 adds the
// version rule and the status range.
#[test]
fn send_interim_refuses_framing_and_the_wrong_status() {
  for (name, request, code, fields, expected) in [
    (
      "a length on a 1xx",
      GET_11,
      100u16,
      &[("Content-Length", b"0".as_slice())] as &[(&str, &[u8])],
      why::BODILESS_STATUS_FRAMING,
    ),
    (
      "a transfer coding on a 1xx",
      GET_11,
      100,
      &[("Transfer-Encoding", b"chunked")],
      why::BODILESS_STATUS_FRAMING,
    ),
    (
      "a final status through the interim call",
      GET_11,
      200,
      NONE,
      // The General constant, whose text happens to match Tunnel's
      // `why::NOT_INTERIM`: two rules, two sites, one wording.
      "only a 1xx response is interim",
    ),
    (
      "a 101 on a General connection",
      GET_11,
      101,
      NONE,
      why::SWITCHING_NEEDS_TUNNEL,
    ),
    (
      "a 1xx to an HTTP/1.0 client",
      GET_10,
      100,
      NONE,
      why::INTERIM_NEEDS_HTTP_11,
    ),
  ] {
    let mut connection = owed(request);
    let mut out = [SENTINEL; 128];
    refuses(
      name,
      connection.send_interim(code, fields, &mut out),
      expected,
      &out,
    );
    assert!(
      connection.is_awaiting_send(),
      "{name}: a refused interim moved the exchange"
    );
  }
}

// ── send_error_response ───────────────────────────────────────────────────────

/// A server whose connection has FAILED, owing its one error response.
fn failed() -> Connection<Server, General> {
  let mut connection = Connection::<Server, General>::new();
  {
    let mut items = connection.handle(b"GET /r HTTP/1.1\r\nHost : bad\r\n\r\n");
    assert!(items.next().is_err(), "the fixture is a §5.1 violation");
  }
  assert!(connection.is_awaiting_send());
  connection
}

// The ONE answer a failed connection may still write is bodiless and carries the
// `close` this core injects. Everything a caller could put in it that would make
// the peer read a body, a second message, or a success is refused — and refusing
// does not spend the answer.
#[test]
fn the_single_error_response_refuses_what_would_contradict_it() {
  for (name, code, fields, expected) in [
    (
      // RFC 9112 §6.3 item 6: the peer would treat the one answer it is going to
      // get as incomplete when the connection closes behind it.
      "an announced body",
      400u16,
      &[("Content-Length", b"5".as_slice())] as &[(&str, &[u8])],
      why::BODILESS_TAKES_NO_BODY,
    ),
    (
      "a transfer coding",
      400,
      &[("Transfer-Encoding", b"chunked")],
      why::BODILESS_TAKES_NO_BODY,
    ),
    (
      "an unreadable length",
      400,
      &[("Content-Length", b"3, 4")],
      why::LENGTH_IS_ONE_VALUE,
    ),
    (
      // RFC 9110 §5.3 folds repeated field lines into one list, so the caller's
      // and the injected one would be a single field saying two things.
      "a Connection field of the caller's own",
      400,
      &[("Connection", b"keep-alive")],
      why::CALLER_STATED_CONNECTION,
    ),
    ("an interim status", 100, NONE, why::INTERIM_NOT_FINAL),
    (
      // A phase whose whole meaning is "a rejection is owed" has no success
      // class to state — the same rule Tunnel's `reject` applies.
      "a success status",
      200,
      NONE,
      why::NO_SUCCESS_TO_STATE,
    ),
  ] {
    let mut connection = failed();
    let mut out = [SENTINEL; 128];
    refuses(
      name,
      connection.send_error_response(code, b"", fields, &mut out),
      expected,
      &out,
    );
    // The one answer is still owed: a refusal does not discharge it.
    assert!(
      connection.is_awaiting_send(),
      "{name}: a refused error response spent the single answer"
    );
    let mut good = [0u8; 128];
    let written = connection
      .send_error_response(400, b"Bad Request", NONE, &mut good)
      .expect("the corrected answer goes out");
    assert_eq!(
      good.get(..written),
      Some(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".as_slice()),
      "{name}"
    );
  }
}

// ── send_body / finish_body ───────────────────────────────────────────────────

/// A server with a counted response of `announced` octets under way.
fn counted(announced: &str, plan: u64) -> (Connection<Server, General>, [u8; 256]) {
  let mut connection = owed(GET_11);
  let mut out = [0u8; 256];
  let fields: &[(&str, &[u8])] = &[("Content-Length", announced.as_bytes())];
  connection
    .send_response(200, b"OK", fields, BodyPlan::ContentLength(plan), &mut out)
    .expect("the head and the plan agree");
  (connection, out)
}

/// A server with a chunked response under way.
fn chunked() -> (Connection<Server, General>, [u8; 256]) {
  let mut connection = owed(GET_11);
  let mut out = [0u8; 256];
  let fields: &[(&str, &[u8])] = &[("Transfer-Encoding", b"chunked")];
  connection
    .send_response(200, b"OK", fields, BodyPlan::Chunked, &mut out)
    .expect("the head and the plan agree");
  (connection, out)
}

// RFC 9112 §6.3 item 6: the body is exactly as long as the head said. An octet
// past the count is the next message's as far as the peer is concerned (§11.1),
// and a body that stops short leaves the peer waiting for octets that never come
// — so both ends of the count are refusals rather than best-effort writes.
#[test]
fn a_counted_body_is_exactly_as_long_as_its_head_said() {
  let (mut connection, _) = counted("3", 3);
  let mut out = [SENTINEL; 64];
  refuses(
    "an over-send past the announced length",
    connection.send_body(b"four", &mut out),
    why::OVER_SEND,
    &out,
  );
  // Still exactly three octets owed: the refusal wrote nothing and counted
  // nothing, so the correct body still goes out.
  let mut good = [0u8; 64];
  let written = connection
    .send_body(b"abc", &mut good)
    .expect("the announced octets");
  assert_eq!(good.get(..written), Some(b"abc".as_slice()));

  let (mut connection, _) = counted("3", 3);
  let mut good = [0u8; 64];
  connection
    .send_body(b"ab", &mut good)
    .expect("a partial write of a counted body is ordinary");
  let mut out = [SENTINEL; 64];
  refuses(
    "finishing a counted body one octet short",
    connection.finish_body(NO_TRAILERS, &mut out),
    why::BODY_INCOMPLETE,
    &out,
  );
}

// RFC 9112 §7.1.2 gives the trailer section to the chunked coding alone: a
// counted or close-delimited body has nowhere to put one, so the fields would go
// on the wire as the next message's head. And RFC 9110 §6.5.1 bounds what may be
// in the section even where there is one.
#[test]
fn trailers_belong_to_a_chunked_body_and_exclude_the_framing_fields() {
  let (mut connection, _) = counted("2", 2);
  let mut good = [0u8; 64];
  connection.send_body(b"ab", &mut good).expect("the body");
  let mut out = [SENTINEL; 64];
  let trailer: &[(&str, &[u8])] = &[("X-Sum", b"ok")];
  refuses(
    "a trailer section on a counted body",
    connection.finish_body(Some(trailer), &mut out),
    why::UNCHUNKED_HAS_NO_TRAILERS,
    &out,
  );

  for (name, trailer) in [
    (
      "Content-Length in a trailer section",
      &[("Content-Length", b"0".as_slice())] as &[(&str, &[u8])],
    ),
    (
      "Transfer-Encoding in a trailer section",
      &[("Transfer-Encoding", b"chunked")],
    ),
    ("Host in a trailer section", &[("Host", b"elsewhere")]),
    ("Trailer in a trailer section", &[("Trailer", b"X-Sum")]),
    (
      "a banned name among benign ones",
      &[("X-Sum", b"ok"), ("content-length", b"0")],
    ),
  ] {
    let (mut connection, _) = chunked();
    let mut out = [SENTINEL; 128];
    refuses(
      name,
      connection.finish_body(Some(trailer), &mut out),
      why::FORBIDDEN_TRAILER,
      &out,
    );
    // The body is still open, so a corrected section still ends the message.
    let mut good = [0u8; 128];
    assert!(
      connection.finish_body(NO_TRAILERS, &mut good).is_ok(),
      "{name}: a refused trailer section ended the body"
    );
  }
}

// RFC 9112 §7.1 spells `last-chunk` as `1*("0")`, so a zero-size chunk header IS
// the end of the body: emitting one mid-body would end the message and leave the
// payload behind it to be read as the next one. An empty `send_body` therefore
// writes nothing at all rather than a `0` line.
#[test]
fn an_empty_chunk_is_never_written_as_a_zero_size_header() {
  let (mut connection, _) = chunked();
  let mut out = [SENTINEL; 64];
  assert_eq!(
    connection.send_body(b"", &mut out),
    Ok(0),
    "an empty chunk writes nothing"
  );
  assert!(
    out.iter().all(|&byte| byte == SENTINEL),
    "an empty chunk put bytes on the wire"
  );
  // …and the body is still open, which is what says the empty call was a no-op
  // rather than the `last-chunk` under another name: a `0` line on the wire
  // would have ENDED the message here.
  let mut good = [0u8; 64];
  let written = connection
    .send_body(b"ab", &mut good)
    .expect("the body is still open");
  assert_eq!(good.get(..written), Some(b"2\r\nab\r\n".as_slice()));
}

// ── tunnel handshakes ─────────────────────────────────────────────────────────

// RFC 9110 §9.3.6 ("A CONNECT request message does not have content") and §7.8:
// every message a tunnel writes IS its head, so a head announcing octets would
// leave the peer waiting for a body this mode has no machinery to send. The
// §7.8 offer rules and the §3.2.3 port rule are checked in the same place.
#[test]
fn a_tunnel_handshake_refuses_what_it_cannot_write() {
  let counted_offer: &[(&str, &[u8])] = &[
    ("Host", b"h"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
    ("Content-Length", b"5"),
  ];
  let chunked_offer: &[(&str, &[u8])] = &[
    ("Host", b"h"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
    ("Transfer-Encoding", b"chunked"),
  ];
  let half_offer: &[(&str, &[u8])] = &[("Host", b"h"), ("Upgrade", b"websocket")];

  for (name, fields, expected) in [
    (
      "an offer announcing content",
      counted_offer,
      why::HANDSHAKE_HAS_NO_CONTENT,
    ),
    (
      "an offer announcing a transfer coding",
      chunked_offer,
      why::HANDSHAKE_HAS_NO_CONTENT,
    ),
    (
      "an offer missing its connection option",
      half_offer,
      why::OFFER_NEEDS_BOTH_HALVES,
    ),
    (
      "an offer that states no Host",
      &[("Connection", b"Upgrade"), ("Upgrade", b"websocket")],
      why::REQUEST_NEEDS_HOST,
    ),
    // RFC 9112 §3.2's other two `Host` MUSTs reach Tunnel mode too: they are
    // scoped to "any request message", and this is one.
    (
      "an offer stating two Host lines",
      &[
        ("Host", b"a.example"),
        ("Host", b"b.example"),
        ("Connection", b"Upgrade"),
        ("Upgrade", b"websocket"),
      ],
      why::ONE_HOST_LINE,
    ),
    (
      "an offer whose Host is not an authority",
      &[
        ("Host", b"bad host"),
        ("Connection", b"Upgrade"),
        ("Upgrade", b"websocket"),
      ],
      why::HOST_NOT_AUTHORITY,
    ),
  ] {
    let mut connection = Connection::<Client, Tunnel>::new();
    let mut out = [SENTINEL; 192];
    refuses(
      name,
      connection.open_upgrade(&ORIGIN, fields, &mut out),
      expected,
      &out,
    );
    // The handshake never began, so a corrected offer still opens one.
    assert!(
      connection.open_upgrade(&ORIGIN, OFFER, &mut out).is_ok(),
      "{name}: a refused offer began the handshake"
    );
  }

  // The target forms §3.2.3 and §3.2.4 give to other methods.
  let mut connection = Connection::<Client, Tunnel>::new();
  let mut out = [SENTINEL; 192];
  refuses(
    "an upgrade offer with an authority-form target",
    connection.open_upgrade(
      &Target::Authority {
        host_port: DESTINATION,
      },
      OFFER,
      &mut out,
    ),
    why::SWITCH_TARGET_FORM,
    &out,
  );

  // RFC 9110 §9.3.6: "There is no default port; a client MUST send the port
  // number", whose server half is a MUST to reject "an empty or invalid port
  // number". RFC 3986 §3.2.3's `port = *DIGIT` bounds neither, because a URI
  // scheme decides what its port means; a CONNECT port is the TCP port of the
  // tunnel's far end, so a number past 65535 addresses nothing and `0` is not a
  // destination a peer can be asked to reach.
  for (name, target) in [
    ("a CONNECT target with no port", "example.com"),
    ("a CONNECT target with an empty port", "example.com:"),
    (
      "a CONNECT port one past the 16-bit range",
      "example.com:65536",
    ),
    (
      "a CONNECT port no integer holds",
      "example.com:184467440737095516160",
    ),
    ("a CONNECT port of zero", "example.com:0"),
    ("an IPv6 CONNECT port past the range", "[::1]:65536"),
  ] {
    let mut connection = Connection::<Client, Tunnel>::new();
    refuses(
      name,
      connection.open_connect(target, CONNECT_HOST, &mut out),
      why::CONNECT_NEEDS_A_PORT,
      &out,
    );
  }

  let mut connection = Connection::<Client, Tunnel>::new();
  refuses(
    "a CONNECT announcing content",
    connection.open_connect(
      DESTINATION,
      &[
        ("Host", b"example.com:443".as_slice()),
        ("Content-Length", b"5"),
      ] as &[(&str, &[u8])],
      &mut out,
    ),
    why::HANDSHAKE_HAS_NO_CONTENT,
    &out,
  );

  // The `Host` rules on the CONNECT path, which shares `requires_host` with the
  // other two: §3.2.3's authority-form target is CONNECT's addressing rule, not
  // an exemption from any of §3.2's three MUSTs.
  for (name, fields, expected) in [
    (
      "a CONNECT stating two Host lines",
      &[
        ("Host", b"a.example:443".as_slice()),
        ("Host", b"b.example:443"),
      ] as &[(&str, &[u8])],
      why::ONE_HOST_LINE,
    ),
    (
      "a CONNECT whose Host is not an authority",
      &[("Host", b"bad host")],
      why::HOST_NOT_AUTHORITY,
    ),
    (
      "a CONNECT that states no Host",
      NONE,
      why::REQUEST_NEEDS_HOST,
    ),
  ] {
    let mut connection = Connection::<Client, Tunnel>::new();
    let mut out = [SENTINEL; 192];
    refuses(
      name,
      connection.open_connect(DESTINATION, fields, &mut out),
      expected,
      &out,
    );
    assert!(
      connection
        .open_connect(DESTINATION, CONNECT_HOST, &mut out)
        .is_ok(),
      "{name}: a refused CONNECT began the handshake"
    );
  }
}

// The Tunnel-mode half of the round trip: a handshake request this crate's
// client writes is one this crate's own tunnel SERVER classifies.
//
// `classify` runs the full `validate_request` — RFC 9112 §3.2's `Host` rules and
// the §3.2.3/§3.2.4 pairing among them — so an `open_upgrade` or `open_connect`
// that emitted a request failing any of them would produce a handshake neither
// end of this crate could complete.
#[test]
fn every_handshake_request_this_core_writes_is_one_it_classifies() {
  let empty_host: &[(&str, &[u8])] = &[
    ("Host", b""),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
  ];
  let zero_length: &[(&str, &[u8])] = &[
    ("Host", b"h"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
    ("Content-Length", b"0"),
  ];

  for (name, fields) in [
    ("an ordinary offer", OFFER),
    ("an offer with an empty Host", empty_host),
    ("an offer stating Content-Length: 0", zero_length),
  ] {
    let mut client = Connection::<Client, Tunnel>::new();
    let mut out = [SENTINEL; 256];
    let n = client
      .open_upgrade(&ORIGIN, fields, &mut out)
      .unwrap_or_else(|error| panic!("{name}: refused a valid offer: {error:?}"));
    let mut server = Connection::<Server, Tunnel>::new();
    assert!(
      server.handle_request(&out[..n]).is_ok(),
      "{name}: our own tunnel server refused what we wrote"
    );
  }

  let mut client = Connection::<Client, Tunnel>::new();
  let mut out = [SENTINEL; 256];
  let n = client
    .open_connect(DESTINATION, CONNECT_HOST, &mut out)
    .expect("a CONNECT with a port and a Host opens the handshake");
  let mut server = Connection::<Server, Tunnel>::new();
  assert!(server.handle_request(&out[..n]).is_ok());
}

/// A tunnel server that has classified an upgrade offer and owes the answer.
fn classified_upgrade() -> Connection<Server, Tunnel> {
  let mut connection = Connection::<Server, Tunnel>::new();
  connection
    .handle_request(
      b"GET /r HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    )
    .expect("the fixture is a well-formed offer");
  connection
}

/// A tunnel server that has classified a CONNECT and owes the answer.
fn classified_connect() -> Connection<Server, Tunnel> {
  let mut connection = Connection::<Server, Tunnel>::new();
  connection
    .handle_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    .expect("the fixture is a well-formed CONNECT");
  connection
}

// RFC 9112 §6.1 with RFC 9110 §8.6 and §9.3.6: the head that SWITCHES frames
// nothing at all, not even `Content-Length: 0` — what follows it is not a body.
// §15.2.2 makes the `Upgrade` field a MUST on the 101 that answers an offer.
#[test]
fn the_head_that_switches_frames_nothing() {
  let switch: &[(&str, &[u8])] = &[("Upgrade", b"websocket"), ("Connection", b"Upgrade")];
  let framed_switch: &[(&str, &[u8])] = &[
    ("Upgrade", b"websocket"),
    ("Connection", b"Upgrade"),
    ("Content-Length", b"0"),
  ];

  let mut connection = classified_upgrade();
  let mut out = [SENTINEL; 192];
  refuses(
    "a 101 carrying a framing field",
    connection.accept(framed_switch, &mut out),
    why::SWITCH_HAS_NO_FRAMING,
    &out,
  );
  refuses(
    "a 101 that names no protocol",
    connection.accept(NONE, &mut out),
    why::SWITCH_NEEDS_BOTH_HALVES,
    &out,
  );
  assert!(
    connection.accept(switch, &mut out).is_ok(),
    "a refused accept spent the handshake"
  );

  let mut connection = classified_connect();
  let mut out = [SENTINEL; 192];
  refuses(
    "a CONNECT 2xx carrying a framing field",
    connection.accept(
      &[("Content-Length", b"0".as_slice())] as &[(&str, &[u8])],
      &mut out,
    ),
    why::SWITCH_HAS_NO_FRAMING,
    &out,
  );
}

// RFC 9110 §15.2 with §7.8: an interim response is a fact about a handshake
// still being decided, so it neither switches nor refuses — and carries no
// framing field either (RFC 9112 §6.1, RFC 9110 §8.6).
#[test]
fn a_tunnel_interim_neither_switches_nor_frames() {
  for (name, code, fields, expected) in [
    (
      "a framing field on a 1xx",
      100u16,
      &[("Content-Length", b"0".as_slice())] as &[(&str, &[u8])],
      why::INTERIM_HAS_NO_FRAMING,
    ),
    (
      "a 101 through the interim call",
      101,
      NONE,
      why::SWITCH_THROUGH_ACCEPT,
    ),
    ("a final status through it", 200, NONE, why::NOT_INTERIM),
  ] {
    let mut connection = classified_upgrade();
    let mut out = [SENTINEL; 192];
    refuses(
      name,
      connection.send_interim(code, fields, &mut out),
      expected,
      &out,
    );
  }
}

// RFC 9110 §9.3.6: "Any 2xx (Successful) response indicates that the sender …
// will switch to tunnel mode immediately after the response header section" — so
// a 2xx written as a REFUSAL of a CONNECT would leave the peer tunnelling while
// this end recorded a refusal, and the two would disagree about whether the
// connection is still HTTP. A refusal also carries no body this core will write.
#[test]
fn a_refusal_never_writes_the_status_that_switches() {
  for (name, code, expected) in [
    ("a 101 through reject", 101u16, why::SWITCH_THROUGH_ACCEPT),
    ("an interim through reject", 100, why::NOT_INTERIM),
  ] {
    let mut connection = classified_upgrade();
    let mut out = [SENTINEL; 192];
    refuses(
      name,
      connection.reject(code, b"", NONE, &mut out),
      expected,
      &out,
    );
  }

  // On a CONNECT the whole 2xx class switches, so none of it refuses.
  for code in [200u16, 201, 299] {
    let mut connection = classified_connect();
    let mut out = [SENTINEL; 192];
    refuses(
      "a 2xx through reject on a CONNECT",
      connection.reject(code, b"", NONE, &mut out),
      why::SWITCH_THROUGH_ACCEPT,
      &out,
    );
  }

  // A refusal announcing content would leave the peer waiting for octets this
  // mode has no machinery to write (RFC 9112 §6.3 item 6).
  let mut connection = classified_upgrade();
  let mut out = [SENTINEL; 192];
  refuses(
    "a refusal announcing content",
    connection.reject(
      426,
      b"Upgrade Required",
      &[("Content-Length", b"5".as_slice())] as &[(&str, &[u8])],
      &mut out,
    ),
    why::HANDSHAKE_HAS_NO_CONTENT,
    &out,
  );
  // Still owed: a refused reject does not spend the single answer.
  assert!(
    connection
      .reject(426, b"Upgrade Required", NONE, &mut out)
      .is_ok()
  );
}

// ── the corpus floor ──────────────────────────────────────────────────────────

/// This file's own source, for the floor below.
const SOURCE: &str = include_str!("smuggling_outbound.rs");

// A FLOOR on the corpus, measured off the source text because the vectors live
// in per-entry-point tables rather than in one list: each `why::` reference is a
// vector naming the exact rule it exists for, and a silent deletion is what this
// catches. Set below the current count so ordinary additions do not have to
// touch it, and high enough that removing a table would fail.
//
// Every constant in `why` is also asserted REACHED — a refusal constant nothing
// names is a rule this corpus does not cover, which is precisely the gap that
// let the send side ship without an adversarial suite at all.
#[test]
fn the_outbound_corpus_keeps_its_vectors() {
  let referenced = SOURCE.matches("why::").count();
  // Each constant is defined once (`pub const NAME`) and referenced through
  // `why::NAME` at least once by the vector that states it.
  let defined = SOURCE.matches("  pub const ").count();
  assert!(
    referenced >= 55,
    "the outbound corpus lost vectors: {referenced} `why::` references"
  );
  assert!(
    defined >= 30,
    "the outbound corpus lost refusal constants: {defined} defined"
  );

  for line in SOURCE.lines() {
    let Some(rest) = line.strip_prefix("  pub const ") else {
      continue;
    };
    let name = rest.split(':').next().unwrap_or_default().trim();
    assert!(
      SOURCE.contains(&format!("why::{name}")),
      "`why::{name}` is defined but no vector names it"
    );
  }
}
