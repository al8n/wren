//! Inbound-FSM tests: one connection, fed the bytes a peer would send, checked
//! against the items it hands back and the readiness it reports.
//!
//! Everything here is borrowed slices and small `Copy` values — no `Vec`, no
//! `format!` — so the whole module runs on the bare `no_std` tier alongside the
//! heap ones.

use super::{
  outbound::{
    BODILESS_STATUS_FRAMING, BODY_INCOMPLETE, BOTH_FRAMINGS, CHUNKED_DECLARATION,
    CHUNKED_UNANNOUNCED, CLOSE_DELIMITED_IS_UNFRAMED, CONTINUE_NEEDS_CONTENT,
    FIELD_STATES_ITS_GRAMMAR, INTERIM_NEEDS_HTTP_11, LENGTH_DISAGREES, LENGTH_IS_ONE_VALUE,
    NO_BODY_IN_FLIGHT, NO_SUCCESS_TO_STATE, OFFER_HAS_NO_CONTENT, OVER_SEND, READ_SIDE_ENDED,
    REFUSED_BODY_NEEDS_CLOSE, REFUSED_BODY_TAKES_NO_INTERIM, REFUSED_RESPONSE_ENDS_THE_REQUEST,
    REQUEST_IS_NEVER_CLOSE_DELIMITED, REQUEST_NEEDS_HOST, SENDER_LIST_EMPTY_ELEMENT,
    TE_NEEDS_HTTP_11, TE_WITHOUT_CHUNKED, UNCHUNKED_HAS_NO_TRAILERS, UNFRAMED_RESPONSE,
    UPGRADE_NEEDS_TUNNEL,
  },
  *,
};
use crate::{
  body::encode::FORBIDDEN_TRAILER,
  // Fully qualified: the glob above is shadowed by this module's own `tunnel`
  // submodule, which holds the Tunnel-mode fixtures.
  connection::{
    inbound::SWITCH_AFTER_CLOSE,
    tunnel::{
      OFFER_NEEDS_BOTH_HALVES, SWITCH_NEEDS_BOTH_HALVES, SWITCH_WAS_NEVER_OFFERED,
      TAKEOVER_STATES_NO_CLOSE,
    },
  },
  error::{Error, H1Error, Refusal, SuggestedStatus},
  event::{Item, NO_BODY_BEING_RECEIVED, SWITCHED, StartLine},
  head::{Target, scan::MAX_LEADING_EMPTY_LINES},
};

/// A request with no framing fields at all: RFC 9112 §6.3 item 7 gives it no
/// body, so its whole message is its head.
const BODILESS: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";

/// The RFC 9112 §3.2.1 origin-form target of every request opened here.
const ORIGIN: Target<'static> = Target::Origin {
  path_and_query: "/",
};

/// The one field a request that is not about framing needs (RFC 9112 §3.2).
const HOST: &[(&str, &[u8])] = &[("Host", b"h")];

/// No field lines at all.
const NO_FIELDS: &[(&str, &[u8])] = &[];

/// What a response with no body announces on a connection that is staying open:
/// RFC 9112 §6.3 item 8 makes a response carrying no framing field at all
/// close-delimited, which is not what a keep-alive response means.
const LENGTH_0: &[(&str, &[u8])] = &[("Content-Length", b"0")];

/// The driver step that follows an EOF: re-offer what is left of the buffer, and
/// report what the connection concluded.
///
/// `handle_eof` observes the transport and nothing else — it cannot see the
/// driver's buffer — so every conclusion that depends on the ABSENCE of further
/// bytes is drawn here, on the offer that runs out. An EMPTY slice is a
/// sufficient re-offer, and is what resolves the EOF when nothing is left.
#[track_caller]
fn resolve_eof<Ro: Role>(c: &mut Connection<Ro, General>, rest: &[u8]) -> Result<(), Error> {
  let mut items = c.handle(rest);
  while items.next()?.is_some() {}
  Ok(())
}

/// Feeds a whole request and drains the items it produces, leaving the
/// connection where a server driver stands with the response owed.
fn feed_request(c: &mut Connection<Server, General>, request: &[u8]) {
  let mut it = c.handle(request);
  while it.next().unwrap().is_some() {}
}

/// Opens a bodiless request through the real send API — what leaves a client
/// with an exchange outstanding for the response tests below to answer.
///
/// The state a sent request leaves behind is produced by sending one, never by
/// a test-only seeding hook.
fn open_bodiless_request(c: &mut Connection<Client, General>, method: &str) {
  let mut out = [0u8; 64];
  let n = c
    .open_request(method, &ORIGIN, HOST, BodyPlan::None, &mut out)
    .unwrap();
  assert_eq!(n, out_len(method));
}

/// The size of the head `open_bodiless_request` writes, spelled out so the
/// helper pins the bytes rather than merely counting them.
fn out_len(method: &str) -> usize {
  method
    .len()
    .saturating_add(b" / HTTP/1.1\r\nHost: h\r\n\r\n".len())
}

/// Sends a bodiless final response through the real send API, which is what
/// discharges the send half of RFC 9112 §9.3.2's re-arm gate.
///
/// The gate opens because a response was written, never because a test hook said so.
fn send_bodiless_response(c: &mut Connection<Server, General>) {
  let mut out = [0u8; 64];
  let n = c
    .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
    .unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
}

/// Feeds the slice and pulls every item to exhaustion, so a request with a body
/// ends at `RecvState::AwaitingRearm` and `ExchangeComplete` has been yielded.
/// Returns the consumed byte count.
fn drain(c: &mut Connection<Server, General>, input: &[u8]) -> usize {
  let mut it = c.handle(input);
  while it.next().unwrap().is_some() {}
  it.consumed()
}

/// Has read the head of a `POST` carrying `Expect: 100-continue` and a
/// `Content-Length`, with the body not yet fed, so `expect_unanswered` is set
/// and the 100 is still owed.
fn server_awaiting_expect() -> Connection<Server, General> {
  let mut c = Connection::<Server, General>::new();
  drain(
    &mut c,
    b"POST /x HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
  );
  c
}

// RFC 9112 §2.1 (`HTTP-message = start-line CRLF *( field-line CRLF ) CRLF
// [ message-body ]`) with §6.3 item 6 (`Content-Length` frames the body): the
// driver is handed the head, then the body octets, then the end of the
// exchange, and the offer is consumed in full.
#[test]
fn server_parses_request_head_then_body() {
  let mut c = Connection::<Server, General>::new();
  let input = b"POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello";
  let mut it = c.handle(input);
  let Some(Item::Head {
    exchange,
    view,
    line,
    interim: false,
  }) = it.next().unwrap()
  else {
    panic!("expected the request head")
  };
  // RFC 9112 §3: the request-line the core parsed to frame this message travels
  // out with it, so a driver routes on the method and target it was handed.
  let StartLine::Request(request) = line else {
    panic!("a server head carries a request-line")
  };
  assert_eq!(request.method, "POST");
  assert_eq!(
    request.target,
    Target::Origin {
      path_and_query: "/up"
    }
  );
  // The core mints the id; the first exchange on a connection is 1.
  assert_eq!(exchange.get(), 1);
  assert_eq!(view.header("host"), Some(b"h".as_slice()));
  let Some(Item::BodyChunk {
    data: b"hello",
    exchange: body_at,
  }) = it.next().unwrap()
  else {
    panic!("expected the body")
  };
  assert_eq!(body_at, exchange);
  // The head's view is still readable after later items were pulled: an item
  // borrows the INPUT, never the iterator (the `Items` lifetime contract).
  assert_eq!(view.header("content-length"), Some(b"5".as_slice()));
  let Some(Item::ExchangeComplete { .. }) = it.next().unwrap() else {
    panic!("expected the end of the exchange")
  };
  assert!(it.next().unwrap().is_none());
  assert_eq!(it.consumed(), input.len());
}

// RFC 9112 §2.2: a head is consumed only once its whole block is present, so a
// split feed reports zero and the driver keeps accumulating into the same buffer.
#[test]
fn need_more_consumes_zero_for_partial_head() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(b"GET / HTTP/1.1\r\nHost:");
  assert!(it.next().unwrap().is_none());
  assert_eq!(it.consumed(), 0); // driver keeps accumulating
  // …and the core still wants bytes rather than a local send.
  assert!(c.wants_read());
  assert!(!c.is_awaiting_send());
}

// RFC 9112 §9.3.2: a server MUST NOT process a pipelined request before the
// previous response is complete, so the second request's bytes stay in the
// driver's buffer until the send side catches up.
#[test]
fn pipelined_second_request_left_unconsumed() {
  let mut c = Connection::<Server, General>::new();
  let two = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
  let mut it = c.handle(two);
  // First exchange fully parses…
  while it.next().unwrap().is_some() {}
  let first_len = BODILESS.len();
  // …but bytes beyond it stay unconsumed until the response is sent.
  assert_eq!(it.consumed(), first_len);
  // Reading the socket cannot help; the local send side is what is missing.
  assert!(c.is_awaiting_send());
  assert!(!c.wants_read());

  // With the response through, the held bytes become the next exchange — and
  // the id the core mints for it is the next one in order (RFC 9112 §9.3.2
  // makes the order the only thing associating a response to its request).
  send_bodiless_response(&mut c);
  let mut it2 = c.handle(two.get(first_len..).unwrap());
  let Some(Item::Head { exchange, .. }) = it2.next().unwrap() else {
    panic!("expected the pipelined request's head")
  };
  assert_eq!(exchange.get(), 2);
}

// RFC 9112 §9.3.2 gates re-arm on BOTH directions, in whichever order they
// finish: a server that answered before it had read the request out re-arms the
// moment that body ends, and the request pipelined behind it becomes the next
// exchange without waiting for another offer.
#[test]
fn a_response_finished_early_re_arms_when_the_request_body_ends() {
  const COUNTED_HEAD: &[u8] = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n";
  let two =
    b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
  assert!(two.starts_with(COUNTED_HEAD));

  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(two.get(..COUNTED_HEAD.len()).unwrap());
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  assert!(it.next().unwrap().is_none());

  // The driver answers on the head alone — a response needs no body read first.
  send_bodiless_response(&mut c);
  assert!(c.wants_read()); // the request body is still owed by the peer
  assert!(!c.is_awaiting_send());

  // The body and the pipelined request arrive together.
  let mut it2 = c.handle(two.get(COUNTED_HEAD.len()..).unwrap());
  assert!(matches!(
    it2.next().unwrap(),
    Some(Item::BodyChunk { data: b"hello", .. })
  ));
  assert!(matches!(
    it2.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
  let Some(Item::Head { exchange, .. }) = it2.next().unwrap() else {
    panic!("expected the pipelined request's head")
  };
  assert_eq!(exchange.get(), 2);
  assert_eq!(it2.consumed(), two.len().saturating_sub(COUNTED_HEAD.len()));
}

// RFC 9110 §15.2.1: any number of interim (1xx) responses may precede the final
// one and a client MUST be able to parse them; an interim does not end the
// exchange, does not begin a body, and mints no new id.
#[test]
fn client_handles_interim_then_final() {
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  let mut it = c.handle(b"HTTP/1.1 100 \r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
  let Some(Item::Head {
    exchange: interim_at,
    interim: true,
    ..
  }) = it.next().unwrap()
  else {
    panic!("expected the interim head")
  };
  let Some(Item::Head {
    exchange: final_at,
    interim: false,
    ..
  }) = it.next().unwrap()
  else {
    panic!("expected the final head")
  };
  // Same exchange: an interim response continues the one it precedes.
  assert_eq!(interim_at, final_at);
  let Some(Item::BodyChunk { data: b"ok", .. }) = it.next().unwrap() else {
    panic!("expected the body")
  };
  let Some(Item::ExchangeComplete { .. }) = it.next().unwrap() else {
    panic!("expected the end of the exchange")
  };
  assert!(it.next().unwrap().is_none());
}

// RFC 9110 §10.1.1: a request carrying `Expect: 100-continue` asks the server to
// approve the head before the body arrives, so the ask is surfaced right after
// the head it belongs to.
#[test]
fn expect_continue_surfaced() {
  let mut c = Connection::<Server, General>::new();
  let mut it =
    c.handle(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n");
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::ExpectContinue { .. })
  ));
  // The body is still owed, so the bytes it needs are what the core wants.
  assert!(it.next().unwrap().is_none());
}

// RFC 9110 §10.1.1's ask is ended by a SEND, never by the receive side handing
// the item over. Those are different events: a driver may answer the head the
// moment it reads it, before or without ever pulling the item, and §15.2 then
// leaves no room for the ask to resurface.
//
// Both halves below are the same defect from the two directions a driver can
// answer in.
#[test]
fn the_expectation_is_discharged_by_the_send_that_answers_it() {
  const ASKING: &[u8] =
    b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n";
  let none: &[(&str, &[u8])] = &[];
  let mut out = [0u8; 96];

  // The driver reads the head, drops the iterator without pulling the ask, and
  // answers it. Re-offering must not hand it the ask it has already met — a
  // second `100` on the wire is a second informational response to one request.
  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(ASKING);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  }
  let n = c.send_interim(100, none, &mut out).unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 100 \r\n\r\n");
  {
    let mut it = c.handle(b"abc");
    assert!(
      matches!(
        it.next().unwrap(),
        Some(Item::BodyChunk { data: b"abc", .. })
      ),
      "the answered ask is not handed over again"
    );
  }

  // The other direction: the driver answers the request outright. §15.2 puts
  // every informational response BEFORE the final one, so an ask surfaced after
  // this one asks a driver to write a 1xx the specification forbids.
  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(ASKING);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  }
  // `Content-Length: 0` because RFC 9112 §6.3 item 8 would otherwise
  // close-delimit a 417 that states no framing field at all.
  let empty: &[(&str, &[u8])] = &[("Content-Length", b"0")];
  let answered = c.send_response(417, b"Expectation Failed", empty, BodyPlan::None, &mut out);
  assert!(answered.is_ok(), "{answered:?}");
  {
    let mut it = c.handle(b"abc");
    let first = it.next().unwrap();
    assert!(
      !matches!(first, Some(Item::ExpectContinue { .. })),
      "a stale ask followed the final response: {first:?}"
    );
  }
}

// The discharge is ATOMIC with the encode, so a refused one leaves the ask
// exactly as it was: nothing was written, so nothing answered it, and the
// obligation a driver would otherwise have lost is still there to pull.
#[test]
fn a_refused_interim_leaves_the_expectation_owed() {
  let mut c = Connection::<Server, General>::new();
  {
    let mut it =
      c.handle(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  }
  // RFC 9112 §6.1 with RFC 9110 §8.6: a 1xx carries no framing field.
  let mut out = [0xAAu8; 96];
  let framed: &[(&str, &[u8])] = &[("Content-Length", b"0")];
  assert!(matches!(
    c.send_interim(100, framed, &mut out),
    Err(Error::InvalidState(_))
  ));
  assert_eq!(out, [0xAAu8; 96], "a refused encode writes nothing");
  {
    let mut it = c.handle(b"abc");
    assert!(
      matches!(it.next().unwrap(), Some(Item::ExpectContinue { .. })),
      "a refused answer discharges nothing"
    );
  }

  // And the refusal the ENCODER makes, which is the one that pins the ordering:
  // every check above it happens before a byte is measured, so a discharge
  // placed anywhere earlier than the encode's own success would survive them
  // all. RFC 9112 §2.1 makes a message one thing — a head that did not fit was
  // not sent, so it answered nothing.
  let mut c = Connection::<Server, General>::new();
  {
    let mut it =
      c.handle(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  }
  let mut cramped = [0xAAu8; 4];
  let none: &[(&str, &[u8])] = &[];
  assert!(c.send_interim(100, none, &mut cramped).is_err());
  assert_eq!(cramped, [0xAAu8; 4]);
  let mut it = c.handle(b"abc");
  assert!(
    matches!(it.next().unwrap(), Some(Item::ExpectContinue { .. })),
    "a head that did not fit answered nothing"
  );
}

// The Expect fact must outlive the transient one: RecvState::Body's copy is
// gone by the time an answer is written.
#[test]
fn the_expect_fact_survives_the_body_it_arrived_with() {
  const REQ: &[u8] = b"POST /x HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\n\
Content-Length: 3\r\n\r\nabc";
  let mut c = Connection::<Server, General>::new();
  drain(&mut c, REQ);
  let exchange = c.exchange.expect("the exchange is still in flight");
  assert!(exchange.expect_unanswered, "the answer still owes a 100");
}

#[test]
fn a_hundred_continue_discharges_the_durable_expect_fact() {
  let mut c = server_awaiting_expect();
  let mut out = [0u8; 64];
  c.send_interim(100, NO_FIELDS, &mut out).unwrap();
  assert!(!c.exchange.expect("still in flight").expect_unanswered);
}

#[test]
fn the_final_response_discharges_the_durable_expect_fact() {
  let mut c = server_awaiting_expect();
  let mut out = [0u8; 128];
  c.send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
    .unwrap();
  assert!(c.exchange.is_none_or(|e| !e.expect_unanswered));
}

// The ask is the CLIENT's to make (RFC 9110 §10.1.1), so a request that made
// none leaves nothing owed. The negative half of the three tests above: without
// it a field hardcoded to `true` would satisfy every one of them.
#[test]
fn a_request_without_an_expectation_owes_no_continue() {
  let mut c = Connection::<Server, General>::new();
  drain(&mut c, BODILESS);
  let exchange = c.exchange.expect("the exchange is still in flight");
  assert!(!exchange.expect_unanswered, "nothing asked for a 100");
}

// RFC 9110 §7.8's two halves, and the 1.0 MUST-ignore folded into has_upgrade.
#[test]
fn the_upgrade_offer_is_recorded_only_when_both_halves_name_a_protocol() {
  let cases: &[(&[u8], bool)] = &[
    (
      b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
      true,
    ),
    (
      b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n",
      false,
    ),
    (
      b"GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\n\r\n",
      false,
    ),
    (b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", false),
    (
      b"GET / HTTP/1.0\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
      false,
    ),
    // The row that separates the two halves of the `&&`. Both fields are
    // PRESENT on a 1.1 request, so `has_upgrade` is true, and the offer still
    // names nothing: RFC 9110 §7.8's `Upgrade` field lists `protocol`s, and an
    // empty value lists none. Without this row an implementation reading
    // `has_upgrade` alone passes every case above, and `into_tunnel`'s
    // `NO_UPGRADE_OFFERED` gate would rest on an untested conjunct.
    (
      b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade:\r\nConnection: Upgrade\r\n\r\n",
      false,
    ),
  ];
  for (req, expected) in cases {
    let mut c = Connection::<Server, General>::new();
    drain(&mut c, req);
    assert_eq!(
      c.exchange.expect("classified").upgrade_offered,
      *expected,
      "for {}",
      core::str::from_utf8(req).unwrap()
    );
  }
}

const _: () = assert!(core::mem::size_of::<Connection<Server, General>>() <= 256);

// RFC 9112 §5.1 (whitespace between a field name and its colon MUST be
// rejected) with §11.2 (why): the violation surfaces once, the connection
// latches, and the server is left owing exactly one error response.
#[test]
fn protocol_error_latches_connection() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(b"GET / HTTP/1.1\r\nHost : bad\r\n\r\n");
  let e = it.next().unwrap_err();
  assert_eq!(e.suggested_status(), Some(SuggestedStatus::BadRequest));
  // Surfaced exactly once: the same iterator answers the latch afterwards.
  assert!(matches!(it.next(), Err(Error::InvalidState(_))));
  let mut it2 = c.handle(BODILESS);
  assert!(it2.next().is_err()); // latched Failed
  assert!(c.is_awaiting_send()); // the 400 is owed
  assert!(!c.wants_read()); // and no byte can change that
}

// Dropping `Items` mid-iteration must not lose the consumed count or re-emit
// items on re-offer.
#[test]
fn items_drop_mid_iteration_is_safe() {
  let mut c = Connection::<Server, General>::new();
  let input = b"POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello";
  // The iterator's life ends at the closing brace, with the body items never
  // pulled — and nothing happens there, which is the property under test.
  let after_head = {
    let mut it = c.handle(input);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    it.consumed()
  };
  // Re-offer only the unconsumed tail: the Head must NOT re-emit.
  let mut it2 = c.handle(input.get(after_head..).unwrap());
  assert!(matches!(
    it2.next().unwrap(),
    Some(Item::BodyChunk { data: b"hello", .. })
  ));
  assert!(matches!(
    it2.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
  assert_eq!(it2.consumed(), b"hello".len());
}

// A 101 answering a request that made no RFC 9110 §7.8 offer is a protocol
// error: "A server MUST NOT switch to a protocol that was not indicated by the
// client in the corresponding request's Upgrade header field", and this
// connection — built under default `Limits`, so it could not have offered even
// if it had wanted to — indicated nothing.
#[test]
fn client_101_in_general_is_protocol_error() {
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  let mut it = c.handle(b"HTTP/1.1 101 \r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
  assert!(it.next().is_err());
}

// RFC 9110 §6.2 with §15.6.6, END TO END and on BOTH sides: a well-formed
// version outside 1.x is a message this core does not speak, not a malformed
// one — so what reaches the driver is `VersionNotSupported`, whose advised
// answer is 505 and not the 400 every grammar fault earns. The codecs pin the
// variant (`a_version_outside_1_x_is_unsupported_not_malformed` on each), and
// this pins that the CONNECTION carries it out unchanged to where a driver reads
// it, which is the only place the distinction becomes a response.
#[test]
fn an_unsupported_version_suggests_505_at_the_connection() {
  // Server: the request-line's version reaches the owed-error-response path.
  let mut c = Connection::<Server, General>::new();
  let error = {
    let mut it = c.handle(b"GET / HTTP/2.0\r\nHost: h\r\n\r\n");
    it.next()
      .expect_err("HTTP/2.0 is not a version this core speaks")
  };
  assert!(matches!(
    error,
    Error::Protocol(crate::error::H1Error::VersionNotSupported)
  ));
  assert_eq!(
    error.suggested_status(),
    Some(SuggestedStatus::VersionNotSupported)
  );
  assert_eq!(SuggestedStatus::VersionNotSupported.code(), 505);
  // …and it is the status the single answer actually goes out with.
  let mut out = [0u8; 128];
  let n = c
    .send_error_response(505, b"HTTP Version Not Supported", NO_FIELDS, &mut out)
    .expect("the single error response a failed server still owes");
  assert_eq!(
    out.get(..n),
    Some(b"HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\n\r\n".as_slice())
  );

  // Client: the status-line's version, on the exchange a request opened. A
  // client has no response to send, so the suggestion is diagnostic here — it
  // names what the PEER did, which is the whole reason it must not decay to 400.
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  let error = {
    let mut it = c.handle(b"HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    it.next()
      .expect_err("HTTP/2.0 is not a version this core speaks")
  };
  assert!(matches!(
    error,
    Error::Protocol(crate::error::H1Error::VersionNotSupported)
  ));
  assert_eq!(
    error.suggested_status(),
    Some(SuggestedStatus::VersionNotSupported)
  );
  assert!(!c.is_awaiting_send(), "a client owes no answer");
}

// RFC 9112 §6.3 item 3 on the RESPONSE side, at the connection layer where it
// becomes §11.1 response splitting rather than a parser verdict.
//
// The item is stated over "a message" and names response splitting in the same
// sentence as request smuggling, so the pair is refused in both directions. What
// this pins is the LIFECYCLE half, which no unit test can: the head is never
// handed over, so a driver cannot act on a message whose extent nobody agrees
// on; the connection latches like any other violation; and it is not reusable
// afterwards, so the octets behind that head are never attributed to a second
// response.
#[test]
fn a_response_carrying_both_framing_fields_latches_the_connection() {
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  let error = {
    let mut it = c.handle(
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n\
        0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    // No head, no body, nothing: the driver is handed the fault instead.
    let error = it.next().expect_err("the pair is unframable");
    assert_eq!(it.consumed(), 0);
    error
  };
  assert!(matches!(
    error,
    Error::Protocol(H1Error::Framing(
      "both Transfer-Encoding and Content-Length"
    ))
  ));
  assert_eq!(error.suggested_status(), Some(SuggestedStatus::BadRequest));

  // Latched: the violation is handed back exactly once, the connection wants no
  // further byte, and the second response in that same offer — which a recipient
  // that had resolved the pair by ignoring one field would have read as a real
  // message — is never parsed.
  assert!(matches!(
    c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
      .next(),
    Err(Error::InvalidState(_))
  ));
  assert!(!c.wants_read());
  // A client has no answer to give, so nothing is owed either.
  assert!(!c.is_awaiting_send());
}

// The PRECEDENCE half at the connection layer: RFC 9112 §6.3 item 1 answers
// "regardless of the header fields present in the message", so item 3's refusal
// may not run ahead of it. A 204 carrying BOTH fields is a bodiless message
// this client accepts and completes — and the connection re-arms behind it,
// which is the observable proof that the head ended where item 1 said it did.
#[test]
fn a_bodiless_response_keeps_item_one_over_item_three() {
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  {
    let mut it = c.handle(
      b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n",
    );
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head { interim: false, .. })
    ));
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
    assert!(it.next().unwrap().is_none());
  }
  // Re-armed: the message was its head, so the next request may go out.
  let mut out = [0u8; 64];
  assert!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_ok()
  );
}

// A General connection may not OPEN an exchange its own continuation forbids.
//
// An `open_request` that refused CONNECT but not a complete RFC 9110 §7.8
// upgrade offer would let one through — while the General receive path condemns
// a 101 answering an offer the exchange never recorded (§7.8's MUST NOT), which
// is every 101 an UNPERMITTED connection can receive. So the offer goes out and
// the connection can only fail on the answer it asked for.
//
// Refused before encoding, with a constant that points at the mode that CAN
// complete it. What lifts the refusal is the operator's permission, not the
// mode: `Connection<_, Tunnel>` is still where a handshake is built from
// scratch.
#[test]
fn a_general_connection_opens_no_upgrade_offer() {
  let offer: &[(&str, &[u8])] = &[
    ("Host", b"h"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
  ];
  let mut c = Connection::<Client, General>::new();
  let mut out = [0xAAu8; 192];
  assert_eq!(
    c.open_request("GET", &ORIGIN, offer, BodyPlan::None, &mut out),
    Err(Error::InvalidState(UPGRADE_NEEDS_TUNNEL))
  );
  assert_eq!(out, [0xAAu8; 192], "a refused open wrote into the buffer");
  // Inert: the exchange never opened, so an ordinary request still goes out.
  assert!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_ok()
  );

  // The two halves are NOT symmetrical, because §7.8 is not symmetrical about
  // them. The `Upgrade` FIELD is the indication a server may act on — "A server
  // MUST NOT switch to a protocol that was not indicated by the client in the
  // corresponding request's Upgrade header field" — so a request carrying it
  // reaches for the takeover whatever else it states, and the ceiling refuses
  // it here exactly as it refuses the complete offer above. A connection option
  // ALONE indicates nothing: §7.6.1's option names no protocol, so there is no
  // 101 a server could legally answer it with, and the request is ordinary.
  let field_only: &[(&str, &[u8])] = &[("Host", b"h"), ("Upgrade", b"websocket")];
  let option_only: &[(&str, &[u8])] = &[("Host", b"h"), ("Connection", b"Upgrade")];
  let mut c = Connection::<Client, General>::new();
  assert_eq!(
    c.open_request("GET", &ORIGIN, field_only, BodyPlan::None, &mut out),
    Err(Error::InvalidState(UPGRADE_NEEDS_TUNNEL)),
    "the field alone is the indication, and the ceiling governs it"
  );
  assert!(
    c.open_request("GET", &ORIGIN, option_only, BodyPlan::None, &mut out)
      .is_ok(),
    "the option alone names no protocol, so it is not an offer"
  );

  // …and the SAME headers open the handshake in the mode that can complete it.
  let mut t = Connection::<Client, Tunnel>::new();
  let n = t
    .open_upgrade(&ORIGIN, offer, &mut out)
    .expect("Tunnel mode is where takeover lives");
  assert_eq!(
    &out[..n],
    b"GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
  );
}

/// A fresh client General connection under default `Limits` — refuses every
/// §7.8 offer, the ceiling [`Connection::new`] always builds.
fn client_general() -> Connection<Client, General> {
  Connection::<Client, General>::new()
}

/// A client General connection whose `Limits` permit a §7.8 offer.
fn client_general_allowing_upgrade() -> Connection<Client, General> {
  Connection::<Client, General>::with_limits(
    Connection::<Client, General>::default_limits().allow_opportunistic_upgrade(true),
  )
}

// The permission Task 1 added is a ceiling, not a default: a connection built
// without it refuses an offer exactly as `a_general_connection_opens_no_upgrade_offer`
// already pins, through the helper the permitting tests below share.
#[test]
fn a_refusing_connection_still_rejects_an_offer() {
  let mut c = client_general(); // default Limits
  let offer: &[(&str, &[u8])] = &[
    ("Host", b"x"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
  ];
  let mut out = [0u8; 256];
  let err = c.open_request("GET", &ORIGIN, offer, BodyPlan::None, &mut out);
  // The REASON, not merely the refusal: `open_request` has a dozen other
  // `InvalidState` answers for a request carrying these fields, and a variant
  // match cannot tell the ceiling from any of them.
  assert!(matches!(err, Err(Error::InvalidState(why)) if why == UPGRADE_NEEDS_TUNNEL));
}

#[test]
fn a_permitting_connection_records_the_offer() {
  let mut c = client_general_allowing_upgrade();
  let offer: &[(&str, &[u8])] = &[
    ("Host", b"x"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
  ];
  let mut out = [0u8; 256];
  c.open_request("GET", &ORIGIN, offer, BodyPlan::None, &mut out)
    .expect("the offer is permitted");
  // The fact the response path will read.
  assert!(c.exchange_upgrade_offered_for_test());
}

// Permission is not indication: a permitting connection whose request carries
// no `Upgrade` fields at all must record no offer, or the response path could
// accept a 101 RFC 9110 §7.8 forbids.
#[test]
fn a_permitting_connection_records_no_offer_when_none_was_made() {
  let mut c = client_general_allowing_upgrade();
  let mut out = [0u8; 256];
  c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
    .expect("ordinary");
  assert!(
    !c.exchange_upgrade_offered_for_test(),
    "permission is not indication"
  );
}

// This crate's DEVIATION, pinned as one. RFC 9110 §7.8 permits the message this
// refuses — a 101 may answer a request whose body is still going out, the client
// "cannot begin using an upgraded protocol on the connection until it has
// completely sent the request message", and the answer is still owed after the
// switch. What this core cannot do is keep writing across the park, so it
// declines the shape at the send path instead.
#[test]
fn an_offering_request_must_be_bodiless() {
  let mut c = client_general_allowing_upgrade();
  // `Transfer-Encoding: chunked` alongside the offer, so the request is
  // otherwise a well-framed `BodyPlan::Chunked` head — `check_framing` has
  // nothing else to refuse it for, and the bodiless rule is the only thing
  // this can be failing on.
  let offer: &[(&str, &[u8])] = &[
    ("Host", b"x"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
    ("Transfer-Encoding", b"chunked"),
  ];
  let mut out = [0u8; 256];
  let err = c.open_request("POST", &ORIGIN, offer, BodyPlan::Chunked, &mut out);
  // BY NAME. `check_framing` and the §7.8 gates share this return type, and this
  // is the only site in the suite that names this constant — a reorder that made
  // some other `InvalidState` fire here would otherwise stay green.
  assert!(matches!(err, Err(Error::InvalidState(why)) if why == OFFER_HAS_NO_CONTENT));
}

// §7.8's OTHER half, enforced rather than assumed: "A sender of Upgrade MUST
// also send an `Upgrade` connection option in the Connection header field
// (Section 7.6.1) to inform intermediaries not to forward this field."
//
// This is the request a both-halves predicate lets through. The field is an
// indication a server may legally switch on, so a core that wrote it un-optioned
// would emit the very field intermediaries forward, and then condemn the
// conforming 101 that came back. Refused here, before a byte, with the constant
// Tunnel's `open_upgrade` refuses the same omission under.
#[test]
fn an_offer_states_the_connection_option_beside_the_field() {
  let mut c = client_general_allowing_upgrade();
  let half: &[(&str, &[u8])] = &[("Host", b"x"), ("Upgrade", b"websocket")];
  let mut out = [0xAAu8; 192];
  let err = c.open_request("GET", &ORIGIN, half, BodyPlan::None, &mut out);
  assert!(matches!(err, Err(Error::InvalidState(why)) if why == OFFER_NEEDS_BOTH_HALVES));
  assert_eq!(out, [0xAAu8; 192], "a refused open wrote into the buffer");
  // Inert: no exchange opened, so the ordinary request behind it still goes out.
  assert!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_ok()
  );
}

// The ORDER of the three, which is the order of what a driver most needs told.
// Each request below fails its own gate and every gate after it.
#[test]
fn the_offer_gates_report_the_most_fundamental_failure() {
  let mut out = [0u8; 256];

  // Ceiling before halves: an unpermitted connection is not told how to spell an
  // offer it may not make at all.
  let half: &[(&str, &[u8])] = &[("Host", b"x"), ("Upgrade", b"websocket")];
  let mut c = client_general();
  let err = c.open_request("GET", &ORIGIN, half, BodyPlan::None, &mut out);
  assert!(matches!(err, Err(Error::InvalidState(why)) if why == UPGRADE_NEEDS_TUNNEL));

  // Halves before content: the offer is malformed as an offer, which is true of
  // the head itself and not of the plan beside it.
  let half_bodied: &[(&str, &[u8])] = &[
    ("Host", b"x"),
    ("Upgrade", b"websocket"),
    ("Transfer-Encoding", b"chunked"),
  ];
  let mut c = client_general_allowing_upgrade();
  let err = c.open_request("POST", &ORIGIN, half_bodied, BodyPlan::Chunked, &mut out);
  assert!(matches!(err, Err(Error::InvalidState(why)) if why == OFFER_NEEDS_BOTH_HALVES));
}

// RFC 9112 §9.6 on this crate's fourth corner: the General client ORIGINATING
// an opportunistic offer. A request that offers an upgrade while stating `close`
// asks a server to switch onto a connection this end has just said it is
// ending — and the 101 that answered it would be refused by this very
// connection's own receive path. This core does not originate a handshake it
// would itself refuse to complete.
#[test]
fn an_offering_request_states_no_close() {
  let mut c = client_general_allowing_upgrade();
  let closing: &[(&str, &[u8])] = &[
    ("Host", b"x"),
    ("Connection", b"Upgrade, close"),
    ("Upgrade", b"websocket"),
  ];
  let mut out = [0xAAu8; 192];
  let err = c.open_request("GET", &ORIGIN, closing, BodyPlan::None, &mut out);
  assert!(matches!(err, Err(Error::InvalidState(why)) if why == TAKEOVER_STATES_NO_CLOSE));
  assert_eq!(out, [0xAAu8; 192], "a refused open wrote into the buffer");

  // NOT a false refusal, in either direction: the offer without `close` still
  // goes out, and an ordinary request may still state `close`.
  assert!(
    c.open_request("GET", &ORIGIN, UPGRADE_OFFER, BodyPlan::None, &mut out)
      .is_ok()
  );
  let mut c = client_general_allowing_upgrade();
  let plain_close: &[(&str, &[u8])] = &[("Host", b"x"), ("Connection", b"close")];
  assert!(
    c.open_request("GET", &ORIGIN, plain_close, BodyPlan::None, &mut out)
      .is_ok(),
    "close on a request that offers nothing is ordinary"
  );
}

#[test]
fn the_permission_is_refused_before_the_body_is() {
  // Both rules refuse this request. The operator's ceiling is the more
  // fundamental one, so a driver that was never permitted to offer learns
  // that rather than being told its body is wrong.
  let mut c = client_general(); // refusing, and the offer also carries a body
  let offer: &[(&str, &[u8])] = &[
    ("Host", b"x"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
    ("Transfer-Encoding", b"chunked"),
  ];
  let mut out = [0u8; 256];
  let err = c.open_request("POST", &ORIGIN, offer, BodyPlan::Chunked, &mut out);
  // Assert on the reported reason, not merely that it refused.
  assert!(matches!(err, Err(Error::InvalidState(reason)) if reason == UPGRADE_NEEDS_TUNNEL));
}

// Task 3's baseline: adding the phase to the pump's borrow set must not change
// the pump's answer for an ordinary connection, which is the only thing this can
// observe until a General connection has a way to reach `Switched`.
#[test]
fn the_pump_sees_the_phase_and_a_general_connection_starts_idle() {
  let mut c = client_general();
  // Nothing sets Switched yet; the point is that the pump can ask.
  let mut items = c.handle(b"");
  assert!(
    matches!(items.next(), Ok(None)),
    "an empty offer is exhausted, not refused"
  );
}

// The guard itself, exercised where the phase can be reached. A General
// connection has no route to `Switched` until Task 4's arm exists, so the phase
// is set directly — this module is `connection`'s own child, so it can — rather
// than leaving the only behaviour this task adds with no test at all.
#[test]
fn the_pump_refuses_every_call_after_a_switch() {
  let mut c = client_general();
  c.tunnel = TunnelPhase::Switched;

  // The bytes behind a switching head belong to the NEXT protocol. Without the
  // guard this input is refused anyway — a pre-existing check answers
  // `Protocol(Framing("response bytes with no outstanding request"))` — so what
  // the guard changes here is not the refusal but its DISPOSITION: that one
  // LATCHES the connection `Failed`, which tells a driver to tear the transport
  // down at the very moment the transport belongs to the next protocol and has
  // to be handed over intact.
  let mut items = c.handle(b"HTTP/1.1 200 OK\r\n\r\n");
  assert!(matches!(items.next(), Err(Error::InvalidState(reason)) if reason == SWITCHED));

  // `Err`, never `Ok(None)`: a parked driver told "feed me more" beside
  // `wants_read() == false` would wait for a conclusion that cannot come.
  //
  // And on EVERY call, not merely the first: the drain loop calls again over the
  // same buffer, and nothing is latched or consumed that would change the answer.
  assert!(matches!(items.next(), Err(Error::InvalidState(reason)) if reason == SWITCHED));

  // Zero because `handle` reset the counter on entry and this offer consumed
  // nothing — NOT a count that carried over. A switching head's count survives
  // only WITHIN the one `Items` that yielded the switch.
  assert_eq!(items.consumed(), 0);
}

/// A complete RFC 9110 §7.8 offer — both halves, and no content, which is what
/// `open_request` accepts on a permitting connection.
const UPGRADE_OFFER: &[(&str, &[u8])] = &[
  ("Host", b"x"),
  ("Connection", b"Upgrade"),
  ("Upgrade", b"websocket"),
];

/// The 101 that answers it, with its own two halves: RFC 9110 §7.8 makes the
/// `Upgrade` field a MUST for the server that switches, and §15.2.2 repeats it.
const SWITCH_101: &[u8] =
  b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n";

/// A client General connection that has written [`UPGRADE_OFFER`] and is reading
/// the response to it.
fn offered_upgrade() -> Connection<Client, General> {
  let mut c = client_general_allowing_upgrade();
  let mut out = [0u8; 256];
  c.open_request("GET", &ORIGIN, UPGRADE_OFFER, BodyPlan::None, &mut out)
    .expect("a permitted offer goes out");
  c
}

// The arm itself: a 101 that answers an offer this connection actually made is
// the switch, and the bytes behind it are handed over untouched.
#[test]
fn a_101_answering_an_offer_yields_the_switch_and_its_leftover() {
  let mut c = offered_upgrade();
  let mut items = c.handle(
    b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\nOPAQUE",
  );
  match items.next() {
    Ok(Some(Item::Switched { head, leftover })) => {
      // §7.8's MUST: the head names the protocol switched to, and only the
      // caller knows whether that is the one it offered.
      assert_eq!(head.header("upgrade"), Some(b"websocket".as_slice()));
      // Verbatim, and NOT consumed: these octets are the new protocol's.
      assert_eq!(leftover, b"OPAQUE");
    }
    other => panic!("expected a switch, got {other:?}"),
  }
  // The head, and only the head — what the driver drops before handing the rest
  // to the protocol that now owns it.
  assert_eq!(items.consumed(), SWITCH_101.len());
  // The pump is parked from here, on this call and on every one after it.
  assert!(matches!(items.next(), Err(Error::InvalidState(reason)) if reason == SWITCHED));

  // NOT `commit_head`'s path: a 101 is in `100..=199`, so falling through would
  // have classed it interim, left the exchange open and kept this pump parsing
  // the next protocol's bytes as HTTP.
  assert_eq!(c.tunnel, TunnelPhase::Switched);
  assert!(matches!(c.recv, RecvState::Idle), "no body was entered");
  // RFC 9110 §7.8: "the server still has an outstanding request to satisfy
  // after the protocol has been changed" — so the exchange is retained, and the
  // switch neither completed it nor aborted it.
  assert!(
    c.exchange_upgrade_offered_for_test(),
    "the exchange that made the offer is still there"
  );
  assert_eq!(c.aborted, None, "nothing was aborted");
}

// Permission is not indication. RFC 9110 §7.8: "A server MUST NOT switch to a
// protocol that was not indicated by the client in the corresponding request's
// Upgrade header field." A permitted connection whose request carried no
// `Upgrade` field indicated nothing, so the 101 answering it is the peer
// violating that MUST — whatever the operator allowed this connection to do.
#[test]
fn a_101_answering_a_request_that_offered_nothing_is_a_protocol_error() {
  let mut c = client_general_allowing_upgrade();
  let mut out = [0u8; 256];
  c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
    .expect("an ordinary request");
  // The head itself is impeccable — both halves of §7.8, and nothing for the
  // head check to condemn. What is missing is the offer it claims to answer.
  let mut items = c.handle(SWITCH_101);
  assert!(
    matches!(items.next(), Err(Error::Protocol(H1Error::Framing(why))) if why == SWITCH_WAS_NEVER_OFFERED)
  );
}

// RFC 9110 §15.2.2 with §7.8: the 101 states BOTH halves or it is not a switch —
// the `upgrade` connection option, and an `Upgrade` field that names a protocol.
// Asked through `names_a_protocol`, the predicate the Tunnel client already
// asks, so a head one mode switches on is one the other switches on.
#[test]
fn a_101_naming_only_one_half_is_a_protocol_error() {
  for half in [
    // No `connection: upgrade`.
    b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n\r\n".as_slice(),
    // No `Upgrade` field.
    b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\n\r\n",
    // Both fields, and the list still names no protocol: `protocol-name` is a
    // token, and a space is not in one.
    b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: web socket\r\n\r\n",
  ] {
    let mut c = offered_upgrade();
    let mut items = c.handle(half);
    assert!(
      matches!(items.next(), Err(Error::Protocol(H1Error::Framing(why))) if why == SWITCH_NEEDS_BOTH_HALVES),
      "{:?}",
      core::str::from_utf8(half)
    );
  }
}

// Every condemnation of a response head applies to the 101 too, and it is asked
// with `check_response_head` — the SAME call `Tunnel`'s `handle_response` makes
// on every head it reads. A head condemned in one mode and switched on in the
// other is two recipients disagreeing about the same bytes (RFC 9112 §11.1).
//
// The fault has to be one a 1xx can carry, and there is exactly one. RFC 9112
// §6.3 item 1 makes every 1xx bodiless "regardless of the header fields
// present in the message", so a framing field on a 101 is one a recipient
// IGNORES — except under §6.1, which sits ahead of the whole list and condemns
// an HTTP/1.0 message carrying `Transfer-Encoding` "even if a Content-Length is
// present".
#[test]
fn a_101_the_head_check_condemns_is_refused_in_both_modes() {
  const CONDEMNED: &[u8] = b"HTTP/1.0 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\ntransfer-encoding: chunked\r\n\r\n";

  // General: the offer was made and both halves are named, so the head check is
  // the only thing left for this to be failing on.
  let mut c = offered_upgrade();
  let mut items = c.handle(CONDEMNED);
  let Err(Error::Protocol(general)) = items.next() else {
    panic!("General must condemn the head, not switch on it")
  };

  // Tunnel, over the same bytes.
  let mut t = Connection::<Client, Tunnel>::new();
  let mut out = [0u8; 128];
  t.open_upgrade(&ORIGIN, UPGRADE_OFFER, &mut out)
    .expect("the mode takeover lives in");
  let Err(Error::Protocol(tunnel)) = t.handle_response(CONDEMNED) else {
    panic!("Tunnel must condemn it too")
  };

  // The SAME fault, not merely two refusals: one check, one verdict, whichever
  // mode is holding the bytes.
  assert_eq!(general, tunnel);
}

// The POSITIVE half of the same symmetry, and the one that is easy to break
// back. RFC 9112 §6.1 states a SENDER's "A server MUST NOT send a
// Transfer-Encoding header field in any response with a status code of 1xx
// (Informational) or 204 (No Content)" — but a recipient rule it is not: §6.3
// item 1 makes a 1xx bodiless "regardless of the header fields present in the
// message", so the field is one this end IGNORES, and `check_response_head`
// says so in both modes. A reader who found §6.1's MUST NOT and "restored" a
// General-only refusal would recreate exactly the two-recipient split RFC 9112
// §11.1 is about, and every other test here would stay green.
//
// So this pins the agreement rather than either verdict: the same bytes, both
// modes, the same head and the same leftover handed over.
#[test]
fn a_101_carrying_transfer_encoding_switches_in_both_modes() {
  const WITH_TE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\ntransfer-encoding: chunked\r\n\r\nOPAQUE";

  let mut c = offered_upgrade();
  let mut items = c.handle(WITH_TE);
  let Ok(Some(Item::Switched {
    head: general_head,
    leftover: general_leftover,
  })) = items.next()
  else {
    panic!("General must switch on a 101 its offer asked for, TE or no TE")
  };

  let mut t = Connection::<Client, Tunnel>::new();
  let mut out = [0u8; 128];
  t.open_upgrade(&ORIGIN, UPGRADE_OFFER, &mut out)
    .expect("the mode takeover lives in");
  let Ok(ClientTunnelOutcome::Switched {
    head: tunnel_head,
    leftover: tunnel_leftover,
  }) = t.handle_response(WITH_TE)
  else {
    panic!("Tunnel must switch on it too")
  };

  // Byte-for-byte the same head, and the same octets left for the protocol that
  // now owns them.
  assert_eq!(general_head.block(), tunnel_head.block());
  assert_eq!(general_leftover, tunnel_leftover);
  assert_eq!(general_leftover, b"OPAQUE");
  // And both connections are spent, by the same phase.
  assert_eq!(c.tunnel, TunnelPhase::Switched);
  assert_eq!(t.tunnel, TunnelPhase::Switched);
}

// RFC 9112 §9.6: a peer that stated the `close` connection option closes "after
// it sends the response containing" it, so it cannot legally continue into
// another protocol — which is what Tunnel decides on its INTERIM arm, through
// `ends_persistence`. Its 101 arm asks `has_close_option` instead.
//
// General reaches the same end EARLIER, and that is the stronger guarantee: the
// interim carrying the option ends the exchange and drains the connection
// (`peer_close_effects`), so the pump stops before the 101 behind it is parsed
// at all. The arm's own `peer_close` guard sits behind this and cannot fire
// while that holds — see the comment on it.
#[test]
fn a_101_after_the_peer_committed_to_closing_never_switches() {
  const CLOSING_INTERIM: &[u8] = b"HTTP/1.1 100 Continue\r\nconnection: close\r\n\r\n";
  let mut c = offered_upgrade();
  let mut items = c.handle(b"HTTP/1.1 100 Continue\r\nconnection: close\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n");
  assert!(matches!(
    items.next(),
    Ok(Some(Item::Head { interim: true, .. }))
  ));
  // Not the switch, and not a second head: the connection is over.
  assert!(matches!(items.next(), Ok(None)));
  assert_eq!(
    items.consumed(),
    CLOSING_INTERIM.len(),
    "the 101 behind it is left unread"
  );
  assert_ne!(c.tunnel, TunnelPhase::Switched);
}

// RFC 9112 §9.6 again, on the head IN HAND rather than on one that came before
// it. `peer_close` accumulates what earlier COMMITTED heads stated, and a 101
// never reaches `commit_head` — so a 101 stating its own `close` leaves the flag
// false, and without this gate it switches, handing the transport to a
// continuing protocol on a connection the peer has just said it is closing.
//
// The rule step 3 states — "a peer that stated `close` has committed to closing,
// so it has nothing to continue INTO" — covers this head exactly as much as an
// earlier one. It is ONE rule about ONE fact, so it keeps ONE constant.
#[test]
fn a_101_stating_its_own_close_never_switches() {
  const CLOSING_SWITCH: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade, close\r\nupgrade: websocket\r\n\r\nOPAQUE";
  let mut c = offered_upgrade();
  let mut items = c.handle(CLOSING_SWITCH);
  let Err(Error::Protocol(H1Error::Framing(why))) = items.next() else {
    panic!("a 101 that states close must not switch")
  };
  assert_eq!(why, SWITCH_AFTER_CLOSE);
  assert_ne!(c.tunnel, TunnelPhase::Switched);
}

// AN HTTP/1.0 101 WITHOUT `keep-alive` STILL SWITCHES, and widening the guard
// from the `close` option to `ends_persistence` is what would break it.
//
// §9.3's 1.0 default answers "may another HTTP MESSAGE follow this one?" — and a
// 101 ends HTTP framing on the connection, so there is no such message for the
// default to govern. The constant is the tell: it reads "a protocol takeover
// after the peer STATED close", and a 1.0 101 carrying no `close` stated
// nothing. Refusing it would need a different reason, and this crate has none —
// nothing else anywhere refuses a 1.0 101.
//
// The request side reasons the same way for CONNECT, and the two must not
// diverge.
#[test]
fn an_http_10_101_without_keep_alive_still_switches() {
  const TEN: &[u8] =
    b"HTTP/1.0 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\nOPAQUE";
  let mut c = offered_upgrade();
  let mut items = c.handle(TEN);
  match items.next() {
    Ok(Some(Item::Switched { leftover, .. })) => {
      assert_eq!(
        leftover, b"OPAQUE",
        "the new protocol's bytes were discarded"
      )
    }
    other => panic!("a 1.0 101 that states no close still switches, got {other:?}"),
  }
  assert_eq!(c.tunnel, TunnelPhase::Switched);
  assert_eq!(c.transport(), Transport::HandedOver);
}

// The FALSE direction, at BOTH versions: an explicitly close-bearing 101 is
// refused whatever version it states, because the option is what the rule is
// about.
#[test]
fn a_101_stating_close_is_refused_at_either_version() {
  for wire in [
    b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade, close\r\nupgrade: websocket\r\n\r\n"
      .as_slice(),
    b"HTTP/1.0 101 Switching Protocols\r\nconnection: upgrade, close\r\nupgrade: websocket\r\n\r\n",
  ] {
    let mut c = offered_upgrade();
    let mut items = c.handle(wire);
    let Err(Error::Protocol(H1Error::Framing(why))) = items.next() else {
      panic!("a 101 that states close must not switch")
    };
    assert_eq!(why, SWITCH_AFTER_CLOSE);
    assert_ne!(c.tunnel, TunnelPhase::Switched);
  }
}

// The gate the drain above keeps dead, exercised where the drain cannot reach
// it — so the state is built by hand, exactly as
// `the_transition_gate_refuses_a_switch_the_other_gates_would_pass` builds its
// own. Its deadness is an invariant of ANOTHER function (`peer_close_effects`),
// which is why the gate is shipped and why a test of the drain is not a test of
// it: change that function and the drain test above still passes.
//
// Every other gate in `switch_or_fault` passes on these bytes —
// `a_101_answering_an_offer_yields_the_switch_and_its_leftover` switches on the
// same fixture and the same input — so `peer_close` is the only thing changed,
// and deleting the gate makes this 101 SWITCH: a driver would be handed a
// transport RFC 9112 §9.6 says the peer is already closing.
#[test]
fn the_close_gate_refuses_a_switch_the_other_gates_would_pass() {
  let mut c = offered_upgrade();
  c.peer_close = true;

  let mut items = c.handle(SWITCH_101);
  let Err(Error::Protocol(H1Error::Framing(why))) = items.next() else {
    panic!("a peer that stated close gets no switch")
  };
  assert_eq!(why, SWITCH_AFTER_CLOSE);
  assert_ne!(c.tunnel, TunnelPhase::Switched);
}

// `consumed` accumulates across the WHOLE offer, the way `commit_head`
// accumulates it: an interim and the 101 can arrive in one buffer, and a driver
// told only the 101's own length would re-offer the interim it has already seen
// as the first bytes of the new protocol.
#[test]
fn an_interim_before_the_101_leaves_the_offer_intact() {
  const INTERIM: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
  let mut c = offered_upgrade();
  let mut items = c.handle(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\nOPAQUE");
  assert!(matches!(
    items.next(),
    Ok(Some(Item::Head { interim: true, .. }))
  ));
  match items.next() {
    Ok(Some(Item::Switched { leftover, .. })) => assert_eq!(leftover, b"OPAQUE"),
    other => panic!("expected a switch, got {other:?}"),
  }
  // BOTH heads, not the 101's own length: 25 octets of interim and 77 of switch.
  assert_eq!(INTERIM.len(), 25);
  assert_eq!(SWITCH_101.len(), 77);
  assert_eq!(items.consumed(), INTERIM.len() + SWITCH_101.len());
}

// A watermark belongs to ONE head. `commit_head` is what normally clears it and
// the arm bypasses it, so the arm clears it itself: `fingerprint` compares the
// field exhaustively, and a connection left holding a stale one is one whose
// state does not describe it.
#[test]
fn the_switch_clears_the_watermark_commit_head_would_have() {
  let mut c = offered_upgrade();
  // A head that has not terminated: nothing is consumed, and the scan records
  // how far into it it looked.
  let partial = SWITCH_101.get(..40).expect("a prefix of the head");
  assert!(matches!(c.handle(partial).next(), Ok(None)));
  assert_eq!(c.consumed, 0, "a partial head consumes nothing");
  assert!(c.watermark > 0, "the partial scan is recorded");

  // The whole head, re-offered from the same start.
  let mut items = c.handle(SWITCH_101);
  assert!(matches!(items.next(), Ok(Some(Item::Switched { .. }))));
  assert_eq!(items.consumed(), SWITCH_101.len());
  assert_eq!(c.watermark, 0, "the switch cleared it");
}

/// A client General connection that offered a §7.8 upgrade, took the 101 that
/// answered it, and is PARKED: the driver holds the head and the leftover, and
/// this value is everything that is left.
///
/// Driven through the real send and receive paths rather than by writing the
/// phase, because §6's table describes the state a CALLER reaches — and because
/// the retained exchange, which is what makes half of these rows non-obvious,
/// only exists on that path.
fn parked() -> Connection<Client, General> {
  let mut c = offered_upgrade();
  {
    let mut items = c.handle(SWITCH_101);
    assert!(
      matches!(items.next(), Ok(Some(Item::Switched { .. }))),
      "the fixture is the real arm, not a written phase"
    );
    assert_eq!(items.consumed(), SWITCH_101.len());
  }
  assert_eq!(c.tunnel, TunnelPhase::Switched);
  c
}

// Every entry point whose signature can carry a refusal names the SWITCH, and
// none of them can be satisfied by the state the switch left behind.
//
// The reason string is what this asserts, not merely `InvalidState`: three of
// these four calls refused a parked connection already, for reasons that are
// true of the message and silent about the connection — `ONE_REQUEST_AT_A_TIME`
// from the retained exchange, and `NO_BODY_IN_FLIGHT` twice from a send side
// that is not `Sending`. An assertion on the variant alone would pass with every
// guard removed.
#[test]
fn a_parked_connection_refuses_every_call_that_can_refuse() {
  let mut c = parked();
  let mut out = [0u8; 64];

  assert!(
    matches!(c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out), Err(Error::InvalidState(why)) if why == SWITCHED)
  );
  assert!(matches!(c.send_body(b"x", &mut out), Err(Error::InvalidState(why)) if why == SWITCHED));
  assert!(
    matches!(c.finish_body(NO_TRAILERS, &mut out), Err(Error::InvalidState(why)) if why == SWITCHED)
  );
  assert!(matches!(c.handle_eof(), Err(Error::InvalidState(why)) if why == SWITCHED));

  // Nothing was encoded: a refusal that had written a head would have put
  // HTTP/1.1 bytes in a buffer the driver hands to another protocol.
  assert_eq!(out, [0u8; 64]);
  // And nothing was RECORDED. `handle_eof` latches `read_closed` and abandons a
  // client's send side before it returns; both would have run had the guard sat
  // anywhere but first, and both rewrite a connection that is already spent —
  // the second of them writing off a request RFC 9110 §7.8 keeps alive: "the
  // server still has an outstanding request to satisfy after the protocol has
  // been changed".
  assert!(
    !c.read_closed,
    "the EOF was not this connection's to record"
  );
  assert!(matches!(c.send, SendState::Idle), "nothing was abandoned");
  assert!(matches!(c.lifecycle, Lifecycle::Open));
}

// `handle` cannot refuse — its signature has no `Result` — so a fresh offer of
// the next protocol's bytes is refused by the ITERATOR, on the first call and
// every call after it.
//
// `the_pump_refuses_every_call_after_a_switch` pins the same guard with the
// phase written by hand, and `a_101_answering_an_offer_yields_the_switch_and_its_leftover`
// pins the second `next()` within the `Items` that yielded the switch. What is
// new here is the ordinary driver shape: a REAL switch, then a LATER `handle`.
// Without the guard these bytes reach the parser through the retained exchange
// and are condemned as a malformed status line, which latches `Failed` — the
// one disposition that tells a driver to tear down a transport it must hand over
// intact.
#[test]
fn a_parked_connection_refuses_a_later_offer_of_bytes() {
  let mut c = parked();
  {
    let mut items = c.handle(b"more opaque bytes");
    assert!(matches!(items.next(), Err(Error::InvalidState(why)) if why == SWITCHED));
    assert!(
      matches!(items.next(), Err(Error::InvalidState(why)) if why == SWITCHED),
      "and again: nothing latches, so the answer cannot change"
    );
    // `consumed` keeps answering, which is what the drop-safety contract needs:
    // zero, because this offer produced nothing.
    assert_eq!(items.consumed(), 0);
  }
  // Not latched, which is the whole difference from the refusal above: `Failed`
  // is a connection to tear down and this one is a transport to hand over.
  assert!(matches!(c.lifecycle, Lifecycle::Open));
}

// The readiness split goes quiet in both halves, and the read half is the row
// that has to be answered from the PHASE.
//
// RFC 9110 §7.8 retains the exchange — "the server still has an outstanding
// request to satisfy after the protocol has been changed" — and `wants_read`'s
// idle-client arm reads `exchange.is_some()`. So the exchange-first answer here
// is TRUE: a driver told to read would take the next protocol's bytes off the
// socket and feed them to a connection that must never see them. Delete the
// phase check in `wants_read` and this test fails on that line.
#[test]
fn a_parked_connection_reads_nothing_and_owes_nothing() {
  let c = parked();
  assert!(
    c.exchange.is_some(),
    "§7.8 leaves the request outstanding, so the trap is live"
  );
  assert!(matches!(c.recv, RecvState::Idle));

  assert!(!c.wants_read(), "the bytes are the next protocol's");
  // These two answer `false` and `None` from the phase, and would answer the
  // same today without it: a §7.8 offer carries no content, so the request that
  // switched left `send` and `recv` both `Idle`. Stated rather than left to be
  // discovered — they pin §6's rows against a switch that one day retains more,
  // and no mutation of today's guards kills them.
  assert!(!c.is_awaiting_send());
  assert_eq!(c.body_progress(), None);
}

// The second of the two `Items` accessors §6 keeps working — `consumed` is
// pinned by `a_parked_connection_refuses_a_later_offer_of_bytes` above.
//
// `limit_body` needs no phase check of its own: it asks the RECEIVE state, which
// the switch left `Idle`, so a parked connection is told there is no body to
// narrow — the same answer it gives between messages, and the honest one.
#[test]
fn a_parked_connection_narrows_no_body() {
  let mut c = parked();
  let mut items = c.handle(b"");
  assert!(
    matches!(items.limit_body(1), Err(Error::InvalidState(why)) if why == NO_BODY_BEING_RECEIVED)
  );
}

// THE WHOLE PRODUCT, enumerated. `transport()` is a pure function of three
// fields, and the product is small enough to state completely — so it is stated
// completely rather than sampled, which is what makes a wrong arm impossible to
// hide behind a reachable-state argument.
//
// The state is written by hand because most of the forty combinations are not
// reachable through the public API — `Lifecycle::Failed` beside
// `TunnelPhase::Idle` with no read-EOF, for instance. That is the point: a pure
// projection must answer for every input it can be given, and a future change
// that makes an unreachable combination reachable then finds the answer already
// decided rather than accidental.
#[test]
fn the_transport_level_is_a_total_function_of_three_fields() {
  use Lifecycle::{Closing, Draining, Failed, Open};
  use Transport::{Ending, HandedOver, Live};

  let phases = [
    ("Idle", TunnelPhase::Idle),
    (
      "Handshaking",
      TunnelPhase::Handshaking(crate::connection::tunnel::Handshake::for_test()),
    ),
    ("Switched", TunnelPhase::Switched),
    ("Refused", TunnelPhase::Refused),
    ("RejectionOwed", TunnelPhase::RejectionOwed),
  ];
  let lifecycles = [
    ("Open", Open),
    ("Closing", Closing),
    ("Draining", Draining),
    ("Failed", Failed),
  ];

  for (phase_name, phase) in phases {
    for (life_name, life) in lifecycles {
      for read_closed in [false, true] {
        let mut c = client_general();
        c.tunnel = phase;
        c.lifecycle = life;
        c.read_closed = read_closed;

        // The derivation, restated independently of the code under test: the
        // handover absorbs, then the failure latch, then the end of keep-alive
        // by either of its two spellings.
        let expected = match (phase, life, read_closed) {
          (TunnelPhase::Switched, _, _) => HandedOver,
          (_, Failed, _) => Transport::Failed,
          (TunnelPhase::Refused | TunnelPhase::RejectionOwed, _, _) => Ending,
          (_, Closing | Draining, _) => Ending,
          (_, Open, true) => Ending,
          (_, Open, false) => Live,
        };
        assert_eq!(
          c.transport(),
          expected,
          "{phase_name} x {life_name} x read_closed={read_closed}"
        );
      }
    }
  }
}

// THE LEVEL, on the connection this whole family is about. What a driver asks is
// what the connection currently IS: there is no INSTANCE of "close the
// transport" to be queued, held, deferred, resolved, suppressed, lost or
// duplicated, so none of those is a thing to assert.
//
// `HandedOver` is absorbing and outranks everything, which is where "a switch
// wins over a local close" lives — one arm's position in one `match`.
#[test]
fn a_parked_connection_reads_handed_over() {
  let mut c = parked();
  assert_eq!(c.transport(), Transport::HandedOver);
  // Reading it twice is two reads, not two instructions.
  assert_eq!(c.transport(), Transport::HandedOver);
  // And a local close cannot change it back: the level makes the stray write
  // harmless rather than something a guard has to forbid.
  c.close();
  assert_eq!(c.transport(), Transport::HandedOver);
  assert_eq!(
    c.poll_event(),
    None,
    "poll_event carries message facts only"
  );
}

// THE ARMED WINDOW: a local close, then a valid 101. The switch still happens —
// the peer is blameless and its response is valid — and the transport reads
// `HandedOver` from the moment it does, with no notice to be minted early or
// cancelled late.
#[test]
fn a_close_before_a_switch_cannot_instruct_a_handed_over_transport() {
  let mut c = offered_upgrade();
  c.close();
  assert_eq!(
    c.transport(),
    Transport::Ending,
    "keep-alive is over the moment it is asked for"
  );

  {
    let mut items = c.handle(SWITCH_101);
    assert!(matches!(items.next(), Ok(Some(Item::Switched { .. }))));
  }
  assert_eq!(
    c.transport(),
    Transport::HandedOver,
    "the phase outranks the close, by its position in the match"
  );
}

// The same window resolved the other way: the offer is declined, so the
// transport was this crate's after all and the close the driver asked for is
// what it reads. Nothing was deferred and nothing was resolved.
#[test]
fn a_close_before_a_declined_offer_reads_ending() {
  let mut c = offered_upgrade();
  c.close();
  {
    let mut items = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    while items.next().expect("an ordinary answer").is_some() {}
  }
  assert_eq!(c.transport(), Transport::Ending);
  // The contract `close()` exists for is unchanged.
  let mut out = [0u8; 128];
  assert!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_err(),
    "no further exchange begins"
  );
}

// AN EOF WHILE ARMED, which is the shape a queued answer gets wrong — stale,
// lost, or doubled. The read side ending is a fact about the transport;
// `transport()` reads it beside the lifecycle, and no predicate decides "may the
// driver have it yet".
#[test]
fn an_eof_while_armed_reads_ending_then_handed_over() {
  let mut c = offered_upgrade();
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(c.read_closed);
  assert_eq!(
    c.transport(),
    Transport::Ending,
    "the read half ended; keep-alive is over whatever answers"
  );

  // …and a 101 buffered behind that EOF still hands the transport over, which
  // the driver reads directly rather than inferring from a notice it may or may
  // not have already drained.
  {
    let mut items = c.handle(SWITCH_101);
    assert!(matches!(items.next(), Ok(Some(Item::Switched { .. }))));
  }
  assert_eq!(c.transport(), Transport::HandedOver);
}

// A LATCHED FAILURE reads `Failed`, not `Ending`, and it is absorbing. A queued
// notice has only two answers here, both wrong: deliver it beside the terminal
// `Err` (duplicate) or drop it (loss). A level has neither — the `Err` says this
// call failed, and the level says what the connection now is.
#[test]
fn a_latched_failure_reads_failed_and_absorbs() {
  let mut c = offered_upgrade();
  c.close();
  {
    let mut items = c.handle(b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\ncontent-length: 2\r\n\r\n");
    assert!(
      items.next().is_err(),
      "a framing fault latches the connection"
    );
  }
  assert_eq!(c.transport(), Transport::Failed);
  assert_eq!(c.transport(), Transport::Failed, "absorbing");
  assert_eq!(c.poll_event(), None);
}

// The FALSE direction: a connection that armed nothing behaves exactly as it
// always did, and an EOF with an ordinary exchange outstanding still says
// keep-alive is over at once.
#[test]
fn an_unarmed_connection_reads_the_same_levels() {
  let mut c = client_general();
  assert_eq!(c.transport(), Transport::Live);
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert_eq!(c.transport(), Transport::Ending);

  let mut c = client_general();
  let mut out = [0u8; 128];
  c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
    .expect("ordinary");
  assert_eq!(c.transport(), Transport::Live);
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert_eq!(c.transport(), Transport::Ending);
}

// §6's `close` row, made true. `close()` initiates RFC 9112 §9.6's local close:
// it moves the lifecycle, and the transport level follows from that — which
// to close the transport. After the switch the transport is the negotiated
// protocol's — the driver HANDS IT OVER, it does not close it — so this is the
// feature's central promise inverted, and the row already claimed the call was
// inert.
#[test]
fn close_is_inert_on_a_parked_connection() {
  let mut c = parked();
  let before = c.lifecycle;
  c.close();
  assert_eq!(
    c.lifecycle, before,
    "close() moved the lifecycle of a connection whose transport is not ours"
  );
  assert_eq!(
    c.transport(),
    Transport::HandedOver,
    "close() changed what a driver reads about a transport that is not ours"
  );

  // Idempotent in the same way, and it never becomes live again.
  c.close();
  assert_eq!(c.lifecycle, before);
  assert_eq!(c.poll_event(), None);
}

// The trap §6.1 names: `into_tunnel` would otherwise mint a fresh tunnel over a
// transport another protocol is already reading, and `open_upgrade` would write
// HTTP/1.1 into it.
//
// The reported reason is `EXCHANGE_IN_FLIGHT`, and asserting it is the point:
// §7.8 makes it TRUE rather than coincidental — the request really is still
// outstanding — which is exactly what makes `take_over`'s own phase gate
// unreachable. A run that reports `SWITCHED` here has changed that argument, not
// merely a message.
#[test]
fn a_parked_connection_cannot_become_a_tunnel() {
  let c = parked();
  let (c, why) = c
    .into_tunnel()
    .expect_err("a parked connection must not transition");
  assert_eq!(why, TransitionRefused::EXCHANGE_IN_FLIGHT);
  // Returned unchanged, still parked: a refused transition costs the caller
  // nothing, and there was nothing here to salvage anyway.
  assert_eq!(c.tunnel, TunnelPhase::Switched);
}

// `take_over`'s phase gate, which nothing can reach through the public API — so
// the state is built by hand, exactly as `the_pump_refuses_every_call_after_a_switch`
// builds its own.
//
// What is written here is the disposition §6.1 REJECTED: a switch that CLEARED
// the exchange. With it gone, `nothing_outstanding` passes, and so does every
// connection gate — the lifecycle is `Open`, the read side is live, no tail, no
// CR, no queued notice — so the phase is the only thing left to refuse on. That
// is what makes this the test for a gate that is dead today: delete it and the
// transition SUCCEEDS, handing back a `Connection<Client, Tunnel>` at
// `TunnelPhase::Idle` whose `open_upgrade` writes HTTP/1.1 bytes into a stream
// that belongs to the protocol the 101 named.
#[test]
fn the_transition_gate_refuses_a_switch_the_other_gates_would_pass() {
  let mut c = parked();
  c.exchange = None;

  let (c, why) = c
    .into_tunnel()
    .expect_err("the phase is the gate that is left");
  assert_eq!(why, TransitionRefused::SWITCHED);
  assert_eq!(c.tunnel, TunnelPhase::Switched);
}

// The server twin: RFC 9110 §9.3.6 makes a 2xx to CONNECT turn the connection
// into a tunnel, which General mode cannot become — so the request is refused
// where it arrives rather than accepted and mis-framed.
#[test]
fn server_connect_in_general_is_protocol_error() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
  let e = it.next().unwrap_err();
  assert_eq!(e.suggested_status(), Some(SuggestedStatus::BadRequest));
}

// RFC 9112 §9.2: data on a connection with no outstanding request is not a
// response — unless it is only CRLFs, which can be discarded (§2.2).
#[test]
fn client_idle_data_rules() {
  let mut c = Connection::<Client, General>::new();
  let mut it = c.handle(b"\r\n\r\n"); // interstitial CRLFs: consumed, no items
  assert!(it.next().unwrap().is_none());
  assert_eq!(it.consumed(), 4);
  let mut it2 = c.handle(b"HTTP/1.1 200 OK\r\n\r\n"); // a "response" with nothing outstanding
  assert!(it2.next().is_err());
}

// RFC 9112 §9.2 with §2.2's lone-CR doctrine: an interstitial CRLF split across
// two reads must not be fatal. The CR alone decides nothing — its LF may be in
// the next segment — so it is held rather than condemned, and the connection says
// it wants the byte that settles it.
#[test]
fn client_idle_holds_a_split_crlf_until_its_lf_arrives() {
  let mut c = Connection::<Client, General>::new();
  let mut it = c.handle(b"\r");
  assert!(it.next().unwrap().is_none());
  assert_eq!(it.consumed(), 0); // the CR stays in the driver's buffer

  // Without this the driver would stop reading and the CR would never resolve.
  assert!(c.wants_read());
  assert!(!c.is_awaiting_send());

  // The LF arrives in the next read and the pair is discarded like any other.
  let mut it2 = c.handle(b"\r\n");
  assert!(it2.next().unwrap().is_none());
  assert_eq!(it2.consumed(), 2);
  assert!(!c.wants_read()); // idle again, with nothing pending
}

// RFC 9112 §2.2: the CR is condemned only once the byte behind it disproves it.
// The pairs in front of it are discarded on the spot, so at most one CR ever
// pends and nothing accumulates across offers.
#[test]
fn client_idle_pending_cr_is_decided_by_the_byte_behind_it() {
  let mut c = Connection::<Client, General>::new();
  let mut it = c.handle(b"\r\n\r");
  assert!(it.next().unwrap().is_none());
  // One whole pair gone; the odd CR held.
  assert_eq!(it.consumed(), 2);
  assert!(c.wants_read());

  // Re-offered from the CR: what follows is not an LF, so §9.2 applies at last.
  let mut it2 = c.handle(b"\rHTTP/1.1 200 OK\r\n\r\n");
  let e = it2.next().unwrap_err();
  assert_eq!(e.suggested_status(), Some(SuggestedStatus::BadRequest));
  assert!(!c.wants_read()); // latched: no byte can help now
}

// RFC 9112 §9.6: after close is signaled, further pipelined requests are dead.
#[test]
fn draining_processes_no_further_requests() {
  let mut c = Connection::<Server, General>::new();
  let two =
    b"GET /a HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
  let mut it = c.handle(two);
  while it.next().unwrap().is_some() {}
  let consumed = it.consumed();
  // The peer's close option is a connection-scoped fact, drained as an event.
  assert_eq!(c.transport(), Transport::Ending);
  assert_eq!(c.poll_event(), None);
  // Complete the exchange with a real response…
  send_bodiless_response(&mut c);
  // …then the second request's bytes must never produce items.
  let mut it2 = c.handle(two.get(consumed..).unwrap());
  assert!(it2.next().unwrap().is_none());
  assert_eq!(it2.consumed(), 0);
  assert!(!c.wants_read());
}

// RFC 9112 §7.1 with §7.1.2: a chunked body streams as it arrives and may close
// with a trailer section, which is delivered field by field before the exchange
// ends.
#[test]
fn chunked_request_with_trailers_streams_items() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(
    b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: v\r\n\r\n",
  );
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::BodyChunk { data: b"abc", .. })
  ));
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::Trailer {
      name: "X-T",
      value: b"v",
      ..
    })
  ));
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
}

// RFC 9112 §2.2: a server "SHOULD ignore at least one empty line (CRLF)
// received prior to the request-line" — the CRLF an older client trailed its
// last request with. Bounded, because unbounded it is a free keep-alive channel
// for a peer that never sends a request.
#[test]
fn server_skips_bounded_leading_empty_lines() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(b"\r\n\r\nGET /a HTTP/1.1\r\nHost: h\r\n\r\n");
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  // The skipped bytes are consumed with the head they preceded, never before it.
  assert_eq!(it.consumed(), 4usize.saturating_add(BODILESS.len()));

  // A trailing lone CR after the allowed empty lines is held by the head scan,
  // exactly as it always was: the server consumes nothing until the whole head is
  // there, so the split-CRLF case never reached a decision here (RFC 9112 §2.2).
  let mut split = Connection::<Server, General>::new();
  let mut it2 = split.handle(b"\r\n\r");
  assert!(it2.next().unwrap().is_none());
  assert_eq!(it2.consumed(), 0);
  assert!(split.wants_read());

  // One line past the allowance is refused rather than waited on. TOO_MANY
  // carries five, which is exactly one over — pinned against the cap itself so
  // that moving the cap moves this test with it.
  assert_eq!(MAX_LEADING_EMPTY_LINES, 4);
  const TOO_MANY: &[u8] = b"\r\n\r\n\r\n\r\n\r\nGET /a HTTP/1.1\r\nHost: h\r\n\r\n";
  let mut over = Connection::<Server, General>::new();
  assert!(over.handle(TOO_MANY).next().is_err());
}

// RFC 9112 §2.2: the head scan is resumable across feeds, so a byte-at-a-time
// driver reaches the same head — and once that head is through, the next one
// starts its own scan rather than inheriting the last one's watermark.
#[test]
fn head_scan_resumes_across_split_feeds() {
  let mut c = Connection::<Server, General>::new();
  for n in 1..BODILESS.len() {
    let mut it = c.handle(BODILESS.get(..n).unwrap());
    assert!(it.next().unwrap().is_none(), "prefix {n}");
    assert_eq!(it.consumed(), 0, "prefix {n}");
  }
  let mut it = c.handle(BODILESS);
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
  assert_eq!(it.consumed(), BODILESS.len());

  // The watermark is back to zero for the next exchange: a fresh partial head
  // is scanned from its own start rather than from the last one's end.
  send_bodiless_response(&mut c);
  let mut it2 = c.handle(b"GET /b HTTP");
  assert!(it2.next().unwrap().is_none());
  assert_eq!(it2.consumed(), 0);
}

// RFC 9112 §6.3 item 8: for a close-delimited response the EOF IS the
// delimiter, so an intact head plus a close is a COMPLETE message.
#[test]
fn eof_completes_a_close_delimited_response() {
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  let mut it = c.handle(b"HTTP/1.1 200 OK\r\n\r\nbody");
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::BodyChunk { data: b"body", .. })
  ));
  assert!(it.next().unwrap().is_none());
  // …and the driver learned keep-alive was over AT THE HEAD, not at the EOF.
  // §6.3 item 8 frames this message by the close, and §9.3 makes a connection
  // that carries one non-persistent: the notice is what says so in time for the
  // driver to stop planning a second request on it.
  assert_eq!(c.transport(), Transport::Ending);
  assert_eq!(c.poll_event(), None);
  // The EOF observes the transport and nothing else. §6.3 item 8's "the close IS
  // the delimiter" is a conclusion about the ABSENCE of further octets, so it is
  // drawn on the re-offer that runs out — where the driver's buffer is visible,
  // and where octets it had not offered yet would still arrive first.
  assert!(matches!(c.handle_eof(), Ok(None)));
  // Idempotent.
  assert!(matches!(c.handle_eof(), Ok(None)));
  {
    let mut it = c.handle(b"");
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
    assert!(it.next().unwrap().is_none());
  }
  assert!(!c.wants_read());
}

// RFC 9110 §15.2 with RFC 9112 §9.5: an interim response is INFORMATIONAL and
// explicitly not the answer, so a close after one leaves the exchange truncated
// exactly as a close before any response byte does. A client told this was a
// clean close would have to conclude its request had been answered by silence.
//
// The watermark is not what says so, and this test proves it: the interim head
// COMPLETED, so the watermark it used went with it (the split feeds are there to
// leave one behind if that were untrue). What remains is an exchange with no
// final head, which is the fact the diagnosis is made from.
#[test]
fn eof_after_an_interim_response_is_a_truncated_exchange() {
  const INTERIM: &[u8] = b"HTTP/1.1 100 \r\n\r\n";
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  // Split feeds first, so there is a watermark to be left behind.
  for n in 1..INTERIM.len() {
    let mut it = c.handle(INTERIM.get(..n).unwrap());
    assert!(it.next().unwrap().is_none(), "prefix {n}");
  }
  {
    let mut it = c.handle(INTERIM);
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head { interim: true, .. })
    ));
    assert_eq!(it.consumed(), INTERIM.len());
  }
  // The EOF itself observes only the transport; the truncation is concluded on
  // the re-offer that finds nothing left, because only then is it provable.
  assert!(matches!(c.handle_eof(), Ok(None)));
  let error = resolve_eof(&mut c, b"").unwrap_err();
  assert!(matches!(
    error,
    Error::Protocol(H1Error::Framing(
      "connection closed before the response arrived"
    ))
  ));
  // Latched like any other violation, and a client owes no answer.
  assert!(matches!(c.handle_eof(), Err(Error::InvalidState(_))));
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
}

// RFC 9112 §6.3 item 6 (a close before the counted octets arrive MUST be treated
// as incomplete) against §9.5 (a close between messages is how a persistent
// connection normally ends).
#[test]
fn eof_splits_clean_close_from_truncation() {
  // Between messages: nothing is in flight, so the close ends nothing.
  let mut idle = Connection::<Server, General>::new();
  assert!(matches!(idle.handle_eof(), Ok(None)));

  // Mid-head: the request-line arrived, its head never terminated.
  let mut partial = Connection::<Server, General>::new();
  assert!(
    partial
      .handle(b"GET / HTTP/1.1\r\n")
      .next()
      .unwrap()
      .is_none()
  );
  assert!(matches!(partial.handle_eof(), Ok(None)));
  assert!(resolve_eof(&mut partial, b"").is_err());

  // Mid-body: the head framed five octets and two arrived.
  let mut short = Connection::<Server, General>::new();
  let mut it = short.handle(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhi");
  while it.next().unwrap().is_some() {}
  assert!(matches!(short.handle_eof(), Ok(None)));
  let e = resolve_eof(&mut short, b"").unwrap_err();
  assert_eq!(e.suggested_status(), Some(SuggestedStatus::BadRequest));
  // The truncation latched the connection like any other violation.
  assert!(matches!(short.handle_eof(), Err(Error::InvalidState(_))));
  assert!(resolve_eof(&mut short, b"").is_err());
  // …but the one error response is owed only where one can still be SENT: the
  // transport is gone, so nothing is owed and there is no error response to
  // write into a socket that has closed.
  assert!(!short.is_awaiting_send());
  let mut out = [0u8; 64];
  assert!(matches!(
    short.send_error_response(400, b"", NO_FIELDS, &mut out),
    Err(Error::InvalidState(_))
  ));
}

// The CLIENT rows of `handle_eof`'s table that no other test covers: a request
// went out and no FINAL response came back.
//
// RFC 9112 §9.5 splits a clean close from a truncated exchange by what was
// outstanding, and a client with an exchange in flight is the second by
// definition — the response it is waiting for is not going to arrive. Reporting
// `Ok(None)` there tells a driver the request completed, which is the one thing
// that did not happen.
#[test]
fn eof_before_a_response_is_a_truncated_exchange() {
  // Not one byte of a response.
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  assert!(matches!(c.handle_eof(), Ok(None)));
  let error = resolve_eof(&mut c, b"").unwrap_err();
  assert!(matches!(
    error,
    Error::Protocol(H1Error::Framing(
      "connection closed before the response arrived"
    ))
  ));
  assert_eq!(error.suggested_status(), Some(SuggestedStatus::BadRequest));
  // Latched: handed back exactly once, and nothing is owed — a client has no
  // response to send, and the transport is gone in any case.
  assert!(matches!(c.handle_eof(), Err(Error::InvalidState(_))));
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());

  // A PARTIAL response head is the sharper diagnosis and keeps it: the peer did
  // start a message, so §2.1's "closed before the head ended" is what a driver
  // is told rather than the no-response-at-all answer above.
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\n");
    assert!(it.next().unwrap().is_none());
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(matches!(
    resolve_eof(&mut c, b""),
    Err(Error::Protocol(H1Error::Framing(
      "connection closed before the head ended"
    )))
  ));

  // And an idle client — no exchange at all — is still the clean close, pending
  // CR included: RFC 9112 §2.2 makes an undecided terminator no part of a
  // message, so there is nothing to have truncated.
  let mut c = Connection::<Client, General>::new();
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(resolve_eof(&mut c, b"").is_ok());
  let mut c = Connection::<Client, General>::new();
  {
    let mut it = c.handle(b"\r\n\r");
    assert!(it.next().unwrap().is_none());
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(resolve_eof(&mut c, b"").is_ok());
}

// The SERVER row: the request arrived in FULL and the response is owed, so a
// read-EOF may not destroy the obligation.
//
// A peer that shuts its write side and waits for the answer is doing legal HTTP
// — RFC 9112 §9.6 tells a client that sent `close` to "cease sending" and go on
// reading, and §9.5 describes a server finishing a response to a request it
// already holds. Draining there would refuse every send call on a connection
// that had done nothing wrong, and the peer would wait for an answer this core
// had silently decided not to give.
#[test]
fn a_read_eof_does_not_destroy_an_owed_response() {
  for (name, request, pull_items) in [
    // The request completed and its items were drained: `AwaitingRearm`.
    ("a drained bodiless request", BODILESS, true),
    // The same request with the items NOT pulled past its head: RFC 9112 §6.3
    // item 7 gives it no body, so the decoder is complete at construction and
    // the `Finished` item is still owed — the EOF is what produces it.
    ("an undrained bodiless request", BODILESS, false),
    // A counted body (§6.3 item 6) that arrived and was drained.
    (
      "a counted request whose octets all arrived",
      b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nhi".as_slice(),
      true,
    ),
  ] {
    let mut c = Connection::<Server, General>::new();
    {
      let mut it = c.handle(request);
      if pull_items {
        while it.next().unwrap().is_some() {}
      } else {
        assert!(
          matches!(it.next().unwrap(), Some(Item::Head { .. })),
          "{name}"
        );
      }
    }

    // The EOF ends nothing by itself: it latches the transport fact and answers
    // `None`. An undrained request still owes its `ExchangeComplete`, and the
    // re-offer is what hands it over — the connection cannot know the request is
    // complete until the driver has shown it there is nothing more.
    assert!(
      matches!(c.handle_eof(), Ok(None)),
      "{name}: the EOF concluded something it cannot see"
    );
    {
      let mut items = c.handle(b"");
      let mut completed = false;
      while let Some(item) = items.next().unwrap_or_else(|e| panic!("{name}: {e:?}")) {
        completed |= matches!(item, Item::ExchangeComplete { .. });
      }
      assert_eq!(
        completed, !pull_items,
        "{name}: the completion item is owed exactly once"
      );
    }
    // Half-closed, not drained: nothing left to read, everything left to write.
    assert!(!c.wants_read(), "{name}");
    assert!(c.is_awaiting_send(), "{name}: the response is still owed");
    // Keep-alive is over and the driver is told once, before it writes.
    assert_eq!(c.transport(), Transport::Ending, "{name}");
    assert_eq!(c.poll_event(), None, "{name}");
    // Idempotent: reporting the same EOF again changes nothing.
    assert!(matches!(c.handle_eof(), Ok(None)), "{name}");
    assert!(c.is_awaiting_send(), "{name}");

    // The response really goes out — this is the whole point of the state.
    let mut out = [0u8; 64];
    let n = c
      .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
      .unwrap_or_else(|e| panic!("{name}: the owed response was refused: {e:?}"));
    assert_eq!(
      &out[..n],
      b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
      "{name}"
    );

    // …and completing it drains the connection, exactly as `Closing` does: no
    // second exchange, nothing more owed, and no second close notice.
    assert!(!c.wants_read(), "{name}");
    assert!(!c.is_awaiting_send(), "{name}");
    assert_eq!(c.poll_event(), None, "{name}");
    assert!(
      matches!(
        c.send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out),
        Err(Error::InvalidState(_))
      ),
      "{name}: the connection took a second response"
    );
  }
}

// The same state with a BODY still to write, and with an interim response
// already sent: RFC 9110 §15.2 lets any number of them precede the final answer,
// and none of them discharges it — so a half-close after one still owes the
// whole final message.
#[test]
fn a_half_closed_server_finishes_the_body_it_started() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let mut out = [0u8; 128];
  // An interim first, so the send side has moved without the exchange ending.
  assert!(c.send_interim(100, NO_FIELDS, &mut out).is_ok());
  // The head of a chunked response, so the send state is `Sending`.
  let chunked: &[(&str, &[u8])] = &[("Transfer-Encoding", b"chunked")];
  assert!(
    c.send_response(200, b"OK", chunked, BodyPlan::Chunked, &mut out)
      .is_ok()
  );

  // Now the peer half-closes, mid-response.
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(!c.wants_read());
  assert!(c.is_awaiting_send());
  assert_eq!(c.transport(), Transport::Ending);

  // The body still writes, and finishing it drains.
  let n = c.send_body(b"hi", &mut out).unwrap();
  assert_eq!(&out[..n], b"2\r\nhi\r\n");
  let n = c.finish_body(NO_TRAILERS, &mut out).unwrap();
  assert_eq!(&out[..n], b"0\r\n\r\n");
  assert!(!c.is_awaiting_send());
  assert!(matches!(
    c.send_body(b"more", &mut out),
    Err(Error::InvalidState(_))
  ));
}

// The rows where the obligation does NOT survive, so the half-close is not a
// blanket "keep everything alive".
#[test]
fn a_read_eof_keeps_only_an_obligation_that_can_still_be_met() {
  // A CLIENT whose own request body is unwritten. RFC 9112 §9.6 tells the sender
  // of a request to "cease sending" when the peer is closing, and there is
  // nobody left to deliver it to — so the exchange ends rather than being held
  // open around a body that can never go out.
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"5")];
  c.open_request(
    "POST",
    &ORIGIN,
    counted,
    BodyPlan::ContentLength(5),
    &mut out,
  )
  .unwrap();
  {
    // A complete response arrives first, so the receive side is through.
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    while it.next().unwrap().is_some() {}
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send(), "a client's unsent body is not owed");
  assert!(matches!(
    c.send_body(b"hello", &mut out),
    Err(Error::InvalidState(_))
  ));

  // A SERVER whose response has already gone out: nothing is owed, so the EOF is
  // the ordinary end of the connection.
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  send_bodiless_response(&mut c);
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());

  // A server whose request is INCOMPLETE owes nothing either: it never received
  // the message it would be answering, so RFC 9112 §6.3 item 6's truncation is
  // what a driver is told and the connection latches rather than half-closing.
  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhi");
    while it.next().unwrap().is_some() {}
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(resolve_eof(&mut c, b"").is_err());
  assert!(!c.is_awaiting_send());
}

/// Two bodiless requests in one read, and the second is the one that matters.
const PIPELINED: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";

/// The same pair with the FIRST request stating RFC 9112 §9.6's `close` option.
const PIPELINED_AFTER_CLOSE: &[u8] =
  b"GET /a HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";

/// Drains one offer and asserts WHICH request targets it served, in order.
///
/// The comparison lives in here rather than in a returned list because the
/// targets borrow the offer: a test says what it expects and this checks it,
/// which is also what makes "nothing was served" (`&[]`) read as an assertion
/// rather than as an empty result nobody looked at.
#[track_caller]
fn serves(c: &mut Connection<Server, General>, offer: &[u8], expected: &[&str], why: &str) {
  let mut seen = 0usize;
  let mut it = c.handle(offer);
  while let Some(item) = it.next().unwrap() {
    let Item::Head {
      line: StartLine::Request(request),
      ..
    } = item
    else {
      continue;
    };
    let Target::Origin { path_and_query } = request.target else {
      panic!("{why}: a request-target this fixture does not use")
    };
    assert_eq!(
      Some(&path_and_query),
      expected.get(seen),
      "{why}: request {seen} is not the one expected"
    );
    seen = seen.saturating_add(1);
  }
  assert_eq!(
    seen,
    expected.len(),
    "{why}: wrong number of requests served"
  );
}

// A half-close does not withdraw the requests the peer already transmitted, and
// RFC 9112 §9.6 says so in as many words: "a TCP connection that is half-closed
// by the client does not delimit a request message, nor does it imply that the
// client is no longer interested in a response."
//
// §9.3.2 had left the second request UNCONSUMED in the driver's buffer until the
// first response went out. Those bytes are a request the peer is still waiting
// for; a connection that dropped them would be reading a transport signal as if
// it were a `close` connection option — which is the reading §9.6 warns against
// in the same paragraph ("transport signals cannot be relied upon to signal edge
// cases, since HTTP/1.1 is independent of transport").
//
// So: both requests are served, in order, both responses go out, and only then
// does the connection drain.
#[test]
fn a_half_closed_server_answers_the_requests_already_in_its_buffer() {
  let mut c = Connection::<Server, General>::new();

  // The first read carries both requests; §9.3.2 stops the pump after the first.
  let at;
  {
    let mut it = c.handle(PIPELINED);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  assert_eq!(at, BODILESS.len(), "§9.3.2 holds the second request back");

  // …and only THEN does the client half-close.
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(
    !c.wants_read(),
    "no byte can arrive on a half-closed read side"
  );
  assert!(c.is_awaiting_send(), "the first response is owed");
  assert_eq!(c.transport(), Transport::Ending);

  // Response one. It re-arms the connection rather than draining it, which is
  // what makes the buffered request reachable.
  send_bodiless_response(&mut c);
  assert!(
    !c.wants_read(),
    "re-offer the BUFFER, do not read the socket"
  );

  // Re-offering the buffer yields the second request — the defect this test
  // replaces asserted it yielded nothing.
  serves(
    &mut c,
    PIPELINED.get(at..).unwrap(),
    &["/b"],
    "the buffered request was dropped",
  );
  assert!(c.is_awaiting_send(), "the second response is owed");

  // Response two, on exchange 2 — RFC 9112 §9.3.2 makes the ORDER the only
  // association between a request and its response, and the ids say so.
  send_bodiless_response(&mut c);

  // Now the buffer really is exhausted, and the connection drains at last.
  {
    let mut it = c.handle(b"");
    assert!(it.next().unwrap().is_none());
    assert_eq!(it.consumed(), 0);
  }
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  assert_eq!(
    c.poll_event(),
    None,
    "the close notice is given exactly once"
  );
  // Drained: a further offer is refused the way §9.6 refuses one.
  let mut it = c.handle(BODILESS);
  assert!(it.next().unwrap().is_none());
  assert_eq!(it.consumed(), 0);
}

// Ordering (a): the response goes out FIRST, the connection re-arms, and only
// THEN does the driver report the EOF.
//
// Nothing about that ordering is unusual — a driver writes the response as soon
// as `is_awaiting_send` says so, and learns about the EOF on its next read — and
// nothing about it changes what the EOF MEANS. But the receive side is idle by
// then and no response is owed, so a rule that decided "is this a half-close?"
// from the exchange state read it as "nothing to preserve" and drained, taking
// the request the driver was still holding with it.
//
// The read side closing is a fact about the TRANSPORT, so it is latched as one.
#[test]
fn an_eof_reported_after_the_rearm_still_keeps_the_buffered_request() {
  let mut c = Connection::<Server, General>::new();
  let at;
  {
    let mut it = c.handle(PIPELINED);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  assert_eq!(at, BODILESS.len(), "§9.3.2 holds the second request back");

  // The response FIRST. This is what re-arms the connection: receive side idle,
  // no exchange, nothing owed — and the driver still holding request two.
  send_bodiless_response(&mut c);
  assert!(
    c.wants_read(),
    "before the EOF it is an ordinary open connection"
  );

  // …and only now the EOF.
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert_eq!(c.transport(), Transport::Ending);
  assert!(!c.wants_read(), "nothing can arrive on a closed read side");

  // The buffered request is still answerable — the invariant at stake.
  serves(
    &mut c,
    PIPELINED.get(at..).unwrap(),
    &["/b"],
    "an EOF reported after the re-arm dropped the buffered request",
  );
  assert!(c.is_awaiting_send());
  send_bodiless_response(&mut c);

  // And only exhaustion drains it.
  {
    let mut it = c.handle(b"");
    assert!(it.next().unwrap().is_none());
  }
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
}

// Ordering (b): the EOF is reported before the response AND again after the re-arm.
//
// `handle_eof` is documented to take the same EOF twice, so a driver that
// reports it on every turn of its loop is doing what the contract allows. The
// second report must therefore be a no-op — never a re-decision, and above all
// never a DOWNGRADE of what the first one established.
#[test]
fn a_repeated_eof_across_the_rearm_is_not_a_downgrade() {
  let mut c = Connection::<Server, General>::new();
  let at;
  {
    let mut it = c.handle(PIPELINED);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert_eq!(c.transport(), Transport::Ending);
  send_bodiless_response(&mut c);

  // The same EOF, reported again now that the connection has re-armed. The
  // once-only question the old notice raised is retired — a level has no
  // delivery count — so what is asserted is that the repeat does not MOVE it.
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert_eq!(
    c.transport(),
    Transport::Ending,
    "a repeated EOF moved the level"
  );

  serves(
    &mut c,
    PIPELINED.get(at..).unwrap(),
    &["/b"],
    "a repeated EOF undid the first one",
  );
  assert!(c.is_awaiting_send());
  send_bodiless_response(&mut c);
  // A third report, now at a boundary, still changes nothing.
  assert!(matches!(c.handle_eof(), Ok(None)));
  serves(&mut c, b"", &[], "a third EOF report produced a message");
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
}

/// Where in the sequence a driver reports the EOF.
#[derive(Debug, Copy, Clone)]
enum Report {
  /// Before the first response — the shape a half-close must not withdraw.
  BeforeResponse,
  /// After it, once the connection has re-armed: ordering (a).
  AfterRearm,
  /// Both, which `handle_eof`'s documented idempotence allows: ordering (b).
  Both,
  /// Twice in a row up front, so the repeat is not merely separated by other
  /// work.
  TwiceUpFront,
}

// The ordering TABLE: when the EOF is reported does not change what it means.
//
// Every row drives the same connection shape — one request answered, a second
// buffered behind it — and differs only in where `handle_eof` falls. Every row
// must end with the buffered request served. The two named tests above are rows
// of this; the table is what says they are not special cases with a fix each,
// which is how the same defect came back relocated.
#[test]
fn the_read_eof_latch_does_not_depend_on_when_it_is_reported() {
  for report in [
    Report::BeforeResponse,
    Report::AfterRearm,
    Report::Both,
    Report::TwiceUpFront,
  ] {
    let mut c = Connection::<Server, General>::new();
    let at;
    {
      let mut it = c.handle(PIPELINED);
      while it.next().unwrap().is_some() {}
      at = it.consumed();
    }
    if matches!(report, Report::BeforeResponse | Report::Both) {
      assert!(matches!(c.handle_eof(), Ok(None)), "{report:?}");
    }
    if matches!(report, Report::TwiceUpFront) {
      assert!(matches!(c.handle_eof(), Ok(None)), "{report:?}");
      assert!(matches!(c.handle_eof(), Ok(None)), "{report:?}");
    }
    send_bodiless_response(&mut c);
    if matches!(report, Report::AfterRearm | Report::Both) {
      assert!(matches!(c.handle_eof(), Ok(None)), "{report:?}");
    }

    // Every ordering reaches the SAME level: order cannot change what a
    // connection is, only when a driver asks. The read side is shut, the
    // buffered request is served, and the connection drains only once it is
    // exhausted.
    assert_eq!(c.transport(), Transport::Ending, "{report:?}");
    assert!(!c.wants_read(), "{report:?}");
    serves(
      &mut c,
      PIPELINED.get(at..).unwrap(),
      &["/b"],
      "the buffered request was lost",
    );
    send_bodiless_response(&mut c);
    {
      let mut it = c.handle(b"");
      assert!(it.next().unwrap().is_none(), "{report:?}");
    }
    assert!(!c.wants_read(), "{report:?}");
    assert!(!c.is_awaiting_send(), "{report:?}");
    // Drained: §9.6's refusal of anything further.
    let mut it = c.handle(BODILESS);
    assert!(it.next().unwrap().is_none(), "{report:?}");
    assert_eq!(it.consumed(), 0, "{report:?}");
  }
}

// The rows of the same table the latch must NOT change: a truncation is not a
// half-close, and an EOF at a boundary with the buffer genuinely empty still
// ends the connection.
#[test]
fn the_read_eof_latch_leaves_the_truncation_rows_alone() {
  // Mid-head and mid-body stay errors, reported before the latch is reached: a
  // message the peer began and abandoned is not a half-close.
  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(b"GET /a HTTP/1.1\r\n");
    assert!(it.next().unwrap().is_none());
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(resolve_eof(&mut c, b"").is_err());
  assert!(!c.is_awaiting_send(), "a truncation owes no answer at EOF");

  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhi");
    while it.next().unwrap().is_some() {}
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(resolve_eof(&mut c, b"").is_err());

  // An EOF at a boundary with nothing buffered: the connection cannot see the
  // driver's buffer, so it latches and the PUMP finds the exhaustion.
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  send_bodiless_response(&mut c);
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert_eq!(c.transport(), Transport::Ending);
  {
    let mut it = c.handle(b"");
    assert!(it.next().unwrap().is_none());
  }
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  let mut it = c.handle(BODILESS);
  assert!(it.next().unwrap().is_none());
  assert_eq!(it.consumed(), 0, "drained: nothing further is processed");
}

// The CLIENT mirror, checked rather than asserted in prose: a client cannot be
// holding a buffered NEXT message the way a server holds a pipelined next
// request, so its EOF rows have no sticky fact to keep.
//
// Two rules make that structural rather than lucky. This end keeps ONE request
// of its own outstanding, so no §9.3.2 re-arm gate leaves a second RESPONSE
// unconsumed — that gate is what strands a server's second request in the first
// place. And RFC 9112 §9.2 makes bytes arriving with nothing outstanding a fault
// rather than a message, so whatever sits behind the response is not a message
// the client could lose.
#[test]
fn a_client_has_no_buffered_message_to_lose_at_eof() {
  const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  {
    let mut it = c.handle(RESPONSE);
    while it.next().unwrap().is_some() {}
    // The whole response was consumed: nothing is held back, because nothing
    // gates a client's receive side the way §9.3.2 gates a server's.
    assert_eq!(it.consumed(), RESPONSE.len());
  }
  // Re-armed and idle: §9.2 makes this a healthy connection with nothing
  // outstanding, which is why it wants no bytes.
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());

  // So the EOF here is the clean close §9.5 describes, and drains — there is no
  // buffered message it could be destroying.
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(!c.wants_read());
  // The re-offer that finds nothing left is what drains it — there was no
  // buffered message, so this is the clean-close row rather than a truncation.
  assert!(resolve_eof(&mut c, b"").is_ok());
  let mut out = [0u8; 64];
  assert!(
    matches!(
      c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out),
      Err(Error::InvalidState(_))
    ),
    "a drained client opens no further request"
  );
}

// A REGRESSION REPLAY, verbatim: a driver holding a COMPLETE message drops the
// iterator mid-body, sees the socket close, and reports the EOF before offering
// the rest.
//
// `Items` blesses that shape outright — a driver may stop pulling and re-offer
// the remainder later — and nothing in `handle_eof`'s contract says the buffer
// must be drained first. So the octets that complete this message are sitting in
// the driver's hand while the connection is being asked whether the message was
// truncated. It cannot know: it never saw them. Answering anyway failed an
// intact message and latched a healthy connection.
//
// The rule the fix restores is the one this crate already applied to the DRAIN:
// the connection cannot see the driver's buffer, so a conclusion that depends on
// the absence of further bytes is the PUMP's to draw, on the offer that runs out.
#[test]
fn an_eof_over_a_complete_buffered_message_is_not_a_truncation() {
  const REQUEST: &[u8] = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello";
  let mut c = Connection::<Server, General>::new();

  // The driver pulls the head and STOPS, leaving all five body octets unoffered.
  let at;
  {
    let mut it = c.handle(REQUEST);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    at = it.consumed();
  }
  assert!(
    at < REQUEST.len(),
    "the body is still the driver's to offer"
  );

  // Then the socket closes, and the driver says so before offering the rest.
  assert!(
    matches!(c.handle_eof(), Ok(None)),
    "the EOF cannot see the buffer and must not guess"
  );

  // Re-offering completes the message: the body arrives, the exchange ends, and
  // nothing was refused.
  let mut body = 0usize;
  let mut complete = false;
  {
    let mut it = c.handle(REQUEST.get(at..).unwrap());
    while let Some(item) = it.next().expect("an intact message is not a fault") {
      match item {
        Item::BodyChunk { data, .. } => body = body.saturating_add(data.len()),
        Item::ExchangeComplete { .. } => complete = true,
        _ => {}
      }
    }
  }
  assert_eq!(body, b"hello".len());
  assert!(complete, "the message completed");

  // And the connection is usable: the response it owes still goes out.
  assert!(c.is_awaiting_send());
  let mut out = [0u8; 64];
  assert!(
    c.send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
      .is_ok()
  );
}

// The same shape for the other two message forms the defect could hide in: a
// chunked body (RFC 9112 §7.1) whose framing lines were never offered, and a
// COMPLETE HEAD that was never parsed at all — where the connection holds a
// watermark over bytes it has seen and the terminator is in the driver's hand.
#[test]
fn an_eof_over_other_complete_buffered_shapes_is_not_a_truncation() {
  // Chunked, dropped after the head.
  const CHUNKED: &[u8] =
    b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
  let mut c = Connection::<Server, General>::new();
  let at;
  {
    let mut it = c.handle(CHUNKED);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    at = it.consumed();
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  let mut complete = false;
  {
    let mut it = c.handle(CHUNKED.get(at..).unwrap());
    while let Some(item) = it.next().expect("an intact chunked body is not a fault") {
      if matches!(item, Item::ExchangeComplete { .. }) {
        complete = true;
      }
    }
  }
  assert!(complete);
  assert!(c.is_awaiting_send());

  // A head the driver offered only PART of, with the rest still buffered: the
  // watermark is past zero, which used to read as "closed mid-head".
  const REQUEST: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
  let split = REQUEST.len().saturating_sub(6);
  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(REQUEST.get(..split).unwrap());
    assert!(it.next().unwrap().is_none());
    assert_eq!(it.consumed(), 0);
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  let mut served = false;
  {
    let mut it = c.handle(REQUEST);
    while let Some(item) = it.next().expect("the head was complete all along") {
      if matches!(item, Item::Head { .. }) {
        served = true;
      }
    }
  }
  assert!(served, "the buffered remainder completed the head");
  assert!(c.is_awaiting_send());

  // The CLIENT twin: a complete response buffered behind a dropped iterator.
  const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  let at;
  {
    let mut it = c.handle(RESPONSE);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    at = it.consumed();
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  let mut complete = false;
  {
    let mut it = c.handle(RESPONSE.get(at..).unwrap());
    while let Some(item) = it.next().expect("an intact response is not a truncation") {
      if matches!(item, Item::ExchangeComplete { .. }) {
        complete = true;
      }
    }
  }
  assert!(complete, "the buffered response completed the exchange");
}

// The GENUINE truncations, each still diagnosed with the constant it always had
// — now on the re-offer that proves them rather than on a guess. This is the
// other half of the property: moving the conclusions must not lose them.
#[test]
fn genuine_truncations_are_still_diagnosed_on_the_exhausting_offer() {
  // Mid-head (RFC 9112 §2.1), with nothing left to complete it.
  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(b"GET /a HTTP/1.1\r\nHos");
    assert!(it.next().unwrap().is_none());
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(matches!(
    resolve_eof(&mut c, b"GET /a HTTP/1.1\r\nHos"),
    Err(Error::Protocol(H1Error::Framing(
      "connection closed before the head ended"
    )))
  ));

  // Mid-body, counted (§6.3 item 6).
  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhi");
    while it.next().unwrap().is_some() {}
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(matches!(
    resolve_eof(&mut c, b""),
    Err(Error::Protocol(H1Error::Framing(
      "connection closed before the Content-Length body ended"
    )))
  ));

  // Mid-body, chunked (§7.1: the trailer section never closed).
  let mut c = Connection::<Server, General>::new();
  {
    let mut it =
      c.handle(b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n");
    while it.next().unwrap().is_some() {}
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(matches!(
    resolve_eof(&mut c, b""),
    Err(Error::Protocol(H1Error::Framing(
      "connection closed before the chunked body ended"
    )))
  ));

  // A client whose request went out and got no final response (§9.5).
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(matches!(
    resolve_eof(&mut c, b""),
    Err(Error::Protocol(H1Error::Framing(
      "connection closed before the response arrived"
    )))
  ));
}

// An EMPTY re-offer is sufficient, and is what resolves an EOF taken at a true
// message boundary: the connection has nothing left to be told, so the offer
// that carries nothing is the one that proves the buffer empty and drains it.
#[test]
fn an_empty_reoffer_resolves_an_eof_at_a_boundary() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  send_bodiless_response(&mut c);
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(!c.wants_read());

  // Still Open until the buffer is shown to be empty — the connection cannot
  // assume it.
  assert!(resolve_eof(&mut c, b"").is_ok());
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  // Drained: RFC 9112 §9.6's refusal of anything further.
  let mut it = c.handle(BODILESS);
  assert!(it.next().unwrap().is_none());
  assert_eq!(it.consumed(), 0);
}

// The DATA-LOSS shape, and the last instance of the class: completing a
// close-delimited body is itself a conclusion that no more bytes will arrive
// ("these are all the octets that came"), so it belongs where the driver's
// buffer is visible.
//
// Drawn at the EOF instead, it completed the message over octets the driver had
// not offered yet — and those octets were then silently dropped, the decoder
// having been moved to `Done`. That is worse than a false truncation: a wrong
// answer rather than a refused one.
//
// RFC 9112 §6.3 item 8 is unchanged; only where it is applied moved.
#[test]
fn an_eof_over_an_unoffered_close_delimited_body_loses_nothing() {
  const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\r\nhello world";
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");

  // The driver pulls the head and STOPS: every body octet is still its own.
  let at;
  {
    let mut it = c.handle(RESPONSE);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    at = it.consumed();
  }
  assert!(
    at < RESPONSE.len(),
    "the body is still the driver's to offer"
  );
  // §6.3 item 8 with §9.3: the driver already knows keep-alive is over.
  assert_eq!(c.transport(), Transport::Ending);

  // Then the socket closes, and the driver says so before offering the rest.
  assert!(
    matches!(c.handle_eof(), Ok(None)),
    "the EOF cannot see the buffer and must not complete the body over it"
  );

  // The unoffered octets ARRIVE, and the completion comes after them.
  let mut body = 0usize;
  let mut complete = false;
  {
    let mut it = c.handle(RESPONSE.get(at..).unwrap());
    while let Some(item) = it.next().expect("an intact message is not a fault") {
      match item {
        Item::BodyChunk { data, .. } => {
          assert!(!complete, "body octets arrived after the completion");
          body = body.saturating_add(data.len());
        }
        Item::ExchangeComplete { .. } => complete = true,
        _ => {}
      }
    }
  }
  assert_eq!(
    body,
    b"hello world".len(),
    "close-delimited octets were lost"
  );
  assert!(complete, "the close still completes the message");
  assert!(!c.wants_read());
}

// The empty-buffer twin: an EOF taken when the driver really has offered
// everything. The completion still waits for the re-offer — that offer just
// carries nothing, which is exactly the handshake `handle_eof` documents.
#[test]
fn an_empty_reoffer_completes_a_close_delimited_body() {
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\n\r\nhello");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::BodyChunk { data: b"hello", .. })
    ));
    assert!(it.next().unwrap().is_none());
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  {
    let mut it = c.handle(b"");
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
    assert!(it.next().unwrap().is_none());
  }
  // Exactly once: the decoder is spent, and a further offer produces nothing.
  let mut it = c.handle(b"");
  assert!(it.next().unwrap().is_none());
}

// THE BARRIER, and the ordering it exists for: a client completes an exchange,
// the driver DROPS the iterator with the offer's tail still unread, and opens
// its next request. Re-offering that tail would have bytes which arrived BEFORE
// the new request was written parsed as that request's response.
//
// RFC 9112 §9.2 is unambiguous about what those bytes are: data received with no
// request outstanding, which a client "MUST NOT consider to be a valid
// response". This crate already diagnoses them on the idle path — what was
// missing is that an exchange opened over them takes them off that path, and the
// diagnosis with it.
//
// The connection cannot see the driver's buffer, so it may not assume the offer
// was exhausted: only a pump pass that reaches the idle boundary can say so.
#[test]
fn a_client_cannot_open_a_request_over_an_unread_tail() {
  // The tail here is a second response the client never asked for.
  const STREAM: &[u8] = b"HTTP/1.1 204 \r\n\r\nHTTP/1.1 204 \r\n\r\n";
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");

  // The driver pulls the completion and stops, leaving the tail unread.
  let at;
  {
    let mut it = c.handle(STREAM);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
    at = it.consumed();
  }
  assert!(at < STREAM.len(), "the tail is still unread");

  // Opening now is refused: the connection cannot tell an exhausted offer from
  // one holding bytes that would be misattributed to this request.
  let mut out = [0u8; 64];
  assert_eq!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out),
    Err(Error::InvalidState(
      "the previous offer has not been read back"
    ))
  );

  // The cure is the pump: offering the tail diagnoses it as §9.2's non-response,
  // which is the correct answer for it.
  let error = resolve_eof(&mut c, STREAM.get(at..).unwrap()).unwrap_err();
  assert!(matches!(
    error,
    Error::Protocol(H1Error::Framing(
      "response bytes with no outstanding request"
    ))
  ));
}

// The same barrier, lifted the ordinary way: when the tail is EMPTY the pump
// reaches the idle boundary, says so, and the next request opens. This is the
// path every well-behaved driver takes, so the barrier must cost it nothing.
#[test]
fn reading_the_offer_back_to_its_end_lifts_the_barrier() {
  const RESPONSE: &[u8] = b"HTTP/1.1 204 \r\n\r\n";
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  let at;
  {
    let mut it = c.handle(RESPONSE);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  assert_eq!(at, RESPONSE.len());
  // Pulling to `Ok(None)` above already reached the boundary, so the barrier is
  // gone and this opens.
  let mut out = [0u8; 64];
  assert!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_ok()
  );

  // And the same when the driver drops early but then re-offers the remainder —
  // here an empty slice, which is a sufficient offer.
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  {
    let mut it = c.handle(RESPONSE);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
  }
  assert!(matches!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out),
    Err(Error::InvalidState(_))
  ));
  {
    let mut it = c.handle(b"");
    assert!(it.next().unwrap().is_none());
  }
  assert!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_ok(),
    "an empty re-offer is enough to lift the barrier"
  );

  // Stray CRLFs between exchanges are §9.2's tolerated case, so reading them
  // back reaches the boundary too rather than stranding the connection.
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  {
    let mut it = c.handle(b"HTTP/1.1 204 \r\n\r\n\r\n");
    while it.next().unwrap().is_some() {}
  }
  assert!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_ok()
  );
}

// The other refusal, named apart because it asks the driver for something else:
// once an EOF has been reported no response can ever arrive, so there is nothing
// to open. "Finish reading first" and "this connection is over" are different
// instructions and a driver must be able to tell them apart.
#[test]
fn a_client_opens_no_request_once_the_read_side_has_ended() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 64];
  // A clean, fully-resolved idle connection — the barrier is not what refuses.
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert_eq!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out),
    Err(Error::InvalidState(
      "the connection can no longer receive a response"
    ))
  );
  // And it stays refused after the re-offer that drains it.
  assert!(resolve_eof(&mut c, b"").is_ok());
  assert!(matches!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out),
    Err(Error::InvalidState(_))
  ));
}

// NON-REGRESSION, and the reason the barrier is client-only: a SERVER holding
// pipelined requests after a re-arm is legal RFC 9112 §9.3.2 traffic. Those
// bytes were sent BY the peer FOR this end to answer, which is the opposite of
// §9.2's situation, and nothing about answering one request may make the next
// unreadable.
#[test]
fn a_servers_pipelined_requests_are_untouched_by_the_barrier() {
  let mut c = Connection::<Server, General>::new();
  let at;
  {
    let mut it = c.handle(PIPELINED);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  assert_eq!(at, BODILESS.len(), "§9.3.2 holds the second request back");
  send_bodiless_response(&mut c);
  // The second request is read and answered exactly as before.
  serves(
    &mut c,
    PIPELINED.get(at..).unwrap(),
    &["/b"],
    "the barrier reached the server side",
  );
  assert!(c.is_awaiting_send());
  send_bodiless_response(&mut c);
  assert!(
    c.wants_read(),
    "a server between exchanges still wants bytes"
  );

  // The same with the iterator DROPPED after the first completion, which is the
  // client-side trigger: a server must still take the pipelined request.
  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(PIPELINED);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
  }
  send_bodiless_response(&mut c);
  serves(
    &mut c,
    PIPELINED.get(at..).unwrap(),
    &["/b"],
    "an early drop stranded a server's pipelined request",
  );
}

// THE SECOND FINDING, verbatim: a client is uploading, and the server answers
// early with a response that ends the connection — a 413 with
// `Connection: close` while the body is still going out.
//
// RFC 9112 §9.5 makes that response the end of the exchange whatever this end
// had left to say, and §9.6 tells the sender of the request to "cease sending".
// Without the release the send side stayed owed: the receive side could never
// settle, `is_awaiting_send()` went on demanding output for a message the peer
// had already answered and closed, and `send_body` stayed legal — so a driver
// following the readiness split wrote the rest of an upload nobody would read.
#[test]
fn a_final_response_that_closes_releases_the_client_from_its_body() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
  c.open_request(
    "POST",
    &ORIGIN,
    counted,
    BodyPlan::ContentLength(11),
    &mut out,
  )
  .expect("a counted request opens");
  let n = c.send_body(b"hello", &mut out).unwrap();
  assert_eq!(&out[..n], b"hello");

  // The server rejects it and closes, mid-upload.
  {
    let mut it =
      c.handle(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head { interim: false, .. })
    ));
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
    assert!(it.next().unwrap().is_none());
  }
  assert_eq!(c.transport(), Transport::Ending);

  // The exchange settled in BOTH directions, so nothing is demanded of the driver.
  assert!(
    !c.is_awaiting_send(),
    "the driver was still being asked to write an abandoned body"
  );
  assert!(!c.wants_read());
  // The exchange really SETTLED in both directions — `Abandoned` owes nothing,
  // so the re-arm gate opened and RFC 9112 §9.6's drain actually happened.
  //
  // Read off the private state, because nothing public distinguishes it: a
  // connection stuck in `Closing` with the receive side awaiting a re-arm
  // refuses the same calls for different reasons and looks identical from
  // outside. That is precisely why it is worth pinning — an internal state that
  // still claims a message is in flight is what the next defect grows from.
  assert!(
    matches!(c.lifecycle, Lifecycle::Draining),
    "the exchange did not settle: {:?}",
    c.lifecycle
  );

  // And writing anyway is refused with a reason, not a silent success and not a
  // misleading "no body in flight": the caller knows its own state, what changed
  // is on the wire.
  assert_eq!(
    c.send_body(b" world", &mut out),
    Err(Error::InvalidState(
      "the peer ended the exchange before this body was sent"
    ))
  );
  assert_eq!(
    c.finish_body(NO_TRAILERS, &mut out),
    Err(Error::InvalidState(
      "the peer ended the exchange before this body was sent"
    ))
  );
}

// The same release from the OTHER trigger, and the same words: RFC 9112 §9.6 is
// one rule, and an EOF ends the exchange from the receive side exactly as a
// closing final response does. Two triggers, one transition — pinned together so
// they cannot drift.
#[test]
fn both_receive_side_endings_release_the_body_identically() {
  /// How the exchange is ended from the receive side.
  #[derive(Debug, Copy, Clone)]
  enum Ending {
    /// A final response stating RFC 9112 §9.6's `close` option.
    ClosingResponse,
    /// §6.3 item 8's close-delimited response, which §9.3 makes non-persistent.
    CloseDelimited,
    /// The transport's read side ending.
    ReadEof,
  }

  for ending in [
    Ending::ClosingResponse,
    Ending::CloseDelimited,
    Ending::ReadEof,
  ] {
    let mut c = Connection::<Client, General>::new();
    let mut out = [0u8; 128];
    let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
    c.open_request(
      "POST",
      &ORIGIN,
      counted,
      BodyPlan::ContentLength(11),
      &mut out,
    )
    .expect("a counted request opens");
    c.send_body(b"hello", &mut out).unwrap();

    match ending {
      Ending::ClosingResponse => {
        let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        while it.next().unwrap().is_some() {}
      }
      Ending::CloseDelimited => {
        {
          let mut it = c.handle(b"HTTP/1.1 200 OK\r\n\r\n");
          while it.next().unwrap().is_some() {}
        }
        // Item 8's body ends at the close, so the exchange completes there.
        assert!(matches!(c.handle_eof(), Ok(None)));
        let mut it = c.handle(b"");
        while it.next().unwrap().is_some() {}
      }
      Ending::ReadEof => {
        {
          let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
          while it.next().unwrap().is_some() {}
        }
        assert!(matches!(c.handle_eof(), Ok(None)));
      }
    }

    assert!(!c.is_awaiting_send(), "{ending:?}: an obligation survived");
    assert!(!c.wants_read(), "{ending:?}");
    assert_eq!(
      c.send_body(b" world", &mut out),
      Err(Error::InvalidState(
        "the peer ended the exchange before this body was sent"
      )),
      "{ending:?}: the release did not name its reason"
    );
  }
}

// The rule is scoped, and the scope matters: a final response that does NOT end
// keep-alive leaves the upload alone. RFC 9112 §9.3 lets a server answer before
// it has read the whole request and the connection stays persistent, so the
// client finishes what it was sending.
#[test]
fn a_final_response_that_keeps_the_connection_leaves_the_body_alone() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
  c.open_request(
    "POST",
    &ORIGIN,
    counted,
    BodyPlan::ContentLength(11),
    &mut out,
  )
  .expect("a counted request opens");
  c.send_body(b"hello", &mut out).unwrap();
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    while it.next().unwrap().is_some() {}
  }
  // The response is in and the connection is staying open, so the upload is
  // still this end's to finish — and the exchange has NOT settled behind it.
  assert!(c.is_awaiting_send());
  let n = c.send_body(b" world", &mut out).unwrap();
  assert_eq!(&out[..n], b" world");
  assert_eq!(c.finish_body(NO_TRAILERS, &mut out).unwrap(), 0);
  assert!(!c.is_awaiting_send());

  // An INTERIM response ends no EXCHANGE either (RFC 9110 §15.2), so on its own
  // it leaves the upload alone. What releases the body is the peer's `close`,
  // not the interim-ness — `a_plain_interim_response_releases_nothing` is the
  // dedicated pin, and the test below is the one where the interim DOES carry
  // the option.
  let mut c = Connection::<Client, General>::new();
  c.open_request(
    "POST",
    &ORIGIN,
    counted,
    BodyPlan::ContentLength(11),
    &mut out,
  )
  .expect("a counted request opens");
  c.send_body(b"hello", &mut out).unwrap();
  {
    let mut it = c.handle(b"HTTP/1.1 100 \r\n\r\n");
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head { interim: true, .. })
    ));
  }
  let n = c.send_body(b" world", &mut out).unwrap();
  assert_eq!(&out[..n], b" world");
}

// The ORDERING: the peer states `close` on an INTERIM response, and the final
// response that ends the exchange does not repeat it.
//
// RFC 9110 §15.2 lets any number of interim responses precede the final one, and
// RFC 9112 §9.6 puts no restriction on which of them carries the option — "as a
// request header field indicates that this is the last request … while in a
// response, the same field indicates that the server is going to close this
// connection". A decision taken from the CURRENT head forgets it, and the client
// went on being asked for body octets the peer had already said it would stop
// reading.
#[test]
fn a_close_on_an_interim_response_is_remembered_at_the_final_one() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
  c.open_request(
    "POST",
    &ORIGIN,
    counted,
    BodyPlan::ContentLength(11),
    &mut out,
  )
  .expect("a counted request opens");
  c.send_body(b"hello", &mut out).unwrap();

  // The interim carries the option; the final head does not.
  {
    let mut it = c.handle(b"HTTP/1.1 100 \r\nConnection: close\r\n\r\n");
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head { interim: true, .. })
    ));
    assert!(it.next().unwrap().is_none());
  }
  assert!(matches!(
    c.poll_event(),
    Some(Event::ExchangeAborted { .. })
  ));
  assert_eq!(c.transport(), Transport::Ending);
  // RFC 9112 §9.6 binds the option to the response CARRYING it — "after it sends
  // the response containing the close connection option" — and a 1xx is a
  // response message. So the release is immediate, not deferred to a final
  // response a conforming server will never send.
  assert_eq!(
    c.send_body(b" wor", &mut out),
    Err(Error::InvalidState(
      "the peer ended the exchange before this body was sent"
    ))
  );

  // The exchange is over at that head: §9.6 makes the peer close after the
  // response carrying the option, and an interim IS complete at its head (§6.3
  // item 1), so nothing more is coming and the connection drained.
  assert!(!c.is_awaiting_send());
  assert!(!c.wants_read(), "a driver told to wait would wait to EOF");
  assert!(
    matches!(c.lifecycle, Lifecycle::Draining),
    "the exchange did not terminate: {:?}",
    c.lifecycle
  );

  // A server that sends a final response ANYWAY does not get it parsed: it is
  // inadmissible, so it can no longer complete an exchange on a connection §9.6
  // says has already closed.
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert!(
      it.next().unwrap().is_none(),
      "a late final response was parsed"
    );
    assert_eq!(it.consumed(), 0);
  }
  assert_eq!(
    c.send_body(b"ld", &mut out),
    Err(Error::InvalidState(
      "the peer ended the exchange before this body was sent"
    ))
  );
}

// THE CONTROL, and the rule it protects: a LOCAL close must NOT abandon the
// body. RFC 9112 §9.6 lets the exchange in flight finish — `close()` says this
// end will begin no further exchange, and says nothing whatever about whether
// the peer is still reading.
//
// Both provenances reach `Lifecycle::Closing`, which is exactly why the decision
// cannot be taken from it.
#[test]
fn a_local_close_during_an_upload_still_lets_the_exchange_finish() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
  c.open_request(
    "POST",
    &ORIGIN,
    counted,
    BodyPlan::ContentLength(11),
    &mut out,
  )
  .expect("a counted request opens");
  c.send_body(b"hello", &mut out).unwrap();

  // OUR close, not the peer's.
  c.close();
  assert_eq!(c.transport(), Transport::Ending);
  assert!(matches!(c.lifecycle, Lifecycle::Closing));

  // The response arrives without any `close` of its own.
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    while it.next().unwrap().is_some() {}
  }
  // The upload is still ours to finish: the peer never said it would stop
  // reading, and §9.6's cease-sending is about the peer's decision.
  assert!(c.is_awaiting_send());
  let n = c.send_body(b" world", &mut out).unwrap();
  assert_eq!(&out[..n], b" world");
  assert_eq!(c.finish_body(NO_TRAILERS, &mut out).unwrap(), 0);
  assert!(!c.is_awaiting_send());
  assert!(matches!(c.lifecycle, Lifecycle::Draining));
}

// The provenance is accumulated from EVERY head the peer sent, so every shape
// keeps working: the option on the final head, the option on an interim with the
// final one repeating it, and §6.3 item 8's close-delimited framing, which says
// the same thing with no field at all.
#[test]
fn every_way_the_peer_can_state_a_close_releases_the_body() {
  /// Where the peer put its `close`.
  #[derive(Debug, Copy, Clone)]
  enum Said {
    /// On the final head only.
    Final,
    /// On an interim only.
    Interim,
    /// On both.
    Both,
    /// Not at all, but the response is close-delimited (§6.3 item 8).
    CloseDelimited,
  }

  for said in [Said::Final, Said::Interim, Said::Both, Said::CloseDelimited] {
    let mut c = Connection::<Client, General>::new();
    let mut out = [0u8; 128];
    let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
    c.open_request(
      "POST",
      &ORIGIN,
      counted,
      BodyPlan::ContentLength(11),
      &mut out,
    )
    .expect("a counted request opens");
    c.send_body(b"hello", &mut out).unwrap();

    if matches!(said, Said::Interim | Said::Both) {
      let mut it = c.handle(b"HTTP/1.1 100 \r\nConnection: close\r\n\r\n");
      while it.next().unwrap().is_some() {}
    }
    let final_head: &[u8] = match said {
      Said::Final | Said::Both => {
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
      }
      Said::Interim => b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
      // Neither framing field: §6.3 item 8 delimits it by the close.
      Said::CloseDelimited => b"HTTP/1.1 200 OK\r\n\r\n",
    };
    {
      let mut it = c.handle(final_head);
      while it.next().unwrap().is_some() {}
    }
    if matches!(said, Said::CloseDelimited) {
      // Item 8's body ends at the close, so the exchange completes there.
      assert!(matches!(c.handle_eof(), Ok(None)));
      let mut it = c.handle(b"");
      while it.next().unwrap().is_some() {}
    }

    assert!(!c.is_awaiting_send(), "{said:?}: an obligation survived");
    assert_eq!(
      c.send_body(b" world", &mut out),
      Err(Error::InvalidState(
        "the peer ended the exchange before this body was sent"
      )),
      "{said:?}"
    );
  }
}

// And the scope holds from the other side: an interim that says nothing about
// closing changes nothing at all. RFC 9110 §15.2 makes it informational, and
// §9.3 keeps the connection persistent.
#[test]
fn a_plain_interim_response_releases_nothing() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
  c.open_request(
    "POST",
    &ORIGIN,
    counted,
    BodyPlan::ContentLength(11),
    &mut out,
  )
  .expect("a counted request opens");
  c.send_body(b"hello", &mut out).unwrap();
  {
    let mut it = c.handle(b"HTTP/1.1 100 \r\n\r\n");
    while it.next().unwrap().is_some() {}
  }
  assert_eq!(c.poll_event(), None, "a plain interim ends no keep-alive");
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    while it.next().unwrap().is_some() {}
  }
  // The connection stays open and the upload stays ours.
  assert!(c.is_awaiting_send());
  assert!(c.send_body(b" world", &mut out).is_ok());
  assert_eq!(c.finish_body(NO_TRAILERS, &mut out).unwrap(), 0);
}

/// The refusal a caller's `Connection: close` on an interim response earns.
const INTERIM_STATES_NO_CLOSE: &str = "an interim response states no Connection: close";

/// What a released body is told.
const RELEASED: &str = "the peer ended the exchange before this body was sent";

// The inbound General ordering: the release fires AT the interim that carries
// the close, not at a final response that will never come.
//
// RFC 9112 §9.6 draws the distinction itself. A server that RECEIVES the option
// closes "after it sends the final response"; a server that SENDS one closes
// "after it sends the response containing the close connection option" — the
// RESPONSE CARRYING IT, not the final one. A 1xx is a response message (RFC 9110
// §15.2), so the peer has committed to closing after that head — and the final
// response this end was waiting for is one a conforming server never sends.
// Deferring the release to it left `send_body` legal and the caller waiting
// forever.
//
// Both body framings, because the release must not depend on how this end framed
// what it was sending.
#[test]
fn an_interim_close_releases_the_body_at_once() {
  for chunked in [false, true] {
    let mut c = Connection::<Client, General>::new();
    let mut out = [0u8; 128];
    let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
    let chunky: &[(&str, &[u8])] = &[("Host", b"h"), ("Transfer-Encoding", b"chunked")];
    let (fields, plan) = if chunked {
      (chunky, BodyPlan::Chunked)
    } else {
      (counted, BodyPlan::ContentLength(11))
    };
    c.open_request("POST", &ORIGIN, fields, plan, &mut out)
      .expect("a request with a body opens");
    assert!(c.send_body(b"hello", &mut out).is_ok(), "chunked={chunked}");

    {
      let mut it = c.handle(b"HTTP/1.1 100 \r\nConnection: close\r\n\r\n");
      assert!(matches!(
        it.next().unwrap(),
        Some(Item::Head { interim: true, .. })
      ));
      assert!(it.next().unwrap().is_none());
    }

    // Released immediately, and told why.
    assert_eq!(
      c.send_body(b" world", &mut out),
      Err(Error::InvalidState(RELEASED)),
      "chunked={chunked}"
    );
    assert_eq!(
      c.finish_body(NO_TRAILERS, &mut out),
      Err(Error::InvalidState(RELEASED)),
      "chunked={chunked}"
    );
    assert!(!c.is_awaiting_send(), "chunked={chunked}");
    assert!(
      matches!(c.poll_event(), Some(Event::ExchangeAborted { .. })),
      "chunked={chunked}"
    );
    assert_eq!(c.transport(), Transport::Ending, "chunked={chunked}");
  }
}

// The same ordering under a split feed and under an iterator dropped mid-stream:
// the release is a consequence of the HEAD, so neither how the interim was
// delivered nor whether the driver kept pulling may change when it fires.
#[test]
fn the_interim_close_release_does_not_depend_on_the_feed_shape() {
  const INTERIM: &[u8] = b"HTTP/1.1 100 \r\nConnection: close\r\n\r\n";

  // Split at every interior point.
  for cut in 1..INTERIM.len() {
    let mut c = Connection::<Client, General>::new();
    let mut out = [0u8; 128];
    let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
    c.open_request(
      "POST",
      &ORIGIN,
      counted,
      BodyPlan::ContentLength(11),
      &mut out,
    )
    .expect("a counted request opens");
    c.send_body(b"hello", &mut out).unwrap();
    {
      let mut it = c.handle(INTERIM.get(..cut).unwrap());
      assert!(it.next().unwrap().is_none(), "cut {cut}");
    }
    // A partial head releases nothing: the option has not been read yet.
    assert!(c.send_body(b" ", &mut out).is_ok(), "cut {cut}");
    {
      let mut it = c.handle(INTERIM);
      assert!(matches!(
        it.next().unwrap(),
        Some(Item::Head { interim: true, .. })
      ));
    }
    assert_eq!(
      c.send_body(b"x", &mut out),
      Err(Error::InvalidState(RELEASED)),
      "cut {cut}"
    );
  }

  // Dropped the moment the head came out, with the offer's tail unread.
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
  c.open_request(
    "POST",
    &ORIGIN,
    counted,
    BodyPlan::ContentLength(11),
    &mut out,
  )
  .expect("a counted request opens");
  c.send_body(b"hello", &mut out).unwrap();
  let at;
  {
    let mut it = c.handle(
      b"HTTP/1.1 100 \r\nConnection: close\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head { interim: true, .. })
    ));
    at = it.consumed();
  }
  assert_eq!(
    c.send_body(b"x", &mut out),
    Err(Error::InvalidState(RELEASED))
  );
  // And re-offering the tail still completes the exchange behind it.
  {
    let mut it = c.handle(
      b"HTTP/1.1 100 \r\nConnection: close\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        .get(at..)
        .unwrap(),
    );
    while it.next().unwrap().is_some() {}
  }
  assert!(!c.is_awaiting_send());
}

// The OUTBOUND General site: `send_interim` refuses a caller-supplied
// `Connection: close` rather than emitting it.
//
// RFC 9112 §9.6 binds the option to the response CARRYING it, and RFC 9110 §15.2
// makes an interim the response that does NOT end the exchange — so stating it
// here asks for two contradictory things at once. Refused before encoding, with
// nothing written; a server that means to close says so on the final response or
// calls `close()`, and both still work.
#[test]
fn an_interim_response_may_not_state_a_close() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let mut out = [0xAAu8; 128];
  let closing: &[(&str, &[u8])] = &[("Connection", b"close")];
  assert_eq!(
    c.send_interim(100, closing, &mut out),
    Err(Error::InvalidState(INTERIM_STATES_NO_CLOSE))
  );
  assert_eq!(
    out, [0xAAu8; 128],
    "a refused interim wrote into the buffer"
  );
  // Inert: the connection did not close behind the refusal, and the interim path
  // still works without the field.
  assert_eq!(c.poll_event(), None);
  let n = c.send_interim(100, NO_FIELDS, &mut out).unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 100 \r\n\r\n");

  // The legal way to say it is unchanged: on the FINAL response.
  let closing_final: &[(&str, &[u8])] = &[("Content-Length", b"0"), ("Connection", b"close")];
  let n = c
    .send_response(200, b"OK", closing_final, BodyPlan::None, &mut out)
    .expect("a final response takes the option");
  assert_eq!(
    &out[..n],
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  );
  assert_eq!(c.transport(), Transport::Ending);
  assert!(!c.wants_read());
}

// Ordering: a close-bearing interim TERMINATES the exchange, it does not merely
// release the body.
//
// The body release above makes one consequence of a received close follow the
// fact at the interim boundary. The other — the exchange ending — was still
// gated on the head being final, so `recv` stayed idle, the exchange stayed
// active, `wants_read()` stayed true, and a peer that sent no final response
// left the caller waiting to EOF.
//
// RFC 9112 §9.6 makes the peer close after the response CARRYING the option is
// complete, and §6.3 item 1 makes a 1xx complete at its head. So there is nothing
// further to wait for, and the driver must be told that rather than left reading.
#[test]
fn a_close_bearing_interim_terminates_the_exchange() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
  c.open_request(
    "POST",
    &ORIGIN,
    counted,
    BodyPlan::ContentLength(11),
    &mut out,
  )
  .expect("a counted request opens");
  c.send_body(b"hello", &mut out).unwrap();
  assert!(c.wants_read());

  {
    let mut it = c.handle(b"HTTP/1.1 100 \r\nConnection: close\r\n\r\n");
    // The head item IS yielded: a 1xx is a real response and RFC 9110 §15.2
    // entitles the driver to see the one that carried the option.
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head { interim: true, .. })
    ));
    assert!(it.next().unwrap().is_none());
    // …and the offset it covers is still reported, so the driver's buffer
    // arithmetic is unchanged by the termination.
    assert_eq!(
      it.consumed(),
      b"HTTP/1.1 100 \r\nConnection: close\r\n\r\n".len()
    );
  }

  // Every consequence, together — the exchange-scoped notice first, because it
  // names the message the driver was tracking.
  assert!(
    matches!(c.poll_event(), Some(Event::ExchangeAborted { .. })),
    "the driver never learned this exchange died unanswered"
  );
  assert_eq!(c.transport(), Transport::Ending);
  assert_eq!(c.poll_event(), None);
  assert_eq!(
    c.send_body(b" world", &mut out),
    Err(Error::InvalidState(RELEASED)),
    "the body was not released"
  );
  assert!(!c.wants_read(), "the driver would have waited to EOF");
  assert!(!c.is_awaiting_send());
  assert!(
    matches!(c.lifecycle, Lifecycle::Draining),
    "the exchange did not terminate: {:?}",
    c.lifecycle
  );

  // A later final response is inadmissible: not parsed, not consumed, and it can
  // no longer complete an exchange on a connection §9.6 says has closed.
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert!(it.next().unwrap().is_none());
    assert_eq!(it.consumed(), 0);
  }
  // And the peer that sends nothing further costs the driver no wait: both
  // readiness answers were already false above, so it closes rather than
  // blocking on a read that can never complete.
  assert!(matches!(c.handle_eof(), Ok(None)));
}

// THE ROUTINE'S POINT, asserted directly: every trigger of "the peer asked to
// close" produces the SAME set of consequences, so a consequence added to the
// routine is applied at all of them.
//
// The three triggers differ only in WHEN the exchange can end, and RFC 9112 §9.6
// is what makes that difference: the peer closes after the response carrying the
// option is COMPLETE. An interim is complete at its head; a final response ends
// where its body does, so its `ExchangeComplete` still comes from the body path.
// Once each has reached its own message end, the state is identical.
#[test]
fn every_received_close_produces_the_same_consequences() {
  /// Which head carried the peer's close.
  #[derive(Debug, Copy, Clone)]
  enum Trigger {
    /// RFC 9112 §9.6's option on an interim response.
    Interim,
    /// The same option on the final response.
    Final,
    /// §6.3 item 8's close-delimited framing, which says it with no field.
    CloseDelimited,
  }

  for trigger in [Trigger::Interim, Trigger::Final, Trigger::CloseDelimited] {
    let mut c = Connection::<Client, General>::new();
    let mut out = [0u8; 128];
    let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
    c.open_request(
      "POST",
      &ORIGIN,
      counted,
      BodyPlan::ContentLength(11),
      &mut out,
    )
    .expect("a counted request opens");
    c.send_body(b"hello", &mut out).unwrap();

    // Whether the exchange ended with an answer is what differs, so it is
    // recorded rather than assumed.
    let mut completed = false;
    let drain = |c: &mut Connection<Client, General>, offer: &[u8], completed: &mut bool| {
      let mut it = c.handle(offer);
      while let Some(item) = it.next().unwrap() {
        *completed |= matches!(item, Item::ExchangeComplete { .. });
      }
    };
    match trigger {
      Trigger::Interim => drain(
        &mut c,
        b"HTTP/1.1 100 \r\nConnection: close\r\n\r\n",
        &mut completed,
      ),
      Trigger::Final => drain(
        &mut c,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        &mut completed,
      ),
      Trigger::CloseDelimited => {
        drain(&mut c, b"HTTP/1.1 200 OK\r\n\r\n", &mut completed);
        // Item 8's body ends at the close, so the message ends there.
        assert!(matches!(c.handle_eof(), Ok(None)));
        drain(&mut c, b"", &mut completed);
      }
    }

    // THE SHARED SET: identical whichever head carried the option.
    assert_eq!(
      c.send_body(b" world", &mut out),
      Err(Error::InvalidState(RELEASED)),
      "{trigger:?}: the body was not released"
    );
    assert!(!c.wants_read(), "{trigger:?}: still waiting for bytes");
    assert!(!c.is_awaiting_send(), "{trigger:?}: still owed output");
    assert!(
      matches!(c.lifecycle, Lifecycle::Draining),
      "{trigger:?}: did not terminate: {:?}",
      c.lifecycle
    );
    // Nothing further is admissible on any of them.
    {
      let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
      assert!(it.next().unwrap().is_none(), "{trigger:?}");
      assert_eq!(it.consumed(), 0, "{trigger:?}");
    }

    // THE CONTRAST, and the point of the abort: how the exchange ENDED differs,
    // because only one of these three ends it without an answer. RFC 9110 §15.2
    // makes a 1xx informational and explicitly not the final response; the other
    // two ARE the response, close-delimited included — §6.3 item 8 makes the
    // close that message's delimiter, so it is COMPLETE, not aborted.
    match trigger {
      Trigger::Interim => {
        assert!(!completed, "an interim yielded a completion");
        assert!(
          matches!(c.poll_event(), Some(Event::ExchangeAborted { .. })),
          "the unanswered exchange was never named"
        );
      }
      Trigger::Final | Trigger::CloseDelimited => {
        assert!(completed, "{trigger:?}: no completion item");
        // …and NO abort: this exchange got its answer.
      }
    }
    assert_eq!(
      c.transport(),
      Transport::Ending,
      "{trigger:?}: keep-alive is over"
    );
    assert_eq!(c.poll_event(), None, "{trigger:?}: no message fact is owed");
  }
}

// The termination is a consequence of the HEAD, so neither the feed shape nor a
// dropped iterator may change when it fires.
#[test]
fn the_interim_close_termination_does_not_depend_on_the_feed_shape() {
  const INTERIM: &[u8] = b"HTTP/1.1 100 \r\nConnection: close\r\n\r\n";
  const TRAILING: &[u8] =
    b"HTTP/1.1 100 \r\nConnection: close\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

  // Split at every interior point.
  for cut in 1..INTERIM.len() {
    let mut c = Connection::<Client, General>::new();
    open_bodiless_request(&mut c, "GET");
    {
      let mut it = c.handle(INTERIM.get(..cut).unwrap());
      assert!(it.next().unwrap().is_none(), "cut {cut}");
    }
    // A partial head terminates nothing: the option has not been read yet.
    assert!(c.wants_read(), "cut {cut}: gave up on a partial head");
    {
      let mut it = c.handle(INTERIM);
      assert!(matches!(
        it.next().unwrap(),
        Some(Item::Head { interim: true, .. })
      ));
    }
    assert!(!c.wants_read(), "cut {cut}");
    assert!(matches!(c.lifecycle, Lifecycle::Draining), "cut {cut}");
  }

  // Dropped the instant the head came out, with the offer's tail unread — the
  // tail is a final response, and re-offering it must still not parse one.
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  let at;
  {
    let mut it = c.handle(TRAILING);
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head { interim: true, .. })
    ));
    at = it.consumed();
  }
  assert_eq!(
    at,
    INTERIM.len(),
    "the interim's own bytes are still counted"
  );
  assert!(!c.wants_read());
  {
    let mut it = c.handle(TRAILING.get(at..).unwrap());
    assert!(it.next().unwrap().is_none(), "the tail was parsed");
    assert_eq!(it.consumed(), 0);
  }
}

// The control: an interim WITHOUT the option changes nothing at all. RFC 9110
// §15.2 makes it informational, §9.3 keeps the connection persistent, and the
// exchange goes on exactly as before.
#[test]
fn a_plain_interim_terminates_nothing() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"11")];
  c.open_request(
    "POST",
    &ORIGIN,
    counted,
    BodyPlan::ContentLength(11),
    &mut out,
  )
  .expect("a counted request opens");
  c.send_body(b"hello", &mut out).unwrap();
  {
    let mut it = c.handle(b"HTTP/1.1 100 \r\n\r\n");
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head { interim: true, .. })
    ));
    assert!(it.next().unwrap().is_none());
  }
  assert_eq!(c.poll_event(), None);
  assert!(c.wants_read(), "the final response is still to come");
  assert!(matches!(c.lifecycle, Lifecycle::Open));
  // The upload is still ours, and the final response still completes normally.
  assert!(c.send_body(b" world", &mut out).is_ok());
  assert_eq!(c.finish_body(NO_TRAILERS, &mut out).unwrap(), 0);
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head { interim: false, .. })
    ));
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
  }
}

// The ids and their order, which is the other half of RFC 9112 §9.3.2: the
// buffered request opens the NEXT exchange rather than reusing the one that just
// ended, so a driver correlating responses by order still can.
#[test]
fn a_half_closed_server_numbers_its_buffered_exchanges_in_order() {
  let mut c = Connection::<Server, General>::new();
  let mut first = None;
  let at;
  {
    let mut it = c.handle(PIPELINED);
    while let Some(item) = it.next().unwrap() {
      if let Item::Head { exchange, .. } = item {
        first = Some(exchange);
      }
    }
    at = it.consumed();
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  send_bodiless_response(&mut c);

  let mut second = None;
  {
    let mut it = c.handle(PIPELINED.get(at..).unwrap());
    while let Some(item) = it.next().unwrap() {
      if let Item::Head { exchange, .. } = item {
        second = Some(exchange);
      }
    }
  }
  let (first, second) = (first.unwrap(), second.unwrap());
  assert_ne!(
    first, second,
    "the buffered request opened its own exchange"
  );
  assert!(first < second, "ids stay monotone across the half-close");
}

// THE CONTROL, and the rule it must not break: RFC 9112 §9.6's `close` connection
// option really does forbid processing anything further: "The server MUST NOT
// process any further requests received on that connection". That rule belongs to
// the OPTION, not to the transport, so a half-close after a request that stated
// `close` still suppresses the request pipelined behind it.
//
// The first response is owed and sendable either way; what differs is that the
// second request is never read.
#[test]
fn a_close_option_still_suppresses_the_request_behind_it() {
  let mut c = Connection::<Server, General>::new();
  let at;
  {
    let mut it = c.handle(PIPELINED_AFTER_CLOSE);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  // The option was read from the head, so keep-alive is already over.
  assert_eq!(c.transport(), Transport::Ending);

  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(c.is_awaiting_send(), "the response to /a is still owed");
  assert_eq!(
    c.transport(),
    Transport::Ending,
    "the EOF behind the option moved the level"
  );
  send_bodiless_response(&mut c);

  // Suppressed: §9.6's MUST NOT, unchanged by the half-close.
  serves(
    &mut c,
    PIPELINED_AFTER_CLOSE.get(at..).unwrap(),
    &[],
    "a request behind a `close` option was processed",
  );
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
}

// The same control from the other direction: a `close` option this END states —
// or a local `close()` — collapses a half-closed connection just as the peer's
// does. §9.6 gives both senders the same MUST NOT.
#[test]
fn a_local_close_collapses_a_half_closed_connection() {
  // A response that states `close`.
  let mut c = Connection::<Server, General>::new();
  let at;
  {
    let mut it = c.handle(PIPELINED);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  let mut out = [0u8; 128];
  let closing: &[(&str, &[u8])] = &[("Content-Length", b"0"), ("Connection", b"close")];
  assert!(
    c.send_response(200, b"OK", closing, BodyPlan::None, &mut out)
      .is_ok()
  );
  serves(
    &mut c,
    PIPELINED.get(at..).unwrap(),
    &[],
    "a response stating `close` did not stop the buffered request",
  );

  // And a local `close()` between the two.
  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(PIPELINED);
    while it.next().unwrap().is_some() {}
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  c.close();
  send_bodiless_response(&mut c);
  serves(
    &mut c,
    PIPELINED.get(at..).unwrap(),
    &[],
    "a local close did not stop the buffered request",
  );
}

// The one-answer rule across the half-close: a buffered request that turns out
// to be MALFORMED still leaves the server owing exactly one error response, and
// that response is still writable — the write side is what a half-close leaves
// open, so unlike a violation found AT the EOF there is somebody to answer.
//
// The close notice is not repeated: it was given when the read side ended, and
// keep-alive ending is one fact about the connection, read as one level.
#[test]
fn a_malformed_buffered_request_still_owes_its_one_answer() {
  const PIPELINED_BAD: &[u8] =
    b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nPOST /b HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
  let mut c = Connection::<Server, General>::new();
  let at;
  {
    let mut it = c.handle(PIPELINED_BAD);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert_eq!(c.transport(), Transport::Ending);
  send_bodiless_response(&mut c);

  // The buffered request is read, and refused: RFC 9112 §6.3 item 3.
  let error = {
    let mut it = c.handle(PIPELINED_BAD.get(at..).unwrap());
    it.next().expect_err("both framing fields are unframable")
  };
  assert_eq!(error.suggested_status(), Some(SuggestedStatus::BadRequest));
  // One answer owed, and still sendable — the peer is still reading.
  assert!(c.is_awaiting_send());
  let mut out = [0u8; 128];
  let n = c
    .send_error_response(400, b"Bad Request", NO_FIELDS, &mut out)
    .expect("the single error response is owed");
  assert_eq!(
    out.get(..n),
    Some(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".as_slice())
  );
  // Spent, drained, and the notice was never repeated.
  assert!(!c.is_awaiting_send());
  assert_eq!(c.poll_event(), None);
  assert!(matches!(
    c.send_error_response(400, b"", NO_FIELDS, &mut out),
    Err(Error::InvalidState(_))
  ));
}

// A message the peer BEGAN and did not finish is a TRUNCATION, reported the
// moment the connection knows no more bytes can arrive — not a silent stop, and
// above all not a wait for input that cannot come.
//
// RFC 9112 §2.1 makes a message begin with a complete head. Once the read side
// has ended, a re-offered buffer that runs out mid-head is that head's last word,
// so the fault is provable NOW; stopping quietly would leave the driver holding a
// connection that wants nothing, owes nothing, and never mentioned the
// half-received request.
#[test]
fn a_truncated_buffered_request_is_reported_not_awaited() {
  const PIPELINED_PARTIAL: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHos";
  let mut c = Connection::<Server, General>::new();
  let at;
  {
    let mut it = c.handle(PIPELINED_PARTIAL);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  send_bodiless_response(&mut c);

  // The re-offer diagnoses it rather than waiting: no item, no consumption, and
  // the exact §2.1 fault.
  let error = {
    let mut it = c.handle(PIPELINED_PARTIAL.get(at..).unwrap());
    let error = it
      .next()
      .expect_err("a partial head cannot become a message");
    assert_eq!(it.consumed(), 0);
    error
  };
  assert!(matches!(
    error,
    Error::Protocol(H1Error::Framing("connection closed before the head ended"))
  ));
  // Latched, and never a request to read more: a truncation found this way owes
  // no answer, exactly as one found at the EOF itself does not.
  assert!(!c.wants_read(), "a closed read side is never waited on");
  assert!(!c.is_awaiting_send());
  assert!(matches!(
    c.handle(PIPELINED_PARTIAL.get(at..).unwrap()).next(),
    Err(Error::InvalidState(_))
  ));
}

// A REGRESSION REPLAY, verbatim. Everything in it happens in one connection:
//
//   request1 complete, request2 buffered behind it carrying BOTH a
//   `Connection: close` option and a `Content-Length: 5` whose body is only
//   two octets long, with the EOF reported BEFORE response1.
//
// It is the case that broke every earlier encoding, because it drives the two
// facts in opposite directions at the same moment: request2's `close` option
// moves POLICY, and the peer's FIN has already moved the TRANSPORT. While both
// lived in one enum, the option's transition erased the read-side fact — after
// which `wants_read()` went back to TRUE and the driver was sent to a socket at
// EOF, and the partial body was never diagnosed at all.
//
// With the two facts in separate fields, every step lands where it should.
#[test]
fn a_close_option_on_a_buffered_request_does_not_erase_the_read_eof() {
  const REQ1: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
  const STREAM: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n\
      POST /b HTTP/1.1\r\nHost: h\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhi";
  let mut c = Connection::<Server, General>::new();

  // Request one is served; §9.3.2 holds request two back.
  let at;
  {
    let mut it = c.handle(STREAM);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  assert_eq!(at, REQ1.len());

  // The EOF arrives BEFORE response one.
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert_eq!(c.transport(), Transport::Ending);
  assert!(!c.wants_read());
  assert!(c.is_awaiting_send());
  send_bodiless_response(&mut c);
  assert!(
    !c.wants_read(),
    "the re-arm did not resurrect the read side"
  );

  // The tail is re-offered. Request two's head yields — a FIN withdrew nothing
  // the peer had already sent — and its `close` option collapses POLICY as it
  // goes, without touching the transport fact.
  let tail = STREAM.get(at..).unwrap();
  {
    let mut it = c.handle(tail);
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::Head {
        line: StartLine::Request(_),
        ..
      })
    ));
    // The two body octets that DID arrive are delivered.
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::BodyChunk { data: b"hi", .. })
    ));
    // And the three that did not are a truncation, now — RFC 9112 §6.3 item 6
    // makes a short counted body a MUST-incomplete, and nothing more is coming.
    let error = it
      .next()
      .expect_err("three octets of the body never arrived");
    assert!(matches!(
      error,
      Error::Protocol(H1Error::Framing(
        "connection closed before the Content-Length body ended"
      ))
    ));
  }

  // Never a wait for bytes that cannot arrive — the invariant at stake, and it
  // holds at every step above as well as here.
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  // The close notice was given exactly once, by whichever cause came first.
  assert_eq!(c.poll_event(), None);
}

// The same stream with request two's body COMPLETE, so the regression's other
// half is pinned too: the `close` option collapses policy, the request is served
// in full, its response goes out, and §9.6 then refuses anything behind it.
#[test]
fn a_buffered_request_with_a_close_option_is_served_and_ends_the_connection() {
  const REQ1: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
  const STREAM: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n\
      POST /b HTTP/1.1\r\nHost: h\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello\
      GET /c HTTP/1.1\r\nHost: h\r\n\r\n";
  let mut c = Connection::<Server, General>::new();
  let at;
  {
    let mut it = c.handle(STREAM);
    while it.next().unwrap().is_some() {}
    at = it.consumed();
  }
  assert_eq!(at, REQ1.len());
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert_eq!(c.transport(), Transport::Ending);
  send_bodiless_response(&mut c);

  // Request two is served whole.
  let tail = STREAM.get(at..).unwrap();
  let after;
  {
    let mut it = c.handle(tail);
    let mut body = 0usize;
    while let Some(item) = it.next().unwrap() {
      if let Item::BodyChunk { data, .. } = item {
        body = body.saturating_add(data.len());
      }
    }
    assert_eq!(body, b"hello".len());
    after = it.consumed();
  }
  assert_eq!(c.poll_event(), None, "the notice is not repeated");
  assert!(c.is_awaiting_send());
  send_bodiless_response(&mut c);

  // …and request THREE is suppressed by §9.6: "The server MUST NOT process any
  // further requests received on that connection", which is the OPTION's rule
  // and still applies with the transport fact set beside it.
  serves(
    &mut c,
    tail.get(after..).unwrap(),
    &[],
    "a request behind a `close` option was processed",
  );
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
}

// A violation found AT the EOF is not half-closed: the single error answer is
// owed only where one can still be sent, and a connection whose read side ended
// on a truncated message has a peer that is no longer listening for a diagnosis
// of it. The `answerable = false` arm of `latch`, pinned from here.
#[test]
fn a_violation_at_eof_leaves_no_answer_owed() {
  let mut c = Connection::<Server, General>::new();
  {
    let mut it =
      c.handle(b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel");
    while it.next().unwrap().is_some() {}
  }
  assert!(matches!(c.handle_eof(), Ok(None)));
  assert!(resolve_eof(&mut c, b"").is_err());
  assert!(!c.is_awaiting_send());
  assert!(!c.wants_read());
  let mut out = [0u8; 64];
  assert!(matches!(
    c.send_error_response(400, b"", NO_FIELDS, &mut out),
    Err(Error::InvalidState(_))
  ));
}

// RFC 9112 §9.6: a local close ends keep-alive, and between exchanges there is
// nothing left to finish — the connection stops wanting bytes at once.
#[test]
fn local_close_between_exchanges_drains_immediately() {
  let mut c = Connection::<Server, General>::new();
  assert!(c.wants_read());
  c.close();
  assert_eq!(c.transport(), Transport::Ending);
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  let mut it = c.handle(BODILESS);
  assert!(it.next().unwrap().is_none());
  assert_eq!(it.consumed(), 0);
}

// RFC 9112 §9.2: a client with no outstanding request needs no bytes — reading
// more cannot produce an item, and the wants-read/awaiting-send split says so
// rather than leaving the driver to guess.
#[test]
fn idle_client_wants_nothing_until_a_request_is_outstanding() {
  let mut c = Connection::<Client, General>::new();
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  open_bodiless_request(&mut c, "GET");
  assert!(c.wants_read());
}

// RFC 9112 §6.3 item 1: a response to HEAD is bodiless "regardless of the header
// fields present", so the connection has to remember which method it sent.
#[test]
fn client_head_request_takes_no_body() {
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "HEAD");
  let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde");
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  // The five octets the field announced belong to no body: the exchange ends at
  // the head, and those bytes stay unconsumed for whatever follows.
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
  assert_eq!(
    it.consumed(),
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".len()
  );
}

// RFC 9112 §3 (`request-line`) and §5 (the field lines under it): the head goes
// out exactly as the caller stated it, and §9.3.2's one-exchange-at-a-time rule
// makes a second open while one is outstanding caller-side misuse — this end
// never pipelines requests of its own.
#[test]
fn client_request_response_roundtrip_shapes() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 256];
  let hdrs: &[(&str, &[u8])] = &[("Host", b"h")];
  let n = c
    .open_request("GET", &ORIGIN, hdrs, BodyPlan::None, &mut out)
    .unwrap();
  assert_eq!(&out[..n], b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
  // second open while in flight → InvalidState (no client pipelining)
  assert!(matches!(
    c.open_request(
      "GET",
      &Target::Origin {
        path_and_query: "/x"
      },
      hdrs,
      BodyPlan::None,
      &mut out
    ),
    Err(Error::InvalidState(_))
  ));
  // The response completes the exchange — and the pump must reach the idle
  // boundary before the next request may open, since only it can say the offer
  // held nothing behind that response (RFC 9112 §9.2).
  {
    let mut it = c.handle(b"HTTP/1.1 204 \r\n\r\n");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
    assert!(it.next().unwrap().is_none());
  }
  let n = c
    .open_request("GET", &ORIGIN, hdrs, BodyPlan::None, &mut out)
    .unwrap();
  assert_eq!(&out[..n], b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
}

// CONNECT is Tunnel-mode-only.
#[test]
fn client_connect_rejected_in_general() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let hdrs: &[(&str, &[u8])] = &[("Host", b"h")];
  assert!(matches!(
    c.open_request(
      "CONNECT",
      &Target::Authority { host_port: "h:443" },
      hdrs,
      BodyPlan::None,
      &mut out
    ),
    Err(Error::InvalidState(_))
  ));
}

// RFC 9112 §2.2 with §9.2: an undecided lone CR at a client's idle cursor is a
// byte the connection has not read yet, and `wants_read()` says so. Opening the
// next request over it would clear the flag and feed a bare CR into the response
// parse, so the request waits for the byte that settles it.
#[test]
fn open_request_refuses_an_undecided_pending_cr() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  let mut it = c.handle(b"\r");
  assert!(it.next().unwrap().is_none());
  assert!(c.wants_read());
  assert!(matches!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out),
    Err(Error::InvalidState(_))
  ));

  // The LF arrives, the pair is discarded, and the request opens.
  let mut it2 = c.handle(b"\r\n");
  assert!(it2.next().unwrap().is_none());
  assert_eq!(it2.consumed(), 2);
  assert!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_ok()
  );
}

// RFC 9112 §3.2: "A client MUST send a Host header field in all HTTP/1.1 request
// messages." Every request this core writes states HTTP/1.1, so the rule binds
// every one of them — checked at the boundary, before a byte is measured.
#[test]
fn a_client_request_states_its_host() {
  let mut out = [0xAAu8; 128];
  let mut c = Connection::<Client, General>::new();
  assert_eq!(
    c.open_request("GET", &ORIGIN, NO_FIELDS, BodyPlan::None, &mut out),
    Err(Error::InvalidState(REQUEST_NEEDS_HOST))
  );
  // Nothing written, and nothing spent: the exchange has not opened, so the
  // corrected request is still the first one on this connection.
  assert_eq!(out, [0xAAu8; 128]);

  // A section that frames its body but forgets the field is the same refusal —
  // the check is not a fallback for a section that says nothing.
  let counted: &[(&str, &[u8])] = &[("Content-Length", b"0")];
  assert_eq!(
    c.open_request("POST", &ORIGIN, counted, BodyPlan::None, &mut out),
    Err(Error::InvalidState(REQUEST_NEEDS_HOST))
  );
  assert_eq!(out, [0xAAu8; 128]);

  // §3.2 again, the other half: "If the authority component is missing or
  // undefined for the target URI, then a client MUST send a Host header field
  // with an empty field value" — so an EMPTY value is the field, not its
  // absence, and the receive side accepts one for the same reason.
  let empty: &[(&str, &[u8])] = &[("Host", b"")];
  let n = c
    .open_request("GET", &ORIGIN, empty, BodyPlan::None, &mut out)
    .expect("an empty Host is the field RFC 9112 §3.2 asks for");
  assert_eq!(&out[..n], b"GET / HTTP/1.1\r\nHost: \r\n\r\n");

  // And the ordinary case, on a fresh connection since the one above is in
  // flight. The name is matched ASCII-case-insensitively (RFC 9110 §5.1).
  let mut c = Connection::<Client, General>::new();
  let lowercase: &[(&str, &[u8])] = &[("hOsT", b"h")];
  let n = c
    .open_request("GET", &ORIGIN, lowercase, BodyPlan::None, &mut out)
    .expect("field names are case-insensitive");
  assert_eq!(&out[..n], b"GET / HTTP/1.1\r\nhOsT: h\r\n\r\n");
}

// The RFC-mandated 400-then-close path out of Failed (RFC 9112 §6.3 item 3 for
// the fault, §6.1's MUST-close for the answer, RFC 9110 §7.6.1 for the
// `Connection` field that states it).
#[test]
fn server_error_response_after_protocol_error() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(
    b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
  ); // TE+CL
  let e = it.next().unwrap_err();
  let code = e.suggested_status().unwrap().code(); // 400
  assert_eq!(code, 400);
  // (No explicit `drop(it)`: `Items` implements no `Drop`, so the borrow simply
  // ends at its last use and `clippy::drop_non_drop` would fire on one.)
  let mut out = [0u8; 128];
  let empty: &[(&str, &[u8])] = &[];
  let n = c.send_error_response(code, b"", empty, &mut out).unwrap();
  let s = core::str::from_utf8(&out[..n]).unwrap();
  assert!(s.starts_with("HTTP/1.1 400 "));
  assert!(s.contains("Connection: close\r\n"));
  assert_eq!(s, "HTTP/1.1 400 \r\nConnection: close\r\n\r\n");
  assert_eq!(c.transport(), Transport::Ending); // forced Draining (9112 §6.1 MUST close)
  assert!(c.send_error_response(400, b"", empty, &mut out).is_err()); // exactly once
  assert!(
    c.send_response(200, b"", empty, BodyPlan::None, &mut out)
      .is_err()
  );
  // …and the inbound side is over too: §9.6 processes no further byte.
  let mut it2 = c.handle(BODILESS);
  assert!(it2.next().unwrap().is_none());
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
}

// RFC 9110 §5.3 (repeated field lines are one comma-separated list) with §9.6:
// the `close` connection option this path MUST send is injected, so a caller
// that also states one would put two `Connection` lines on the wire — one
// message saying two things about the connection. Refused rather than folded,
// and refusing costs the caller nothing: the single allowed answer is still
// owed.
#[test]
fn error_response_refuses_fields_that_contradict_it() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(b"GET / HTTP/1.1\r\nHost : bad\r\n\r\n");
  assert!(it.next().is_err());
  let mut out = [0u8; 128];
  let their_close: &[(&str, &[u8])] = &[("connection", b"close")];
  assert!(matches!(
    c.send_error_response(400, b"", their_close, &mut out),
    Err(Error::InvalidState(_))
  ));
  assert_eq!(out, [0u8; 128]); // nothing written

  // Nor may the head announce a body: this message is close-delimited by the
  // close it forces (RFC 9112 §6.3 item 8), so octets announced and never
  // written would leave the peer treating the one answer it gets as incomplete
  // (item 6). `Content-Length: 0` says "no body" and is fine.
  let five: &[(&str, &[u8])] = &[("Content-Length", b"5")];
  assert!(matches!(
    c.send_error_response(400, b"", five, &mut out),
    Err(Error::InvalidState(_))
  ));
  let chunked: &[(&str, &[u8])] = &[("Transfer-Encoding", b"chunked")];
  assert!(matches!(
    c.send_error_response(400, b"", chunked, &mut out),
    Err(Error::InvalidState(_))
  ));

  // None of the refusals spent the one answer the connection allows.
  assert!(c.is_awaiting_send());
  let n = c
    .send_error_response(400, b"Bad Request", LENGTH_0, &mut out)
    .unwrap();
  assert_eq!(
    &out[..n],
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  );
}

// RFC 9112 §2.1 with §11.1: a response is ONE message, so a server that has
// already answered has no second answer to give — the single error response is
// owed only while the response to the message in flight has not started going
// out. A 400 written here would be read as part of the response the peer is
// already parsing.
#[test]
fn a_violation_after_the_final_response_owes_no_answer() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n");
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  assert!(it.next().unwrap().is_none());

  // Answered on the head alone, which §9.3.2 allows: re-arm is gated on both
  // directions finishing, in whichever order they do.
  let mut out = [0u8; 128];
  let n = c
    .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
    .unwrap();

  // …and only then does the request body turn out to be malformed (§7.1:
  // `chunk-size` is `1*HEXDIG`).
  let mut it2 = c.handle(b"zz\r\n");
  assert!(it2.next().is_err());
  assert!(!c.is_awaiting_send()); // the one answer was already spent
  assert!(matches!(
    c.send_error_response(400, b"", NO_FIELDS, &mut out[n..]),
    Err(Error::InvalidState(_))
  ));
  assert_eq!(&out[..n], b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  assert!(out.get(n..).unwrap().iter().all(|&b| b == 0));
  // The `Err` was the notice; a latch queues no event of its own (see `latch`).
  assert_eq!(c.poll_event(), None);
}

// The same rule at its worst point (RFC 9112 §11.1): with a counted body part
// written, an error response would land INSIDE the octets the head announced —
// the peer would read the 400 as body bytes of the 200 and then parse whatever
// followed as the next message.
#[test]
fn a_violation_while_a_body_is_being_written_owes_no_answer() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n");
  while it.next().unwrap().is_some() {}

  let mut out = [0u8; 128];
  let five: &[(&str, &[u8])] = &[("Content-Length", b"5")];
  let mut w = c
    .send_response(200, b"OK", five, BodyPlan::ContentLength(5), &mut out)
    .unwrap();
  w += c.send_body(b"hel", &mut out[w..]).unwrap();

  let mut it2 = c.handle(b"zz\r\n");
  assert!(it2.next().is_err());
  assert!(!c.is_awaiting_send());
  assert!(matches!(
    c.send_error_response(400, b"", NO_FIELDS, &mut out[w..]),
    Err(Error::InvalidState(_))
  ));
  assert_eq!(
    &out[..w],
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"
  );
  assert!(out.get(w..).unwrap().iter().all(|&b| b == 0));
  // Nor can the body go on, and WHICH refusal is the point: not the counted
  // body's own rules (the count is still short, so `finish_body` would have
  // said so) but the LATCH — the connection is failed, not merely stuck, and
  // every call on it answers with the same sentence.
  assert_eq!(
    c.send_body(b"lo", &mut out[w..]),
    Err(Error::InvalidState(FAILED))
  );
  assert_eq!(
    c.finish_body(NO_TRAILERS, &mut out[w..]),
    Err(Error::InvalidState(FAILED))
  );
}

// RFC 9112 §6.3 item 4 with §7.1, on the SEND side and read more strictly than a
// peer's list is: a recipient tolerates `gzip, chunked` because item 4 ¶1 still
// tells it where the body ends, but a sender that wrote it would be naming a
// coding it never applied — this core applies exactly one. So the declaration
// must be a lone, final, unparameterized `chunked`, or the octets `send_body`
// writes are not the octets the head announced (§11.1, §11.2).
#[test]
fn a_chunked_plan_needs_a_chunked_declaration() {
  let mut out = [0u8; 256];
  for bad in [
    b"chunked, gzip".as_slice(), // item 4 ¶2: the chunked frames nothing here
    b"gzip, chunked",            // delimited, but gzip was never applied
    b"chunked, chunked",         // §6.1: applied more than once
    b"chunked;a=b",              // §7.1 defines no parameters for it
    b"gzip",
  ] {
    let mut c = Connection::<Server, General>::new();
    feed_request(&mut c, BODILESS);
    let hdrs: &[(&str, &[u8])] = &[("Transfer-Encoding", bad)];
    assert_eq!(
      c.send_response(200, b"OK", hdrs, BodyPlan::Chunked, &mut out),
      Err(Error::InvalidState(CHUNKED_DECLARATION)),
      "{bad:?}"
    );
    assert!(c.is_awaiting_send(), "{bad:?}"); // refused, and still owed
  }

  // RFC 9110 §5.2 folds repeated field lines into ONE list, so a `gzip` line in
  // front of a `chunked` line is `gzip, chunked` and refused just the same.
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let split: &[(&str, &[u8])] = &[
    ("Transfer-Encoding", b"gzip"),
    ("Transfer-Encoding", b"chunked"),
  ];
  assert_eq!(
    c.send_response(200, b"OK", split, BodyPlan::Chunked, &mut out),
    Err(Error::InvalidState(CHUNKED_DECLARATION))
  );

  // The one declaration this core will write a chunked body under.
  let chunked: &[(&str, &[u8])] = &[("Transfer-Encoding", b"chunked")];
  assert!(
    c.send_response(200, b"OK", chunked, BodyPlan::Chunked, &mut out)
      .is_ok()
  );
}

// RFC 9112 §9.6 with the exactly-once rule `signal_close` states: the single
// error answer forces a close of its own, but a connection whose close was
// already announced — the peer's option, or a local `close()` — must not hear
// the same fact twice.
#[test]
fn error_response_does_not_repeat_a_close_already_signaled() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n");
  while it.next().unwrap().is_some() {}
  c.close();
  assert_eq!(c.transport(), Transport::Ending);

  // A chunk-size line that is not `1*HEXDIG` fails the connection while it is
  // already closing (RFC 9112 §7.1).
  let mut it2 = c.handle(b"zz\r\n");
  assert!(it2.next().is_err());
  assert!(c.is_awaiting_send()); // the single answer is owed

  let mut out = [0u8; 128];
  let n = c
    .send_error_response(400, b"", NO_FIELDS, &mut out)
    .unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 400 \r\nConnection: close\r\n\r\n");
  assert_eq!(c.poll_event(), None); // announced once, when it first happened
}

// RFC 9112 §9.6: a sender of the `close` connection option "MUST initiate a
// close of the connection after it sends the response", so the option ends
// keep-alive whichever end wrote it — the connection drains instead of
// re-arming, exactly as it does for a request that stated one.
#[test]
fn a_response_that_states_close_drains_the_connection() {
  let mut c = Connection::<Server, General>::new();
  let two = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
  let mut it = c.handle(two);
  while it.next().unwrap().is_some() {}
  assert_eq!(it.consumed(), BODILESS.len());

  let mut out = [0u8; 128];
  let closing: &[(&str, &[u8])] = &[("Content-Length", b"0"), ("Connection", b"close")];
  assert!(
    c.send_response(200, b"OK", closing, BodyPlan::None, &mut out)
      .is_ok()
  );
  assert_eq!(c.transport(), Transport::Ending);
  assert!(!c.wants_read());
  // The request pipelined behind it is dead: §9.6 processes no further byte.
  let mut it2 = c.handle(two.get(BODILESS.len()..).unwrap());
  assert!(it2.next().unwrap().is_none());
  assert_eq!(it2.consumed(), 0);
}

// RFC 9112 §6.3 item 6: a counted body is exactly as long as the head said, so
// the countdown is the framing — an over-send would put octets of the next
// message inside this one (§11.1 response splitting).
#[test]
fn server_response_with_content_length_body() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"); // helper drains items
  let mut out = [0u8; 256];
  let n = c
    .send_response(
      200,
      b"OK",
      [("Content-Length", b"5".as_slice())].as_slice(),
      BodyPlan::ContentLength(5),
      &mut out,
    )
    .unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
  let m = c.send_body(b"hel", &mut out[n..]).unwrap();
  let k = c.send_body(b"lo", &mut out[n + m..]).unwrap();
  assert_eq!(&out[n..n + m + k], b"hello");
  assert_eq!(
    c.send_body(b"!", &mut out),
    Err(Error::InvalidState(OVER_SEND)),
    "RFC 9112 §6.3 item 6: an octet past the count is the next message's"
  );
  // …and the refusal wrote nothing: the head is still the head.
  assert_eq!(&out[..n], b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
  let f = c.finish_body(NO_TRAILERS, &mut out[n + m + k..]).unwrap();
  assert_eq!(f, 0);
  // re-armed: next pipelined request now consumable
  assert!(!c.is_awaiting_send());
  // Re-armed HERE, not on the next feed: a driver that asks what to do after
  // writing the last byte of a response must be told to read (the pump would
  // re-arm too, but only once it is given bytes it has no reason to ask for).
  assert!(c.wants_read());
  let mut it = c.handle(b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n");
  let Some(Item::Head { exchange, .. }) = it.next().unwrap() else {
    panic!("expected the next request's head")
  };
  assert_eq!(exchange.get(), 2);
}

// RFC 9112 §7.1 with §7.1.2: each write is one `chunk-size CRLF chunk-data
// CRLF`, and the body ends at the `last-chunk` plus the trailer section that
// closes it.
#[test]
fn server_chunked_response_with_trailers() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
  let mut out = [0u8; 256];
  let mut w = 0;
  w += c
    .send_response(
      200,
      b"OK",
      [("Transfer-Encoding", b"chunked".as_slice())].as_slice(),
      BodyPlan::Chunked,
      &mut out,
    )
    .unwrap();
  w += c.send_body(b"hi", &mut out[w..]).unwrap();
  let trailers: &[(&str, &[u8])] = &[("X-T", b"v")];
  w += c.finish_body(Some(trailers), &mut out[w..]).unwrap();
  assert!(
    core::str::from_utf8(&out[..w])
      .unwrap()
      .ends_with("2\r\nhi\r\n0\r\nX-T: v\r\n\r\n")
  );
  assert_eq!(
    &out[..w],
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-T: v\r\n\r\n"
  );
  assert!(!c.is_awaiting_send()); // both directions through: re-armed
  assert!(c.wants_read()); // …and ready for the next exchange without a feed
}

// RFC 9110 §6.5.1: "A sender MUST NOT generate a trailer field unless the sender
// knows the corresponding header field name's definition permits the field to be
// sent in trailers", and the same section says why: "Many fields cannot be
// processed outside the header section" — those describing "message framing,
// routing, authentication, request modifiers, response controls, or content
// format" among them.
//
// The four this core can decide on its own are refused here: a framing field in
// a trailer section would state a SECOND delimitation of a message already framed
// by the chunked coding (§11.2, self-inflicted), `Host` is routing evaluated
// before the content by definition, and `Trailer` announces the section so it
// cannot be one. The list is deliberately narrow — everything else is the
// caller's, with its syntax checked and nothing more.
#[test]
fn trailers_refuse_the_fields_that_frame_or_route() {
  /// A server with a chunked response under way and its body written.
  fn sending() -> (Connection<Server, General>, [u8; 128]) {
    let mut c = Connection::<Server, General>::new();
    feed_request(&mut c, BODILESS);
    let mut out = [0u8; 128];
    c.send_response(
      200,
      b"OK",
      [("Transfer-Encoding", b"chunked".as_slice())].as_slice(),
      BodyPlan::Chunked,
      &mut out,
    )
    .expect("a chunked response opens");
    (c, out)
  }

  // Case-insensitive, exactly as a field name comparison is (RFC 9110 §5.1).
  for banned in [
    &[("Content-Length", b"5".as_slice())] as &[(&str, &[u8])],
    &[("content-length", b"0")],
    &[("Transfer-Encoding", b"chunked")],
    &[("TRANSFER-ENCODING", b"gzip")],
    &[("Host", b"elsewhere")],
    &[("host", b"")],
    &[("Trailer", b"X-T")],
    // RFC 9110 §7.6.1: connection control is "only meaningful for a single
    // transport-level connection", and a trailer `Connection: close` would put
    // the closing signal on the wire while this end's state machine re-armed —
    // the peer reading a connection that is ending, the sender holding one it
    // means to reuse.
    &[("Connection", b"close")],
    &[("connection", b"keep-alive")],
    // §7.8: a switch is decided by the head, and §7.6.1 requires the field to be
    // named in `Connection`, which is itself refused above.
    &[("Upgrade", b"websocket")],
    // §10.1.1 with §6.5.1's own list: a request modifier exists to be evaluated
    // BEFORE the content, so one delivered after it is a contradiction.
    &[("Expect", b"100-continue")],
    // One banned name among benign ones still refuses the section.
    &[("X-Sum", b"ok"), ("Content-Length", b"0")],
    &[("X-Sum", b"ok"), ("Connection", b"close")],
  ] {
    let (mut c, _) = sending();
    let mut out = [0xAAu8; 128];
    assert_eq!(
      c.finish_body(Some(banned), &mut out),
      Err(Error::InvalidState(FORBIDDEN_TRAILER)),
      "{banned:?}"
    );
    // Refused before either encoder pass, so nothing reached the caller's slice
    // and NOTHING moved: the body is still open for a corrected section, and the
    // connection has not closed behind a trailer it declined to write.
    assert_eq!(out, [0xAAu8; 128], "{banned:?}");
    assert_eq!(
      c.poll_event(),
      None,
      "{banned:?}: the refusal moved the connection"
    );
    assert!(matches!(c.lifecycle, Lifecycle::Open), "{banned:?}");
    let n = c
      .finish_body(NO_TRAILERS, &mut out)
      .unwrap_or_else(|e| panic!("{banned:?}: the body could not be ended: {e:?}"));
    assert_eq!(&out[..n], b"0\r\n\r\n", "{banned:?}");
  }

  // `TE` is deliberately NOT in the set, and the boundary is asserted rather than
  // assumed: RFC 9110 §10.1.4's field is hop-by-hop, but this core never
  // generates or interprets it, so it has no decision a trailer `TE` could
  // contradict. It falls to §6.5.1's delegated remainder like any other name the
  // registry governs.
  let (mut c, _) = sending();
  let mut out = [0u8; 128];
  let te: &[(&str, &[u8])] = &[("TE", b"trailers")];
  let n = c
    .finish_body(Some(te), &mut out)
    .expect("a field this core never reads is the caller's to state");
  assert_eq!(out.get(..n), Some(b"0\r\nTE: trailers\r\n\r\n".as_slice()));

  // A benign trailer is written exactly as before: the set is a refusal over the
  // names this core itself interprets, not a whitelist.
  let (mut c, _) = sending();
  let mut out = [0u8; 128];
  let benign: &[(&str, &[u8])] = &[("X-Sum", b"ok"), ("X-Trace", b"1")];
  let n = c
    .finish_body(Some(benign), &mut out)
    .expect("an ordinary trailer field is the caller's to send");
  assert_eq!(
    out.get(..n),
    Some(b"0\r\nX-Sum: ok\r\nX-Trace: 1\r\n\r\n".as_slice())
  );
}

// RFC 9112 §6.3 item 8 with §9.3: a response carrying NO framing field is
// delimited by the connection closing, and §9.3 states the rule: "In order to
// remain persistent, all messages on a connection need to have a self-defined
// message length" — so such a response is the last one, whether or not the peer
// also spelled `Connection: close`.
//
// The notice has to reach the driver at the HEAD, which is where the commitment
// is made: a driver told only by the EOF would already have decided whether to
// plan a second request on the connection. The send side announces exactly this
// for an outbound `BodyPlan::CloseDelimited`; this is the receive half.
#[test]
fn an_inbound_close_delimited_response_signals_the_end_of_keep_alive() {
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  // HTTP/1.1, and no `Connection: close`: the ABSENCE of both framing fields is
  // the whole declaration (item 8 is the list's "otherwise").
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nbody");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  }
  assert_eq!(c.transport(), Transport::Ending);
  // Exactly once, like every other close signal (a peer's option, a local
  // `close()`): the driver is told the fact, not each of its causes.
  assert_eq!(c.poll_event(), None);

  // A counted response on an otherwise identical connection signals nothing —
  // which is what says the notice above came from item 8 and not from the head
  // merely having arrived.
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody");
    while it.next().unwrap().is_some() {}
  }
  assert_eq!(c.poll_event(), None);
}

// gate-exempt: split_robustness::byte_at_a_time_head_parse_stays_linear — names a wall-clock probe in `http1-proto/tests/split_robustness.rs`, a
// SEPARATE integration-test compilation unit this check does not scan; this test pins the field-level invariant that probe depends on.
// The head-scan watermark is progress through ONE head, so it may never go
// BACKWARDS within that head — and an offer SHORTER than the last one is the way
// it could. A driver that calls `handle` with an empty slice (a zero-byte read,
// a wakeup that carried nothing) or re-offers a prefix must not make the next
// scan restart over bytes already looked at, since a restart per offer is
// exactly the quadratic behaviour the watermark exists to prevent.
//
// Asserted on the FIELD, because a clobber changes no answer this core gives —
// the terminator is found either way, only later. Its wall-clock consequence is
// `split_robustness::byte_at_a_time_head_parse_stays_linear`; this is the
// invariant that probe measures, stated where it can be read directly.
#[test]
fn a_shorter_offer_does_not_rewind_the_head_watermark() {
  const PARTIAL: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n";
  const PARTIAL_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";

  // Server: the §3 request-line path.
  let mut c = Connection::<Server, General>::new();
  {
    let mut it = c.handle(PARTIAL);
    assert!(it.next().unwrap().is_none());
  }
  assert_eq!(c.watermark, PARTIAL.len());
  {
    let mut it = c.handle(b"");
    assert!(it.next().unwrap().is_none());
  }
  assert_eq!(
    c.watermark,
    PARTIAL.len(),
    "an empty offer rewound the scan"
  );
  // The head still completes, and the watermark goes back to zero with it: it
  // belongs to ONE head.
  {
    let mut it = c.handle(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  }
  assert_eq!(c.watermark, 0);

  // Client: the §4 status-line path keeps its own assignment.
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  {
    let mut it = c.handle(PARTIAL_RESPONSE);
    assert!(it.next().unwrap().is_none());
  }
  assert_eq!(c.watermark, PARTIAL_RESPONSE.len());
  {
    let mut it = c.handle(b"");
    assert!(it.next().unwrap().is_none());
  }
  assert_eq!(
    c.watermark,
    PARTIAL_RESPONSE.len(),
    "an empty offer rewound the scan"
  );

  // Tunnel: the third assignment site, which shares the same field.
  let mut c = Connection::<Client, Tunnel>::new();
  let mut out = [0u8; 128];
  c.open_upgrade(
    &Target::Origin {
      path_and_query: "/",
    },
    [
      ("Host", b"h".as_slice()),
      ("Connection", b"Upgrade"),
      ("Upgrade", b"websocket"),
    ]
    .as_slice(),
    &mut out,
  )
  .expect("the offer encodes");
  assert!(matches!(
    c.handle_response(PARTIAL_RESPONSE),
    Ok(ClientTunnelOutcome::NeedMore)
  ));
  assert_eq!(c.watermark, PARTIAL_RESPONSE.len());
  assert!(matches!(
    c.handle_response(b""),
    Ok(ClientTunnelOutcome::NeedMore)
  ));
  assert_eq!(
    c.watermark,
    PARTIAL_RESPONSE.len(),
    "an empty offer rewound the tunnel scan"
  );
}

// RFC 9112 §9.2 with §2.2: an idle client discards the stray empty lines a
// server may trail its last response with, and the allowance is BOUNDED —
// unbounded it is a free keep-alive channel for a peer that never answers.
//
// The bound has to be CUMULATIVE across offers, which the server's is for free:
// its leading empty lines are never consumed, so the region they sit in keeps
// growing and one scan of it sees them all. These are DISCARDED, so a per-offer
// count would reset with every read and a peer dribbling one pair at a time
// would never hit the limit at all.
#[test]
fn idle_crlf_discards_are_bounded_across_offers() {
  let mut c = Connection::<Client, General>::new();
  // One pair per offer, which is the shape a per-offer bound cannot see.
  for pair in 0..MAX_LEADING_EMPTY_LINES {
    let mut it = c.handle(b"\r\n");
    assert!(it.next().unwrap().is_none(), "pair {pair}");
    assert_eq!(it.consumed(), 2, "pair {pair}");
  }
  // One past the allowance, and the connection says so rather than accepting
  // another.
  let mut it = c.handle(b"\r\n");
  let error = it.next().expect_err("the allowance is bounded in total");
  assert_eq!(error.suggested_status(), Some(SuggestedStatus::BadRequest));

  // The allowance is per IDLE PERIOD, not per connection: a request resets it,
  // because what it bounds is how long a peer may keep a connection with nothing
  // outstanding alive on empty lines alone.
  let mut c = Connection::<Client, General>::new();
  for _ in 0..MAX_LEADING_EMPTY_LINES {
    let mut it = c.handle(b"\r\n");
    assert!(it.next().unwrap().is_none());
  }
  open_bodiless_request(&mut c, "GET");
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    while it.next().unwrap().is_some() {}
  }
  // Idle again, with the tally cleared: the same run of pairs is tolerated.
  for pair in 0..MAX_LEADING_EMPTY_LINES {
    let mut it = c.handle(b"\r\n");
    assert!(it.next().unwrap().is_none(), "second period, pair {pair}");
  }
}

// RFC 9110 §15.2.1 (any number of interim responses may precede the final one)
// with §10.1.1 (`Expect: 100-continue` is what usually asks for one): an interim
// leaves the exchange exactly where it was, and the final response is what ends
// it. And a 101 is never sendable in General mode.
#[test]
fn interim_then_final_response() {
  let mut c = Connection::<Server, General>::new();
  feed_request(
    &mut c,
    b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nExpect: 100-continue\r\n\r\n",
  );
  let mut out = [0u8; 128];
  let empty: &[(&str, &[u8])] = &[];
  let n = c.send_interim(100, empty, &mut out).unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 100 \r\n\r\n");
  // Still owed: an interim response is not the answer to the request.
  assert!(c.is_awaiting_send());
  assert!(
    c.send_response(
      200,
      b"",
      [("Content-Length", b"0".as_slice())].as_slice(),
      BodyPlan::None,
      &mut out
    )
    .is_ok()
  );
  assert!(c.send_interim(100, empty, &mut out).is_err()); // after final → InvalidState

  // A 101 is never sendable in General mode.
  let mut c2 = Connection::<Server, General>::new();
  feed_request(&mut c2, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
  assert!(c2.send_interim(101, empty, &mut out).is_err());
  assert!(
    c2.send_response(101, b"", empty, BodyPlan::None, &mut out)
      .is_err()
  );
  // …and neither refusal spent the response the request is still owed.
  assert!(c2.is_awaiting_send());
}

// RFC 9112 §6.3 item 1: a response to HEAD is terminated by the empty line that
// ends its head "regardless of the header fields present in the message", so the
// fields may describe a body that is never written — and writing one anyway
// would be octets the peer reads as the next response (§11.1).
#[test]
fn head_request_gets_bodiless_response() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, b"HEAD / HTTP/1.1\r\nHost: h\r\n\r\n");
  let mut out = [0u8; 128];
  // CL header allowed, but BodyPlan must be None for HEAD → anything else InvalidState.
  assert!(
    c.send_response(
      200,
      b"",
      [("Content-Length", b"5".as_slice())].as_slice(),
      BodyPlan::ContentLength(5),
      &mut out
    )
    .is_err()
  );
  assert!(
    c.send_response(
      200,
      b"",
      [("Content-Length", b"5".as_slice())].as_slice(),
      BodyPlan::None,
      &mut out
    )
    .is_ok()
  );
  // The head is the whole message: nothing may follow it.
  assert!(c.send_body(b"x", &mut out).is_err());
}

// RFC 9112 §9.3.2 (re-arm needs BOTH directions) with §9.6 (`close` ends
// keep-alive): a full exchange on a persistent connection re-arms and the next
// one takes the next id in order, while a request carrying the close option
// finishes and then drains.
#[test]
fn keep_alive_rearms_and_close_drains() {
  let mut c = Connection::<Server, General>::new();
  let mut out = [0u8; 128];
  let two =
    b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n";

  // The first exchange parses whole; the second waits, unconsumed (§9.3.2).
  let mut it = c.handle(two);
  let Some(Item::Head {
    exchange: first, ..
  }) = it.next().unwrap()
  else {
    panic!("expected the first request's head")
  };
  // Ids are minted by the connection and start at 1; zero is never one it minted.
  assert_eq!(first.get(), 1);
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
  assert!(it.next().unwrap().is_none());
  let held = it.consumed();
  assert_eq!(held, BODILESS.len());
  assert!(c.is_awaiting_send());
  assert!(!c.wants_read());

  // Answering it re-arms the connection, and only then.
  let n = c
    .send_response(204, b"No Content", NO_FIELDS, BodyPlan::None, &mut out)
    .unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 204 No Content\r\n\r\n");
  assert!(!c.is_awaiting_send());
  assert!(c.wants_read());

  // The held bytes are the next exchange, and its id is the next in order.
  let mut it2 = c.handle(two.get(held..).unwrap());
  let Some(Item::Head {
    exchange: second, ..
  }) = it2.next().unwrap()
  else {
    panic!("expected the second request's head")
  };
  assert_eq!(second.get(), 2);
  assert!(second > first);
  assert!(matches!(
    it2.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
  assert_eq!(it2.consumed(), two.len().saturating_sub(held));

  // The peer's close option is a connection-scoped fact, drained as an event…
  assert_eq!(c.transport(), Transport::Ending);
  assert_eq!(c.poll_event(), None);
  // …and the exchange in flight still gets its response (§9.6).
  let n = c
    .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
    .unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

  // After it, nothing more begins: no third exchange, no further byte read, and
  // no further response to send.
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  let mut it3 = c.handle(b"GET /c HTTP/1.1\r\nHost: h\r\n\r\n");
  assert!(it3.next().unwrap().is_none());
  assert_eq!(it3.consumed(), 0);
  assert!(
    c.send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
      .is_err()
  );
}

// RFC 9112 §6.3 items 3-8 with §11.1: the framing fields the caller writes and
// the body this core then frames must state the same message, or the peer
// delimits it somewhere the sender did not — response splitting, self-inflicted.
// The plan says what will be written; the fields are what the peer reads.
#[test]
fn declared_framing_must_match_the_body_plan() {
  let mut out = [0u8; 256];
  let cl5: &[(&str, &[u8])] = &[("Content-Length", b"5")];
  let chunked: &[(&str, &[u8])] = &[("Transfer-Encoding", b"chunked")];
  let both: &[(&str, &[u8])] = &[("Content-Length", b"5"), ("Transfer-Encoding", b"chunked")];

  // WHICH refusal, not merely that one happened: every row here is an
  // `InvalidState`, so a row that started failing for a NEIGHBOURING rule would
  // keep passing while proving nothing it names.
  for (headers, plan, why) in [
    // A length that is not the plan's.
    (cl5, BodyPlan::ContentLength(4), LENGTH_DISAGREES),
    // §6.3 item 3 with §6.2: the two fields disagree.
    (both, BodyPlan::Chunked, BOTH_FRAMINGS),
    // Counted, but nothing says so — item 8 would frame it by the close.
    (NO_FIELDS, BodyPlan::ContentLength(5), UNFRAMED_RESPONSE),
    // Item 8 again, meant this time but not stated: a bodiless RESPONSE with no
    // framing field at all is close-delimited, which is what
    // `BodyPlan::CloseDelimited` says deliberately.
    (NO_FIELDS, BodyPlan::None, UNFRAMED_RESPONSE),
    (chunked, BodyPlan::ContentLength(5), TE_WITHOUT_CHUNKED),
    // Five octets announced, none written.
    (cl5, BodyPlan::None, LENGTH_DISAGREES),
    // ── item 8's own rows, which this table was missing ──────────────────
    // Item 8 is the list's "otherwise", so the ABSENCE of both fields is the
    // declaration: either field beside a close-delimited body would have the
    // peer ending the message at a count this core never writes down to, or by
    // a coding it is not applying.
    (cl5, BodyPlan::CloseDelimited, CLOSE_DELIMITED_IS_UNFRAMED),
    (
      chunked,
      BodyPlan::CloseDelimited,
      CLOSE_DELIMITED_IS_UNFRAMED,
    ),
    (both, BodyPlan::CloseDelimited, CLOSE_DELIMITED_IS_UNFRAMED),
    (
      LENGTH_0,
      BodyPlan::CloseDelimited,
      CLOSE_DELIMITED_IS_UNFRAMED,
    ),
    // …and the chunked plan's own two, which the CHUNKED constants exist for.
    (NO_FIELDS, BodyPlan::Chunked, CHUNKED_UNANNOUNCED),
    (
      [("Transfer-Encoding", b"gzip, chunked".as_slice())].as_slice(),
      BodyPlan::Chunked,
      CHUNKED_DECLARATION,
    ),
  ] {
    let mut c = Connection::<Server, General>::new();
    feed_request(&mut c, BODILESS);
    assert_eq!(
      c.send_response(200, b"OK", headers, plan, &mut out),
      Err(Error::InvalidState(why)),
      "{plan:?}"
    );
    // A refused head leaves the response owed, exactly as before the call.
    assert!(c.is_awaiting_send(), "{plan:?}");
  }

  for (headers, plan) in [
    (LENGTH_0, BodyPlan::None),
    (cl5, BodyPlan::ContentLength(5)),
    (chunked, BodyPlan::Chunked),
    // Item 8 stated deliberately: NEITHER field, which is what declares it.
    (NO_FIELDS, BodyPlan::CloseDelimited),
  ] {
    let mut c = Connection::<Server, General>::new();
    feed_request(&mut c, BODILESS);
    assert!(
      c.send_response(200, b"OK", headers, plan, &mut out).is_ok(),
      "{plan:?}"
    );
  }

  // A REQUEST is never close-delimited (§6.3 item 7 and the note under item 8),
  // so a bodiless one needs no framing field at all — but a counted one does, or
  // the server reads no body and the octets behind the head become the next
  // request (§11.2 smuggling).
  let mut c = Connection::<Client, General>::new();
  assert_eq!(
    c.open_request("POST", &ORIGIN, HOST, BodyPlan::ContentLength(3), &mut out),
    Err(Error::InvalidState(UNFRAMED_RESPONSE))
  );
  assert_eq!(
    c.open_request("POST", &ORIGIN, HOST, BodyPlan::CloseDelimited, &mut out),
    Err(Error::InvalidState(REQUEST_IS_NEVER_CLOSE_DELIMITED))
  );
  assert!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_ok()
  );
}

// RFC 9112 §6.1 and RFC 9110 §8.6 name the same two statuses from the two
// framing fields' sides: a server MUST NOT send `Transfer-Encoding` in a 1xx or
// a 204, and MUST NOT send `Content-Length` in one either. RFC 9110 §15.2 gives
// an interim response no body to frame at all.
#[test]
fn bodiless_statuses_refuse_framing_fields() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let mut out = [0u8; 128];
  let chunked: &[(&str, &[u8])] = &[("Transfer-Encoding", b"chunked")];
  assert_eq!(
    c.send_interim(100, chunked, &mut out),
    Err(Error::InvalidState(BODILESS_STATUS_FRAMING))
  );
  assert!(
    c.send_response(204, b"", chunked, BodyPlan::None, &mut out)
      .is_err()
  );
  // RFC 9110 §8.6's half, and `Content-Length: 0` is not an exemption: the field
  // is forbidden there whatever it says, because item 1 already framed the
  // message and a recipient that read the field instead would frame it twice.
  assert_eq!(
    c.send_interim(100, LENGTH_0, &mut out),
    Err(Error::InvalidState(BODILESS_STATUS_FRAMING))
  );
  assert!(
    c.send_response(204, b"", LENGTH_0, BodyPlan::None, &mut out)
      .is_err()
  );
  // 304 is bodiless by the same item 1, but neither MUST NOT names it — a cache
  // validator may echo the fields of the representation. One accepted response
  // per connection, so the second shape gets its own.
  assert!(
    c.send_response(304, b"", chunked, BodyPlan::None, &mut out)
      .is_ok()
  );
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  assert!(
    c.send_response(304, b"", LENGTH_0, BodyPlan::None, &mut out)
      .is_ok()
  );
}

// RFC 9112 §6.2's sender MUST NOT is UNCONDITIONAL: "A sender MUST NOT send a
// Content-Length header field in any message that contains a Transfer-Encoding
// header field". RFC 9110 §8.6 spells the field `1*DIGIT`. Neither rule is
// suspended by §6.3 item 1: that item tells a RECIPIENT to ignore the fields of
// a bodiless response, which is not a licence for the SENDER to write anything
// into them. A pair of them on the wire is the §11.2 primitive whatever this end
// meant by it, and a length no recipient can read is one two recipients may read
// differently.
//
// What stays legal is item 1's own case, and it is asserted here so the rule
// above cannot be tightened into refusing it: a SINGLE well-formed
// `Content-Length` on a HEAD response or a 304, describing the body a GET would
// have received.
#[test]
fn a_bodiless_response_obeys_the_sender_framing_rules() {
  const BOTH: &[(&str, &[u8])] = &[("Content-Length", b"5"), ("Transfer-Encoding", b"chunked")];
  const DISAGREEING_LIST: &[(&str, &[u8])] = &[("Content-Length", b"3, 4")];
  const NOT_DIGITS: &[(&str, &[u8])] = &[("Content-Length", b"abc")];
  const COUNTED: &[(&str, &[u8])] = &[("Content-Length", b"5")];

  // A HEAD response: bodiless by item 1 whatever its fields say.
  for (fields, refusal) in [
    (BOTH, BOTH_FRAMINGS),
    // RFC 9110 §8.6 admits ONE value, so a list of them — agreeing or not — is
    // refused by the sender rule before the recipient's item-5 exception is
    // reached. That exception exists so a RECIPIENT handed `42, 42` can still
    // frame the message; a sender has no such excuse.
    (DISAGREEING_LIST, LENGTH_IS_ONE_VALUE),
    (NOT_DIGITS, LENGTH_IS_ONE_VALUE),
  ] {
    let mut c = Connection::<Server, General>::new();
    feed_request(&mut c, b"HEAD / HTTP/1.1\r\nHost: h\r\n\r\n");
    let mut out = [0xAAu8; 128];
    assert_eq!(
      c.send_response(200, b"OK", fields, BodyPlan::None, &mut out),
      Err(Error::InvalidState(refusal)),
      "{fields:?}"
    );
    assert_eq!(out, [0xAAu8; 128], "{fields:?}");
  }

  // A 304, which item 1 makes bodiless for a different reason and which neither
  // §6.1 nor §8.6 names — so the pair is refused there by §6.2 alone.
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let mut out = [0xAAu8; 128];
  assert_eq!(
    c.send_response(304, b"", BOTH, BodyPlan::None, &mut out),
    Err(Error::InvalidState(BOTH_FRAMINGS))
  );
  assert_eq!(out, [0xAAu8; 128]);

  // Item 1's legitimate case, both statuses: one well-formed length, describing
  // the representation rather than a body this message carries.
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, b"HEAD / HTTP/1.1\r\nHost: h\r\n\r\n");
  let n = c
    .send_response(200, b"OK", COUNTED, BodyPlan::None, &mut out)
    .expect("item 1 lets a HEAD response state the length a GET would have sent");
  assert_eq!(
    out.get(..n),
    Some(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".as_slice())
  );
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  assert!(
    c.send_response(304, b"", COUNTED, BodyPlan::None, &mut out)
      .is_ok()
  );
}

// The single error answer is the answer to a message this connection COULD NOT
// FRAME, so the whole 2xx class is refused: a phase whose whole meaning is "a
// rejection is owed" has no success class to state. The same rule Tunnel's
// `reject` applies from `RejectionOwed`, in the same words.
//
// A 3xx is NOT refused — a redirect is a valid way to refuse the request as it
// was put — and neither is a status outside the registry, which RFC 9112 §4
// makes a bare three-digit this core does not police.
#[test]
fn the_single_error_response_states_no_success() {
  /// Fails a fresh server connection, leaving its one answer owed.
  fn failed() -> Connection<Server, General> {
    let mut c = Connection::<Server, General>::new();
    {
      let mut it = c.handle(b"GET / HTTP/1.1\r\nHost : bad\r\n\r\n");
      assert!(it.next().is_err());
    }
    assert!(c.is_awaiting_send());
    c
  }

  for code in [200u16, 201, 204, 299] {
    let mut c = failed();
    let mut out = [0xAAu8; 128];
    assert_eq!(
      c.send_error_response(code, b"", NO_FIELDS, &mut out),
      Err(Error::InvalidState(NO_SUCCESS_TO_STATE)),
      "{code}"
    );
    // The refusal writes nothing and does not SPEND the answer: the caller
    // retries with a status that is one.
    assert_eq!(out, [0xAAu8; 128], "{code}");
    assert!(c.is_awaiting_send(), "{code}");
    assert!(
      c.send_error_response(400, b"Bad Request", NO_FIELDS, &mut out)
        .is_ok(),
      "{code}"
    );
  }

  // A redirect refuses the request as it was put, so it goes out.
  let mut c = failed();
  let mut out = [0u8; 128];
  let n = c
    .send_error_response(308, b"Permanent Redirect", NO_FIELDS, &mut out)
    .expect("a 3xx is a rejection");
  assert_eq!(
    out.get(..n),
    Some(b"HTTP/1.1 308 Permanent Redirect\r\nConnection: close\r\n\r\n".as_slice())
  );

  // Unregistered but inside RFC 9110 §15's five classes: which 5xx a driver
  // sends is not this core's to police.
  let mut c = failed();
  assert!(
    c.send_error_response(599, b"", NO_FIELDS, &mut out).is_ok(),
    "an unregistered code within a real class is the driver's choice"
  );
  // Outside them, though, §15 says "values outside that range are invalid", and
  // a sender chooses its own number.
  let mut c = failed();
  assert!(matches!(
    c.send_error_response(999, b"", NO_FIELDS, &mut out),
    Err(Error::InvalidState(_))
  ));
}

// RFC 9112 §2.1 with §11.1: a message is written whole or not at all, so a
// destination too small to take one leaves both the buffer and the exchange
// exactly where they were — there is no half-sent head to unsend.
#[test]
fn a_short_buffer_leaves_the_send_state_untouched() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let mut tiny = [0xAAu8; 8];
  let Err(Error::BufferTooSmall { need, have: 8 }) =
    c.send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut tiny)
  else {
    panic!("expected the exact need")
  };
  assert_eq!(need, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".len());
  assert_eq!(tiny, [0xAAu8; 8]);
  // Still owed: nothing was written, so the exchange has not moved.
  assert!(c.is_awaiting_send());
  send_bodiless_response(&mut c);
  assert!(!c.is_awaiting_send());
}

// RFC 9112 §7.1: a chunk is its size line, its octets, and the CRLF that closes
// it — one indivisible piece of framing. A buffer that fits only part of it must
// take none of it, or the body ends where the sender did not say it did.
#[test]
fn a_partly_fitting_chunk_is_not_written() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let mut out = [0u8; 128];
  let chunked: &[(&str, &[u8])] = &[("Transfer-Encoding", b"chunked")];
  let n = c
    .send_response(200, b"OK", chunked, BodyPlan::Chunked, &mut out)
    .unwrap();

  // `4\r\ndata\r\n` is nine bytes; eight is one short.
  let mut short = [0xAAu8; 8];
  let Err(Error::BufferTooSmall { need: 9, have: 8 }) = c.send_body(b"data", &mut short) else {
    panic!("expected the exact need")
  };
  assert_eq!(short, [0xAAu8; 8]);

  // The body is untouched by the refusal: the same write fits and goes out.
  let m = c.send_body(b"data", &mut out[n..]).unwrap();
  assert_eq!(&out[n..n + m], b"4\r\ndata\r\n");
  let f = c.finish_body(NO_TRAILERS, &mut out[n + m..]).unwrap();
  assert_eq!(&out[n + m..n + m + f], b"0\r\n\r\n");
}

// RFC 9112 §6.3 item 7: a message framed with no body has none, so an octet
// offered for one belongs to no message this connection is carrying.
#[test]
fn a_bodiless_plan_takes_no_body() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let mut out = [0u8; 128];
  // Nothing is in flight to write a body for until the head goes out — and
  // WHICH refusal says so, since a bare `is_err()` here would equally pass on a
  // failed connection, a drained one, or a framing complaint about a head that
  // was never sent.
  assert_eq!(
    c.send_body(b"x", &mut out),
    Err(Error::InvalidState(NO_BODY_IN_FLIGHT))
  );
  assert_eq!(
    c.finish_body(NO_TRAILERS, &mut out),
    Err(Error::InvalidState(NO_BODY_IN_FLIGHT))
  );
  assert!(
    c.send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
      .is_ok()
  );
  // …and the head WAS the message, so the same rule answers afterwards.
  assert_eq!(
    c.send_body(b"x", &mut out),
    Err(Error::InvalidState(NO_BODY_IN_FLIGHT))
  );
  assert_eq!(
    c.finish_body(NO_TRAILERS, &mut out),
    Err(Error::InvalidState(NO_BODY_IN_FLIGHT))
  );
}

// RFC 9112 §6.3 item 6 with §7.1.2: a counted body ends when its count does —
// not before, and a trailer section belongs to the chunked coding alone.
#[test]
fn a_counted_body_finishes_only_when_it_is_complete() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let mut out = [0u8; 128];
  let cl5: &[(&str, &[u8])] = &[("Content-Length", b"5")];
  let n = c
    .send_response(200, b"OK", cl5, BodyPlan::ContentLength(5), &mut out)
    .unwrap();
  let m = c.send_body(b"hel", &mut out[n..]).unwrap();
  // Two octets still owed: finishing here would truncate the message. WHICH
  // refusal is the point — a bare `is_err()` would pass equally on the trailer
  // rule two lines down, and the two say different things to a caller.
  assert_eq!(
    c.finish_body(NO_TRAILERS, &mut out[n + m..]),
    Err(Error::InvalidState(BODY_INCOMPLETE))
  );
  assert!(c.is_awaiting_send());
  // …and one octet PAST the count is the other half of item 6: those bytes are
  // the next message's as far as the peer is concerned (§11.1).
  assert_eq!(
    c.send_body(b"lol", &mut out[n + m..]),
    Err(Error::InvalidState(OVER_SEND))
  );
  let k = c.send_body(b"lo", &mut out[n + m..]).unwrap();
  // §7.1.2 gives a trailer section to a chunked body only.
  let trailers: &[(&str, &[u8])] = &[("X-T", b"v")];
  assert_eq!(
    c.finish_body(Some(trailers), &mut out[n + m + k..]),
    Err(Error::InvalidState(UNCHUNKED_HAS_NO_TRAILERS))
  );
  assert!(c.finish_body(NO_TRAILERS, &mut out[n + m + k..]).is_ok());
  assert!(!c.is_awaiting_send());
}

// RFC 9112 §7.1 `chunk-size = 1*HEXDIG` with `last-chunk = 1*("0")`: a zero-size
// chunk header IS the last chunk, so an empty write frames nothing rather than
// ending the body early (§11.2, self-inflicted).
#[test]
fn an_empty_write_frames_nothing() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let mut out = [0u8; 128];
  let chunked: &[(&str, &[u8])] = &[("Transfer-Encoding", b"chunked")];
  let n = c
    .send_response(200, b"OK", chunked, BodyPlan::Chunked, &mut out)
    .unwrap();
  assert_eq!(c.send_body(b"", &mut out[n..]).unwrap(), 0);
  let f = c.finish_body(NO_TRAILERS, &mut out[n..]).unwrap();
  assert_eq!(&out[n..n + f], b"0\r\n\r\n");
}

// RFC 9112 §9.6: a local close ends keep-alive, and the exchange in flight still
// finishes — its response goes out and the connection drains behind it.
#[test]
fn a_local_close_lets_the_exchange_in_flight_finish() {
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  c.close();
  assert_eq!(c.transport(), Transport::Ending);
  assert!(c.is_awaiting_send()); // the response is still owed
  let mut out = [0u8; 128];
  assert!(
    c.send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
      .is_ok()
  );
  assert!(!c.is_awaiting_send());
  assert!(!c.wants_read());
  // Drained: no further exchange, in either direction.
  assert!(
    c.send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
      .is_err()
  );
}

// RFC 9112 §9.3: a recipient decides persistence from "the protocol version and
// Connection header field (Section 7.6.1 of [HTTP]) in the most recently
// received message" — and with HTTP/1.0 and no `keep-alive` option the decision
// list ends where every other branch does: "The connection will close after the
// current response". So the exchange finishes and the connection does not re-arm
// behind it.
#[test]
fn an_http_10_request_ends_the_connection_after_its_response() {
  const FIRST: usize = b"GET /a HTTP/1.0\r\nHost: h\r\n\r\n".len();
  let two = b"GET /a HTTP/1.0\r\nHost: h\r\n\r\nGET /b HTTP/1.0\r\nHost: h\r\n\r\n";

  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(two);
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
  assert!(it.next().unwrap().is_none());
  // Only the first request's bytes: the second waits on the response (§9.3.2),
  // and once that response is out it is dead rather than merely waiting.
  assert_eq!(it.consumed(), FIRST);
  // The version IS the directive here — no field said so — and it reaches the
  // driver as the same level a stated `close` option produces.
  assert_eq!(c.transport(), Transport::Ending);

  // §9.6: the exchange in flight still gets its answer…
  send_bodiless_response(&mut c);
  // …and nothing follows it: no re-arm, no further byte, no further response.
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  let mut it2 = c.handle(two.get(FIRST..).unwrap());
  assert!(it2.next().unwrap().is_none());
  assert_eq!(it2.consumed(), 0);
  let mut out = [0u8; 64];
  assert!(matches!(
    c.send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out),
    Err(Error::InvalidState(_))
  ));
}

// RFC 9112 §9.3's third bullet: an HTTP/1.0 message that carries the
// `keep-alive` connection option (RFC 9110 §7.6.1) asks the connection to
// persist, and a recipient that "wishes to honor the HTTP/1.0 keep-alive
// mechanism" re-arms exactly as it does for 1.1.
#[test]
fn an_http_10_request_with_keep_alive_re_arms() {
  const KEPT: &[u8] = b"GET /a HTTP/1.0\r\nHost: h\r\nConnection: keep-alive\r\n\r\n";
  let two = b"GET /a HTTP/1.0\r\nHost: h\r\nConnection: keep-alive\r\n\r\nGET /b HTTP/1.0\r\nHost: h\r\nConnection: keep-alive\r\n\r\n";
  assert!(two.starts_with(KEPT));

  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(two);
  while it.next().unwrap().is_some() {}
  assert_eq!(it.consumed(), KEPT.len());
  // Nothing was signalled: keep-alive holds, so there is no close to announce.
  assert_eq!(c.poll_event(), None);

  send_bodiless_response(&mut c);
  assert!(c.wants_read());
  let mut it2 = c.handle(two.get(KEPT.len()..).unwrap());
  let Some(Item::Head { exchange, .. }) = it2.next().unwrap() else {
    panic!("expected the second request's head")
  };
  assert_eq!(exchange.get(), 2);
}

// RFC 9112 §6.1: "A server MUST NOT send a response containing Transfer-Encoding
// unless the corresponding request indicates HTTP/1.1 (or later minor
// revisions)" — the coding postdates 1.0, and a peer that does not implement it
// reads the chunk framing as content. The MUST NOT is about the FIELD, so it
// holds even where §6.3 item 1 makes the recipient ignore it.
#[test]
fn a_chunked_response_is_refused_to_an_http_10_peer() {
  const TEN: &[u8] = b"GET / HTTP/1.0\r\nHost: h\r\nConnection: keep-alive\r\n\r\n";
  let mut out = [0u8; 128];
  let chunked: &[(&str, &[u8])] = &[("Transfer-Encoding", b"chunked")];

  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, TEN);
  assert_eq!(
    c.send_response(200, b"OK", chunked, BodyPlan::Chunked, &mut out),
    Err(Error::InvalidState(TE_NEEDS_HTTP_11))
  );
  // A 304's fields describe a representation the recipient ignores (item 1), and
  // §6.1's MUST NOT still refuses the field.
  assert_eq!(
    c.send_response(304, b"", chunked, BodyPlan::None, &mut out),
    Err(Error::InvalidState(TE_NEEDS_HTTP_11))
  );
  // Refused before a byte is written, and the response is still owed.
  assert_eq!(out, [0u8; 128]);
  assert!(c.is_awaiting_send());

  // What a 1.0 peer CAN be answered with: §6.3 item 6's counted body…
  let n = c
    .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
    .unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  // …or item 8's close-delimited one, the feature that "exists primarily for
  // backwards compatibility with HTTP/1.0".
  let mut c2 = Connection::<Server, General>::new();
  feed_request(&mut c2, TEN);
  assert!(
    c2.send_response(200, b"OK", NO_FIELDS, BodyPlan::CloseDelimited, &mut out)
      .is_ok()
  );
}

// RFC 9112 §6.3 item 8: a response with no declared length has a body of "the
// number of octets received prior to the server closing the connection", so the
// octets keep coming until EOF and the EOF is what completes the exchange. §9.3
// makes such a response the last one on the connection.
#[test]
fn a_client_reads_an_http_10_response_to_the_close() {
  const HEAD_AND_START: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nhel";
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");

  let mut it = c.handle(HEAD_AND_START);
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::Head { interim: false, .. })
  ));
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::BodyChunk { data: b"hel", .. })
  ));
  assert!(it.next().unwrap().is_none());
  assert_eq!(it.consumed(), HEAD_AND_START.len());
  // §9.3: a 1.0 response without `keep-alive` is the last on the connection…
  assert_eq!(c.transport(), Transport::Ending);
  // …and yet its own body goes on: keep-alive being over does not end a message.
  assert!(c.wants_read());
  let mut it2 = c.handle(b"lo");
  assert!(matches!(
    it2.next().unwrap(),
    Some(Item::BodyChunk { data: b"lo", .. })
  ));
  assert!(it2.next().unwrap().is_none());

  // The close is the delimiter: an intact head plus EOF is a COMPLETE message —
  // concluded on the re-offer that runs out, since that is where the absence of
  // further octets is provable.
  assert!(matches!(c.handle_eof(), Ok(None)));
  {
    let mut it = c.handle(b"");
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
  }
  assert!(!c.wants_read());
  let mut out = [0u8; 64];
  assert!(matches!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out),
    Err(Error::InvalidState(_))
  ));
}

// RFC 9112 §9.6: a local close stops the connection at the point it would
// otherwise re-arm (§9.3.2), so a request already pipelined behind a FINISHED
// exchange never becomes one — the close is taken between messages, where there
// is nothing left to finish.
#[test]
fn a_local_close_after_an_exchange_prevents_the_next_one() {
  let two = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(two);
  while it.next().unwrap().is_some() {}
  assert_eq!(it.consumed(), BODILESS.len());
  send_bodiless_response(&mut c);
  // Re-armed and open: the pipelined request would be the next exchange.
  assert!(c.wants_read());
  assert_eq!(c.poll_event(), None);

  c.close();
  assert_eq!(c.transport(), Transport::Ending);
  assert_eq!(c.poll_event(), None); // announced once
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  let mut it2 = c.handle(two.get(BODILESS.len()..).unwrap());
  assert!(it2.next().unwrap().is_none());
  assert_eq!(it2.consumed(), 0);
}

// RFC 9112 §9.3: a client "MAY send additional requests on a persistent
// connection until it sends or receives a close connection option", and §9.6's
// local close is this end sending one — so the next request never opens.
#[test]
fn a_local_close_refuses_the_next_client_request() {
  let mut c = Connection::<Client, General>::new();
  open_bodiless_request(&mut c, "GET");
  let mut it = c.handle(b"HTTP/1.1 204 \r\n\r\n");
  while it.next().unwrap().is_some() {}
  assert_eq!(c.poll_event(), None); // re-armed, and nothing announced

  c.close();
  assert_eq!(c.transport(), Transport::Ending);
  let mut out = [0u8; 64];
  assert!(matches!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out),
    Err(Error::InvalidState(_))
  ));
  assert_eq!(out, [0u8; 64]);
}

// RFC 9110 §15.2: "Since HTTP/1.0 did not define any 1xx status codes, a server
// MUST NOT send a 1xx response to an HTTP/1.0 client." Nothing in such a request
// can ask for one — §10.1.1's expectation is dropped from it — so what this
// refuses is the interim a driver sends on its own initiative.
#[test]
fn an_interim_response_is_refused_to_an_http_10_peer() {
  let mut c = Connection::<Server, General>::new();
  feed_request(
    &mut c,
    b"POST / HTTP/1.0\r\nHost: h\r\nContent-Length: 0\r\nExpect: 100-continue\r\n\r\n",
  );
  let mut out = [0u8; 128];
  assert_eq!(
    c.send_interim(100, NO_FIELDS, &mut out),
    Err(Error::InvalidState(INTERIM_NEEDS_HTTP_11))
  );
  assert_eq!(out, [0u8; 128]);
  // Refused, and the final response the request is owed is untouched.
  assert!(c.is_awaiting_send());
  let n = c
    .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
    .unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
}

// RFC 9110 §10.1.1: a server "MUST ignore" a 100-continue expectation received
// in an HTTP/1.0 request, so the ask never reaches the driver at all — the other
// half of why §15.2's interim response is never owed to such a peer.
#[test]
fn an_http_10_expectation_never_reaches_the_driver() {
  let mut c = Connection::<Server, General>::new();
  let mut it =
    c.handle(b"POST / HTTP/1.0\r\nHost: h\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\nhi");
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  // The 1.1 spelling of this request yields `Item::ExpectContinue` here.
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::BodyChunk { data: b"hi", .. })
  ));
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
}

// RFC 9112 §6.3 item 8: the body is "determined by the number of octets received
// prior to the server closing the connection", so the head declares nothing and
// the close is part of the framing. §9.3 makes that close mandatory rather than
// a policy choice: "In order to remain persistent, all messages on a connection
// need to have a self-defined message length".
#[test]
fn a_close_delimited_response_is_framed_by_the_close() {
  let two = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(two);
  while it.next().unwrap().is_some() {}
  assert_eq!(it.consumed(), BODILESS.len());
  assert_eq!(c.poll_event(), None); // a 1.1 exchange: nothing signalled yet

  let mut out = [0u8; 128];
  let ctype: &[(&str, &[u8])] = &[("Content-Type", b"text/plain")];
  let mut w = c
    .send_response(200, b"OK", ctype, BodyPlan::CloseDelimited, &mut out)
    .unwrap();
  // Neither framing field: the ABSENCE of both is what declares item 8.
  assert_eq!(
    &out[..w],
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
  );
  // The head implies the close, so the notice is due there — the driver has to
  // know before it writes the body that this connection is ending.
  assert_eq!(c.transport(), Transport::Ending);

  // Raw octets: no count to keep, and no chunk framing to add.
  w += c.send_body(b"hel", &mut out[w..]).unwrap();
  w += c.send_body(b"lo", &mut out[w..]).unwrap();
  assert_eq!(
    &out[..w],
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"
  );
  // Nothing on the wire ends the body — the close does — so finishing writes no
  // bytes and only ends the message here.
  assert_eq!(c.finish_body(NO_TRAILERS, &mut out[w..]).unwrap(), 0);
  assert!(out.get(w..).unwrap().iter().all(|&b| b == 0));

  // Drained: the request pipelined behind it never runs, and nothing more may be
  // written in either direction.
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  let mut it2 = c.handle(two.get(BODILESS.len()..).unwrap());
  assert!(it2.next().unwrap().is_none());
  assert_eq!(it2.consumed(), 0);
  assert!(matches!(
    c.send_body(b"x", &mut out[w..]),
    Err(Error::InvalidState(_))
  ));
  assert!(matches!(
    c.send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out[w..]),
    Err(Error::InvalidState(_))
  ));
  assert_eq!(c.poll_event(), None); // announced once
}

// RFC 9112 §6.3: item 8 is the list's "otherwise", so a close-delimited message
// is exactly the one whose head declares NOTHING. A `Content-Length` beside it
// would frame the body at a count this core is not writing to, and a
// `Transfer-Encoding` would frame it by a coding it is not applying — either way
// the peer ends the message somewhere the sender did not (§11.1).
#[test]
fn a_close_delimited_head_declares_no_framing_field() {
  let mut out = [0u8; 128];
  let cl5: &[(&str, &[u8])] = &[("Content-Length", b"5")];
  let chunked: &[(&str, &[u8])] = &[("Transfer-Encoding", b"chunked")];
  for headers in [LENGTH_0, cl5, chunked] {
    let mut c = Connection::<Server, General>::new();
    feed_request(&mut c, BODILESS);
    assert_eq!(
      c.send_response(200, b"OK", headers, BodyPlan::CloseDelimited, &mut out),
      Err(Error::InvalidState(CLOSE_DELIMITED_IS_UNFRAMED))
    );
    // Refused, and the response is still owed.
    assert!(c.is_awaiting_send());
  }
  assert_eq!(out, [0u8; 128]);

  // RFC 9112 §7.1.2 gives the trailer section to the chunked coding alone, so a
  // body that ends at the close has nowhere to put one.
  let mut c = Connection::<Server, General>::new();
  feed_request(&mut c, BODILESS);
  let n = c
    .send_response(200, b"OK", NO_FIELDS, BodyPlan::CloseDelimited, &mut out)
    .unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 200 OK\r\n\r\n");
  let trailers: &[(&str, &[u8])] = &[("X-T", b"v")];
  assert!(matches!(
    c.finish_body(Some(trailers), &mut out[n..]),
    Err(Error::InvalidState(_))
  ));
}

// RFC 9112 §6.3's note under item 8: "Request messages are never close-delimited
// because they are always explicitly framed by length or transfer coding, with
// the absence of both implying the request ends immediately after the header
// section." A close-delimited request would be a server waiting for a close that
// this end is waiting for a response before making.
#[test]
fn a_request_is_never_close_delimited() {
  let mut c = Connection::<Client, General>::new();
  let mut out = [0u8; 128];
  assert_eq!(
    c.open_request("POST", &ORIGIN, HOST, BodyPlan::CloseDelimited, &mut out),
    Err(Error::InvalidState(REQUEST_IS_NEVER_CLOSE_DELIMITED))
  );
  assert_eq!(out, [0u8; 128]);
  // The refusal opened no exchange: the next request is still this end's first.
  assert!(
    c.open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
      .is_ok()
  );
}

/// A server whose inbound bodies are bounded at `max` payload octets each,
/// built through the real construction path rather than by writing a field.
fn bounded_server(max: u64) -> Connection<Server, General> {
  Connection::<Server, General>::with_limits(
    Connection::<Server, General>::default_limits().with_max_body_bytes(max),
  )
}

/// Feeds `input`, pulls items until one of them is an error, and returns it.
#[track_caller]
fn drain_until_error(c: &mut Connection<Server, General>, input: &[u8]) -> Error {
  let mut it = c.handle(input);
  loop {
    match it.next() {
      Ok(Some(_)) => {}
      Ok(None) => panic!("the offer was exhausted without an error"),
      Err(error) => return error,
    }
  }
}

// THE RESOLUTION RULE, and the only test that catches the reading it exists to
// prevent. The chunk-framing budget is resolved from the payload ceiling IN
// FORCE, so raising only the payload knob carries the framing budget with it. A
// budget seeded from the ROLE DEFAULT would answer 65,536 here — and 100 MiB
// delivered at the commonest 4 KiB chunk granularity spends 153,600 octets of
// RFC 9112 §7.1 chunk-size lines, so ordinary chunked traffic would be refused
// about 42.7 MiB into a body this ceiling allows.
#[test]
fn raising_only_the_payload_ceiling_raises_the_framing_budget_with_it() {
  let limits = Connection::<Server, General>::default_limits().with_max_body_bytes(100 << 20);
  assert_eq!(limits.max_chunk_framing_bytes(), (100 << 20) >> 4);
}

// The other two halves of the same rule. The role default survives as a FLOOR,
// so narrowing the payload ceiling never leaves a body unable to state its own
// RFC 9112 §7.1 framing; and a STATED budget pins itself, which is part of the
// value rather than of its resolution — so equality compares what was stated,
// not what it resolves to.
#[test]
fn the_framing_budget_has_a_floor_and_records_what_was_stated() {
  let server = Connection::<Server, General>::default_limits();
  assert_eq!(server.max_body_bytes(), 1 << 20);
  assert_eq!(server.max_chunk_framing_bytes(), 1 << 16);
  // A sixteenth of nothing is nothing; the floor is what a body still gets.
  assert_eq!(
    server.with_max_body_bytes(0).max_chunk_framing_bytes(),
    1 << 16
  );
  // `u64::MAX >> 4` is 2^60, so "unbounded" stays ONE knob.
  assert_eq!(
    server
      .with_max_body_bytes(u64::MAX)
      .max_chunk_framing_bytes(),
    u64::MAX >> 4
  );
  // Stated, and therefore no longer tracking the payload ceiling.
  let stated = server.with_max_chunk_framing_bytes(1 << 16);
  assert_eq!(
    stated
      .with_max_body_bytes(100 << 20)
      .max_chunk_framing_bytes(),
    1 << 16
  );
  // Presence is part of the value, even where the two resolve identically.
  assert_ne!(server, stated);
  // The client's own seed, which is a different progression.
  let client = Connection::<Client, General>::default_limits();
  assert_eq!(client.max_body_bytes(), 64 << 20);
  assert_eq!(client.max_chunk_framing_bytes(), (64 << 20) >> 4);
  // A connection answers exactly what the limits it was built from resolve to.
  let c = Connection::<Server, General>::with_limits(stated);
  assert_eq!(c.max_body_bytes(), stated.max_body_bytes());
  assert_eq!(
    c.max_chunk_framing_bytes(),
    stated.max_chunk_framing_bytes()
  );
}

#[test]
fn opportunistic_upgrade_is_refused_unless_the_builder_allows_it() {
  type C = Connection<Client, General>;
  // The posture the README states: reject what an RFC leaves us free to
  // reject. RFC 9110 §7.8 leaves this free — it obliges a client to nothing.
  assert!(!C::default_limits().opportunistic_upgrade_allowed());
  assert!(
    C::default_limits()
      .allow_opportunistic_upgrade(true)
      .opportunistic_upgrade_allowed()
  );
  assert!(
    !C::default_limits()
      .allow_opportunistic_upgrade(false)
      .opportunistic_upgrade_allowed()
  );
  // Const-usable, like every other Limits builder, and it survives the
  // decomposition `with_limits` performs.
  const L: Limits =
    Connection::<Client, General>::default_limits().allow_opportunistic_upgrade(true);
  assert!(C::with_limits(L).opportunistic_upgrade_allowed_for_test());
}

// RFC 9112 §6.3 item 6 with RFC 9110 §15.5.14: a declaration past the ceiling
// is refused before an octet of content is read, and the refusal is POLICY —
// nothing on the wire broke a rule, so the connection is not failed and the
// server still owes its one answer. RFC 9112 §9.6's notice is given once.
#[test]
fn a_counted_body_over_the_limit_refuses_without_failing_the_connection() {
  let mut c = bounded_server(4);
  let error = drain_until_error(
    &mut c,
    b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
  );
  let Error::Refused(Refusal::BodyTooLarge { exchange, limit }) = error else {
    panic!("expected a policy refusal, got {error:?}")
  };
  // The LIMIT, not the observed size, which the peer chooses and may never end.
  assert_eq!(limit, 4);
  assert_eq!(exchange.get(), 1);
  // RFC 9110 §15.5.14 is what a server driver is advised to answer with.
  assert_eq!(
    error.suggested_status(),
    Some(SuggestedStatus::ContentTooLarge)
  );
  assert_eq!(SuggestedStatus::ContentTooLarge.code(), 413);
  assert_eq!(
    SuggestedStatus::ContentTooLarge.reason(),
    "Content Too Large"
  );
  // NOT the failed state: no violation was found and none was constructed.
  assert!(!matches!(c.lifecycle, Lifecycle::Failed));
  // The readiness split says "write, and only write".
  assert!(!c.wants_read());
  assert!(c.is_awaiting_send());
  assert_eq!(c.transport(), Transport::Ending);
  assert_eq!(c.poll_event(), None);
}

// RFC 9112 §7.1 declares no total, ever — a size line announces one chunk — so
// nothing about eleven one-octet chunks is refusable from the head and the
// bound has to be cumulative. Every octet the ceiling allowed is delivered
// first, and the eleventh chunk is refused with the ceiling named as the limit.
//
// gate-exempt: body::tests::a_later_chunk_overrunning_the_remainder_is_refused_at_its_size_line — names a DIFFERENT test, in `body`'s own test
// module, that pins the fact this paragraph cites; a test does not call another test.
// WHERE inside that chunk the refusal falls is not decidable from here, and this
// test does not claim it: the whole body rides in ONE offer, so a gate at the
// size line and the shell's charge on the data one call later reach a driver as
// the same error after the same ten octets. That the size LINE is what answers
// is `body::tests::a_later_chunk_overrunning_the_remainder_is_refused_at_its_size_line`,
// which feeds a line whose data has not arrived.
#[test]
fn a_chunked_body_over_the_limit_refuses_cumulatively() {
  const HEAD: &[u8] = b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
  // Eleven `1\r\na\r\n` chunks, spelled out so the fixture needs no allocation.
  const BODY: &[u8] = b"1\r\na\r\n1\r\na\r\n1\r\na\r\n1\r\na\r\n1\r\na\r\n1\r\na\r\n\
1\r\na\r\n1\r\na\r\n1\r\na\r\n1\r\na\r\n1\r\na\r\n";

  let mut c = bounded_server(10);
  {
    let mut it = c.handle(HEAD);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    assert_eq!(it.consumed(), HEAD.len());
  }
  let mut delivered = 0usize;
  let error = {
    let mut it = c.handle(BODY);
    loop {
      match it.next() {
        Ok(Some(Item::BodyChunk { data, .. })) => delivered = delivered.saturating_add(data.len()),
        Ok(Some(_)) => {}
        Ok(None) => panic!("the offer was exhausted without a refusal"),
        Err(error) => break error,
      }
    }
  };
  assert_eq!(
    delivered, 10,
    "every octet the ceiling allowed was handed over"
  );
  assert!(
    matches!(
      error,
      Error::Refused(Refusal::BodyTooLarge { limit: 10, .. })
    ),
    "{error:?}"
  );
  assert!(!matches!(c.lifecycle, Lifecycle::Failed));
}

// RFC 9112 §9.3: "A server MUST read the entire request message body or close
// the connection after sending its response" — the core has taken the close
// branch, so the one response still owed has to say so on the wire (RFC 9110
// §10.1.1's SHOULD). Driven from a CHUNKED body, so the refusal is the
// cumulative charge's rather than the declaration gate's.
#[test]
fn a_refused_server_still_owes_exactly_one_response_and_it_must_state_close() {
  const CLOSING_413: &[(&str, &[u8])] = &[("Content-Length", b"0"), ("Connection", b"close")];
  let mut c = bounded_server(4);
  let error = drain_until_error(
    &mut c,
    b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
  );
  assert!(matches!(error, Error::Refused(_)), "{error:?}");
  assert!(c.is_awaiting_send());

  let mut out = [0u8; 128];
  let without_close = c
    .send_response(
      413,
      b"Content Too Large",
      LENGTH_0,
      BodyPlan::None,
      &mut out,
    )
    .unwrap_err();
  assert!(
    matches!(without_close, Error::InvalidState(m) if m == REFUSED_BODY_NEEDS_CLOSE),
    "{without_close:?}"
  );
  // The refusal writes nothing and does not spend the one answer.
  assert_eq!(out, [0u8; 128]);

  let n = c
    .send_response(
      413,
      b"Content Too Large",
      CLOSING_413,
      BodyPlan::None,
      &mut out,
    )
    .unwrap();
  assert_eq!(
    out.get(..n),
    Some(
      b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        .as_slice()
    )
  );
  // EXACTLY one: RFC 9112 §9.6 drains the connection behind the response that
  // stated the option, so a second answer has nowhere to go.
  assert!(
    c.send_response(413, b"", CLOSING_413, BodyPlan::None, &mut out)
      .is_err()
  );
  assert!(!c.is_awaiting_send());
  assert!(!c.wants_read());
}

// RFC 9110 §10.1.1: the expectation asks "shall I send the content?" and this
// end has already answered no, so the ask is never surfaced and no `100
// (Continue)` can be written for it. The gate covers every 1xx, not only the
// invitation — a refused exchange owes one final answer and nothing else.
#[test]
fn a_refused_body_takes_no_interim() {
  let mut c = bounded_server(4);
  let error = {
    let mut it =
      c.handle(b"POST /x HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n");
    // The expectation is NOT surfaced: the only item this head yields is the
    // head, and the next pull is the refusal.
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    it.next().unwrap_err()
  };
  assert!(matches!(error, Error::Refused(_)), "{error:?}");

  let mut out = [0u8; 64];
  for code in [100u16, 103] {
    let refused = c.send_interim(code, NO_FIELDS, &mut out).unwrap_err();
    assert!(
      matches!(refused, Error::InvalidState(m) if m == REFUSED_BODY_TAKES_NO_INTERIM),
      "{code}: {refused:?}"
    );
  }
  assert_eq!(out, [0u8; 64]);
}

/// A server that has read a head whose `Content-Length` is past its ceiling and
/// has NOT pumped again — the driver shape the contiguous-handover recipe asks
/// for, which stops at `Item::Head` and drops the iterator.
///
/// The refusal exists here, but only inside the decoder: the pump step that
/// moves it onto the exchange has not run. Every send gate has to see it
/// anyway, which is the window a gate reading the exchange alone would miss.
fn head_refused_before_the_pump(request: &[u8]) -> Connection<Server, General> {
  let mut c = bounded_server(4);
  {
    let mut it = c.handle(request);
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    // Dropped WITHOUT a second pull: the refusal is unresolved by construction.
  }
  c
}

// WINDOW ONE, the interim gate. RFC 9110 §10.1.1 makes a `100 (Continue)` an
// invitation to send content, and this end has already refused this message's —
// so the invitation must be impossible from the instant the head is read, not
// from the next pull onwards.
#[test]
fn no_interim_goes_out_while_a_head_refusal_is_still_unresolved() {
  let mut c = head_refused_before_the_pump(
    b"POST /x HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
  );
  let mut out = [0u8; 64];
  let refused = c.send_interim(100, NO_FIELDS, &mut out).unwrap_err();
  assert!(
    matches!(refused, Error::InvalidState(m) if m == REFUSED_BODY_TAKES_NO_INTERIM),
    "{refused:?}"
  );
  assert_eq!(out, [0u8; 64], "nothing was written");
}

// WINDOW ONE, the final-response gate. This is the call that SPENDS the one
// answer: a close-less response written here would leave the peer told the
// connection is persistent (RFC 9112 §9.3) and the 413 with nowhere to go. The
// gate refuses it before anything is encoded, so the answer is still owed —
// and it refuses only what it must, since the same response WITH the option
// goes out of this same window.
#[test]
fn a_close_less_answer_is_refused_while_a_head_refusal_is_still_unresolved() {
  const CLOSING_413: &[(&str, &[u8])] = &[("Content-Length", b"0"), ("Connection", b"close")];
  let mut c =
    head_refused_before_the_pump(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n");
  let mut out = [0u8; 128];
  let without_close = c
    .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
    .unwrap_err();
  assert!(
    matches!(without_close, Error::InvalidState(m) if m == REFUSED_BODY_NEEDS_CLOSE),
    "{without_close:?}"
  );
  assert_eq!(out, [0u8; 128], "nothing was written");

  // The one answer was not spent, and the 413 is still representable.
  let n = c
    .send_response(
      413,
      b"Content Too Large",
      CLOSING_413,
      BodyPlan::None,
      &mut out,
    )
    .unwrap();
  assert_eq!(
    out.get(..n),
    Some(
      b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        .as_slice()
    )
  );
}

// RFC 9112 §9.6's notice is once per CONNECTION, whichever cause reaches it
// first: the refusal signals the close, and the peer's write side ending after
// it is the same fact arriving twice.
#[test]
fn the_close_notice_is_queued_once_under_doubled_causes() {
  let mut c = bounded_server(4);
  let error = drain_until_error(
    &mut c,
    b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
  );
  assert!(matches!(error, Error::Refused(_)), "{error:?}");
  assert!(c.handle_eof().unwrap().is_none());
  assert_eq!(c.transport(), Transport::Ending);
  assert_eq!(c.poll_event(), None);
}

// The CLIENT half, on the framing that has no early exit at all: RFC 9112 §6.3
// item 8 declares nothing and is delimited only by the close, so the cumulative
// charge is its only gate — and it is response-only, which is why the client's
// default ceiling is the larger one. A client has no answer to write, so the
// refusal drains the connection outright, and §9.6's notice is still given once
// even though the close-delimited head had already signalled it.
#[test]
fn a_client_refuses_a_close_delimited_response_and_drains() {
  let mut c = Connection::<Client, General>::with_limits(
    Connection::<Client, General>::default_limits().with_max_body_bytes(4),
  );
  open_bodiless_request(&mut c, "GET");
  let error = {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\n\r\nhello");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    it.next().unwrap_err()
  };
  assert!(
    matches!(
      error,
      Error::Refused(Refusal::BodyTooLarge { limit: 4, .. })
    ),
    "{error:?}"
  );
  assert!(!matches!(c.lifecycle, Lifecycle::Failed));
  // Nothing left to read, and nothing this end could answer with.
  assert!(!c.wants_read());
  assert!(!c.is_awaiting_send());
  assert_eq!(c.transport(), Transport::Ending);
  assert_eq!(c.poll_event(), None);
}

// WINDOW ONE, the REQUEST-BODY side. A client with a chunked request still
// going out reads a final response head whose `Content-Length` is past its
// ceiling: the decoder is refused the moment `commit_head` builds it, before
// the head item is yielded, and the driver here drops the iterator without
// pulling again — so the pump step that resolves the refusal has not run.
//
// Every further request octet is work the peer is made to read for an answer
// this end has already declined. RFC 9112 §9.3 makes reading the whole response
// the condition for reusing the connection, and declining it is exactly what
// this end did, so nothing this request body could still say serves an exchange
// that can complete.
#[test]
fn a_refused_response_stops_the_request_body_before_the_pump_resolves_it() {
  const CHUNKED_REQUEST: &[(&str, &[u8])] = &[("Host", b"h"), ("Transfer-Encoding", b"chunked")];
  let mut c = Connection::<Client, General>::with_limits(
    Connection::<Client, General>::default_limits().with_max_body_bytes(4),
  );
  let mut out = [0u8; 128];
  c.open_request(
    "POST",
    &ORIGIN,
    CHUNKED_REQUEST,
    BodyPlan::Chunked,
    &mut out,
  )
  .unwrap();
  // The upload is under way and unrefused: this is what stops.
  assert!(c.send_body(b"hi", &mut out).unwrap() > 0);

  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    // Dropped WITHOUT a second pull: the refusal is unresolved by construction.
  }

  out = [0u8; 128];
  // Repeatedly, because the defect was that each call encoded again.
  for attempt in 0..2u8 {
    let refused = c.send_body(b"more", &mut out).unwrap_err();
    assert!(
      matches!(refused, Error::InvalidState(m) if m == REFUSED_RESPONSE_ENDS_THE_REQUEST),
      "attempt {attempt}: {refused:?}"
    );
  }
  let finished = c.finish_body(NO_TRAILERS, &mut out).unwrap_err();
  assert!(
    matches!(finished, Error::InvalidState(m) if m == REFUSED_RESPONSE_ENDS_THE_REQUEST),
    "{finished:?}"
  );
  assert_eq!(out, [0u8; 128], "nothing was written after the refusal");

  // And the write stays refused once the pump RESOLVES it, which is the half
  // that already worked: `refuse` settles the connection — clearing the
  // exchange that held the flag — and releases the send side, so the reason
  // quoted changes while the answer does not. No octet reaches the wire in
  // either window.
  let error = {
    let mut it = c.handle(b"");
    it.next().unwrap_err()
  };
  assert!(matches!(error, Error::Refused(_)), "{error:?}");
  assert!(c.send_body(b"more", &mut out).is_err());
  assert!(c.finish_body(NO_TRAILERS, &mut out).is_err());
  assert_eq!(out, [0u8; 128], "and still nothing was written");
}

// THE CONTROL, and the whole risk of the gate above: a SERVER's outbound body
// is the ANSWER to the refused message, not the message that was refused. A 413
// carrying its explanation is why this design refuses rather than latching, so
// a response body already under way must finish — here in window one, where the
// request's refusal is live in the decoder and the gate is being consulted.
#[test]
fn a_refused_request_still_lets_the_server_finish_the_answer_it_started() {
  const CLOSING_413: &[(&str, &[u8])] = &[("Content-Length", b"7"), ("Connection", b"close")];
  let mut c =
    head_refused_before_the_pump(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n");
  let mut out = [0u8; 128];
  let n = c
    .send_response(
      413,
      b"Content Too Large",
      CLOSING_413,
      BodyPlan::ContentLength(7),
      &mut out,
    )
    .unwrap();
  assert_eq!(
    out.get(..n),
    Some(
      b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 7\r\nConnection: close\r\n\r\n"
        .as_slice()
    )
  );
  // The explanation itself, written while the refusal is still in the decoder.
  let n = c.send_body(b"too big", &mut out).unwrap();
  assert_eq!(out.get(..n), Some(b"too big".as_slice()));
  assert_eq!(c.finish_body(NO_TRAILERS, &mut out).unwrap(), 0);
}

// THE STALL. Readiness is what a driver acts on when it is not pulling items,
// and both halves of it used to key on the pump step that FORMALISES a
// refusal — so a server that stopped at `Item::Head` was told "read, do not
// send" about a message no further octet can change.
//
// With RFC 9110 §10.1.1's expectation on the request that is a deadlock rather
// than a cosmetic wrong answer: the peer is withholding its content until it is
// answered, this end is waiting for content that will never come, and the
// refusal was decidable from the head alone. Both ends wait until a timeout.
#[test]
fn a_head_refused_body_tells_a_server_to_write_rather_than_to_read() {
  let mut c = head_refused_before_the_pump(
    b"POST /x HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
  );
  assert!(!c.wants_read(), "no octet can change a refusal");
  assert!(c.is_awaiting_send(), "the one answer is due now");

  // THE PENDING CONCLUSION, and the rule that keeps a refusal deliverable to a
  // driver that has stopped reading: an EMPTY slice is a sufficient re-offer.
  let error = {
    let mut it = c.handle(b"");
    it.next().unwrap_err()
  };
  assert!(
    matches!(
      error,
      Error::Refused(Refusal::BodyTooLarge { limit: 4, .. })
    ),
    "{error:?}"
  );
  // And the answer does not move when the pump formalises what was already true.
  assert!(!c.wants_read());
  assert!(c.is_awaiting_send());
}

// The CLIENT side of the same window, where the two halves answer differently:
// a client owes no response and its own request body has already been stopped,
// so both go quiet together and the pending conclusion is all there is to
// collect.
#[test]
fn a_refused_response_leaves_a_client_no_readiness_and_one_pump_owed() {
  const CHUNKED_REQUEST: &[(&str, &[u8])] = &[("Host", b"h"), ("Transfer-Encoding", b"chunked")];
  let mut c = Connection::<Client, General>::with_limits(
    Connection::<Client, General>::default_limits().with_max_body_bytes(4),
  );
  // A request body still in flight, so the send side is NOT idle: without that
  // this end's answer to "is a write owed?" would be false for a reason that
  // has nothing to do with the refusal.
  let mut out = [0u8; 128];
  c.open_request(
    "POST",
    &ORIGIN,
    CHUNKED_REQUEST,
    BodyPlan::Chunked,
    &mut out,
  )
  .unwrap();
  assert!(c.send_body(b"hi", &mut out).unwrap() > 0);
  {
    let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  }
  assert!(!c.wants_read());
  // A client owes no response, and the write it DOES have outstanding has
  // already been stopped — reporting an obligation here would name a call that
  // every send path refuses.
  assert!(!c.is_awaiting_send(), "a client owes no response");
  assert!(c.send_body(b"more", &mut out).is_err());
  let error = {
    let mut it = c.handle(b"");
    it.next().unwrap_err()
  };
  assert!(matches!(error, Error::Refused(_)), "{error:?}");
}

// THE CONTROL, and the whole risk of asking the decoder instead of the state: a
// body still owed octets must go on advertising read work, or the fix above
// trades a stall on refused bodies for a stall on every healthy one.
#[test]
fn a_body_still_owed_octets_still_advertises_read_work() {
  let mut c = bounded_server(1 << 20);
  {
    let mut it = c.handle(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhe");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    assert!(matches!(it.next().unwrap(), Some(Item::BodyChunk { .. })));
  }
  assert!(c.wants_read(), "three octets are still owed");
  assert!(!c.is_awaiting_send(), "the request is not through");
}

// The sibling of the refused case, and it is reachable for exactly the reason
// the refused one is: `Items` lets a driver stop pulling mid-stream, so a body
// whose octets have ALL arrived can be left mid-`Body` with its item still
// owed. That item comes from the next call rather than from the wire, so the
// read half must say so — the same pending conclusion, by the same rule.
#[test]
fn a_body_whose_octets_all_arrived_owes_an_item_rather_than_a_read() {
  let mut c = bounded_server(1 << 20);
  {
    let mut it = c.handle(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    let Some(Item::BodyChunk { data, .. }) = it.next().unwrap() else {
      panic!("expected the body")
    };
    assert_eq!(data, b"hello");
    // Stopped here, which the item stream explicitly permits.
  }
  assert!(!c.wants_read(), "every octet of this body has arrived");
  assert!(
    !c.is_awaiting_send(),
    "the completion item has not been taken"
  );
  let mut it = c.handle(b"");
  assert!(matches!(
    it.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
}

// SYNTAX BEFORE POLICY. A ceiling of zero refuses every message that carries
// content, so policy has everything to say about this body — but `zz` is not
// RFC 9112 §7.1's `chunk-size = 1*HEXDIG` at all, and a malformed element is
// diagnosed as malformed. Only a message that PARSED can be refused by policy,
// so this latches the connection and hands back a protocol violation.
#[test]
fn a_syntactically_malformed_chunk_still_latches_rather_than_refusing() {
  let mut c = bounded_server(0);
  let error = drain_until_error(
    &mut c,
    b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n",
  );
  assert!(
    matches!(error, Error::Protocol(H1Error::Malformed(_))),
    "{error:?}"
  );
  assert!(matches!(c.lifecycle, Lifecycle::Failed));
  assert_eq!(error.suggested_status(), Some(SuggestedStatus::BadRequest));
}

/// A server whose inbound bodies are bounded at `framing` chunk-framing octets
/// each, with the payload ceiling left where the role puts it.
///
/// The twin of `bounded_server`, and it has to be a separate helper: the two
/// knobs are not independent, so a test that means to exercise the framing
/// budget must STATE it rather than reach it by lowering the payload ceiling.
fn framing_bounded_server(framing: u64) -> Connection<Server, General> {
  Connection::<Server, General>::with_limits(
    Connection::<Server, General>::default_limits().with_max_chunk_framing_bytes(framing),
  )
}

// PER BODY, like the payload ceiling beside it and for the same reason: RFC 9112
// §9.3 carries many messages on one connection, and a budget that accumulated
// across them would refuse a conformant peer for the sins of its earlier
// requests. Each body here spends the WHOLE budget — nine octets of chunk-size
// line against nine — so a tally that survived the first would refuse the
// second's opening line, while one that never started at zero would refuse the
// first's last.
#[test]
fn the_framing_budget_resets_per_body() {
  const REQUEST: &[u8] = b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n\
1\r\na\r\n1\r\na\r\n0\r\n\r\n";
  let mut c = framing_bounded_server(9);
  assert_eq!(drain(&mut c, REQUEST), REQUEST.len(), "the first body");
  send_bodiless_response(&mut c);
  assert_eq!(drain(&mut c, REQUEST), REQUEST.len(), "the second body");
  send_bodiless_response(&mut c);
  // Two exchanges, both through, and no failure or close along the way.
  assert_eq!(c.next_exchange, 3);
  assert!(!matches!(c.lifecycle, Lifecycle::Failed));
  assert_eq!(c.poll_event(), None);
}

// THE FRAMING REFUSAL AS A DRIVER SEES IT. RFC 9112 §7.1.1 asks a server to
// limit "the total length of chunk extensions received in a request" and to
// "generate an appropriate 4xx (Client Error) response if that amount is
// exceeded". This core charges the whole size LINE instead, which is stricter
// and is local policy under RFC 9110 §15.5's 4xx class, so the status it
// advises is read off that same class — a 4xx, and not the 413 the payload
// ceiling advises, whose name is about content this message is well inside.
// Everything else is the refusal disposition its sibling already has: not a
// failure, one answer still owed, and that answer has to state `close`.
#[test]
fn a_chunk_framing_refusal_advises_a_4xx_and_still_owes_one_answer() {
  const CLOSING_400: &[(&str, &[u8])] = &[("Content-Length", b"0"), ("Connection", b"close")];
  let mut c = framing_bounded_server(3);
  let mut delivered = 0usize;
  let error = {
    let mut it = c.handle(
      b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n1\r\na\r\n",
    );
    loop {
      match it.next() {
        Ok(Some(Item::BodyChunk { data, .. })) => delivered = delivered.saturating_add(data.len()),
        Ok(Some(_)) => {}
        Ok(None) => panic!("the offer was exhausted without a refusal"),
        Err(error) => break error,
      }
    }
  };
  // One three-octet size line fits the budget, so its chunk is delivered; the
  // second line is what the budget refuses.
  assert_eq!(delivered, 1);
  let Error::Refused(Refusal::ChunkFramingTooLarge { exchange, limit }) = error else {
    panic!("expected a framing refusal, got {error:?}")
  };
  assert_eq!(limit, 3, "the BUDGET that refused, in framing octets");
  assert_eq!(exchange.get(), 1);
  assert_eq!(error.suggested_status(), Some(SuggestedStatus::BadRequest));
  assert_eq!(SuggestedStatus::BadRequest.code(), 400);
  assert_eq!(SuggestedStatus::BadRequest.reason(), "Bad Request");
  // NOT a violation: nothing on the wire broke a rule, so the connection is
  // answerable and RFC 9112 §9.6's notice is given once.
  assert!(!matches!(c.lifecycle, Lifecycle::Failed));
  assert!(!c.wants_read());
  assert!(c.is_awaiting_send());
  assert_eq!(c.transport(), Transport::Ending);

  let mut out = [0u8; 128];
  let without_close = c
    .send_response(400, b"Bad Request", LENGTH_0, BodyPlan::None, &mut out)
    .unwrap_err();
  assert!(
    matches!(without_close, Error::InvalidState(m) if m == REFUSED_BODY_NEEDS_CLOSE),
    "{without_close:?}"
  );
  assert_eq!(out, [0u8; 128], "the one answer was not spent");
  let n = c
    .send_response(400, b"Bad Request", CLOSING_400, BodyPlan::None, &mut out)
    .unwrap();
  assert_eq!(
    out.get(..n),
    Some(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice())
  );
}

// THE GRANULARITY THE BUDGET IMPLIES, and the property worth writing down about
// it: because the budget is a sixteenth of the payload ceiling, the smallest
// chunk size a FULL body can be sent in does not move with the role. 64-octet
// chunks spend the budget exactly and die at the last-chunk line at either
// role; 65-octet chunks fit at either, with room over. Both numbers are read
// off the resolved limits rather than restated, so a change to the resolution
// rule moves this test with it.
#[test]
fn the_sustainable_chunk_granularity_does_not_move_with_the_role() {
  // What a whole body of `payload` costs in RFC 9112 §7.1 chunk-size lines at
  // `chunk` octets per chunk: four octets for every chunk's line — two hex
  // digits and the CRLF, since 64 and 65 are both `4x` — and three for the
  // last chunk's `0\r\n`.
  fn framing_cost(payload: u64, chunk: u64) -> u64 {
    payload.div_ceil(chunk) * 4 + 3
  }
  let server = Connection::<Server, General>::default_limits();
  let client = Connection::<Client, General>::default_limits();
  for limits in [server, client] {
    let payload = limits.max_body_bytes();
    let budget = limits.max_chunk_framing_bytes();
    assert!(
      framing_cost(payload, 64) > budget,
      "64-octet chunks spend more than the budget"
    );
    assert!(
      framing_cost(payload, 65) <= budget,
      "65 is the sustainable granularity"
    );
  }
  // And it is the SIXTEENTH that makes the boundary role-independent: the two
  // roles' ceilings differ by 64, their budgets by the same factor.
  assert_eq!(client.max_body_bytes() / server.max_body_bytes(), 64);
  assert_eq!(
    client.max_chunk_framing_bytes() / server.max_chunk_framing_bytes(),
    64
  );
}

/// Fields a response to a refused body has to carry: RFC 9112 §9.3's close
/// branch has been taken, so the one answer left has to say so on the wire.
const CLOSING_413: &[(&str, &[u8])] = &[("Content-Length", b"0"), ("Connection", b"close")];

// THE RATCHET, through the public surface, and the property that makes the
// connection ceiling a MAXIMUM rather than a default: narrowing is `min` and
// reports nothing, so a route asking for more than the connection allows is
// capped silently. Per EXCHANGE, not per connection — the next message on the
// same keep-alive connection starts from the operator's ceiling again, because
// what a narrowing writes is the decoder built for one message.
#[test]
fn limit_body_narrows_one_exchange_and_caps_a_route_that_asks_for_more() {
  let mut c = bounded_server(1 << 20);
  {
    let mut it = c.handle(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    // Above the ceiling: `Ok`, and 1 MiB is what the route actually gets.
    assert_eq!(it.limit_body(8 << 20), Ok(()));
    assert_eq!(it.limit_body(16), Ok(()));
    // Idempotent and order-free: a widen after a narrow is a no-op.
    assert_eq!(it.limit_body(64), Ok(()));
  }
  let progress = c.body_progress().expect("a body is being received");
  assert_eq!(
    progress.limit, 16,
    "min only, in any order, any number of times"
  );
  assert_eq!(progress.announced, Some(5));
  assert_eq!(progress.received, 0);
  assert_eq!(progress.exchange.get(), 1);
  // The OPERATOR's ceiling is untouched: a route narrows a message, not a
  // connection, and there is no path from a live connection back to `Limits`.
  assert_eq!(c.max_body_bytes(), 1 << 20);

  // Finish the exchange and take the next one on the same connection.
  drain(&mut c, b"hello");
  send_bodiless_response(&mut c);
  {
    let mut it = c.handle(b"POST /y HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  }
  let next = c.body_progress().expect("the second body");
  assert_eq!(next.exchange.get(), 2);
  assert_eq!(
    next.limit,
    1 << 20,
    "the narrowing died with the message it was made for"
  );
}

// RFC 9112 §6.3 item 6 states the whole body in the head, so a route ceiling
// below what that number already declared is unsatisfiable at once — and the
// limit the refusal carries is the ROUTE's own maximum, because the narrowing
// is COMMITTED before satisfiability is checked. A driver logging the refusal
// otherwise reads back the ceiling the route replaced.
//
// Everything a wire-side refusal leaves behind holds here too: policy, not a
// violation, one notice, one answer still owed, and that answer must state
// `close`.
#[test]
fn an_unsatisfiable_route_limit_refuses_and_names_the_routes_own_maximum() {
  let mut c = bounded_server(1 << 20);
  let error = {
    let mut it = c.handle(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5000\r\n\r\n");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    it.limit_body(4096).unwrap_err()
  };
  let Error::Refused(Refusal::BodyTooLarge { exchange, limit }) = error else {
    panic!("expected a policy refusal, got {error:?}")
  };
  assert_eq!(limit, 4096, "the route's max, not the ceiling it replaced");
  assert_eq!(exchange.get(), 1);
  assert_eq!(
    error.suggested_status(),
    Some(SuggestedStatus::ContentTooLarge)
  );
  assert!(!matches!(c.lifecycle, Lifecycle::Failed));
  assert!(!c.wants_read());
  assert!(c.is_awaiting_send());
  assert_eq!(c.transport(), Transport::Ending);
  assert_eq!(c.poll_event(), None);
  // The body is gone, so there is no progress left to report.
  assert_eq!(c.body_progress(), None);

  let mut out = [0u8; 128];
  let without_close = c
    .send_response(
      413,
      b"Content Too Large",
      LENGTH_0,
      BodyPlan::None,
      &mut out,
    )
    .unwrap_err();
  assert!(
    matches!(without_close, Error::InvalidState(m) if m == REFUSED_BODY_NEEDS_CLOSE),
    "{without_close:?}"
  );
  assert!(
    c.send_response(
      413,
      b"Content Too Large",
      CLOSING_413,
      BodyPlan::None,
      &mut out
    )
    .is_ok()
  );
}

// THE THREE ANSWERS `limit_body` OWES, kept apart. RFC 9112 §6.3 item 7 gives a
// GET no body at all, which is a body of no octets rather than no body — so a
// driver that narrows after EVERY head must be answered `Ok`, or the uniform
// shape is the one shape that cannot be written. `InvalidState` is reserved for
// a connection that cannot act on the call, and its two causes are told apart
// by text alone, which is why the benign case must not join them.
#[test]
fn limit_body_is_vacuous_on_a_bodiless_message_and_invalid_between_them() {
  let mut c = bounded_server(1 << 20);
  {
    let mut it = c.handle(BODILESS);
    // Between messages: nothing is being received yet.
    let idle = it.limit_body(1).unwrap_err();
    assert!(
      matches!(idle, Error::InvalidState(m) if m == NO_BODY_BEING_RECEIVED),
      "{idle:?}"
    );
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    assert_eq!(
      it.limit_body(1),
      Ok(()),
      "a narrow-after-every-head driver must not error on a GET"
    );
    // The body is over, and the exchange with it: still vacuous, never an error.
    while it.next().unwrap().is_some() {}
    assert_eq!(
      it.limit_body(1),
      Err(Error::InvalidState(NO_BODY_BEING_RECEIVED))
    );
  }

  // A connection that has FAILED answers the lifecycle's own way, and the text
  // is what distinguishes it from the benign case above.
  let mut failed = bounded_server(1 << 20);
  let violation = drain_until_error(
    &mut failed,
    b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
  );
  assert!(matches!(violation, Error::Protocol(_)), "{violation:?}");
  let mut it = failed.handle(b"");
  assert!(matches!(it.limit_body(1), Err(Error::InvalidState(m)) if m == FAILED));
}

// THE CONTIGUOUS HANDOVER, and the pump shape it forces. RFC 9112 §6.3 item 6
// states the whole body's length in the head, and the counted framing claims
// `min(remaining, input.len())` in one go — so a driver that waits until its
// own buffer holds `announced` more octets takes the whole body as ONE borrowed
// chunk, with no copy anywhere in this core.
//
// Two steps of the recipe are not discoverable from the signatures, and this is
// written in the order that makes both load-bearing:
//
//  1. STOP at `Item::Head` and DROP the iterator. One more `next()` would hand
//     back a partial chunk of whatever happened to be buffered, and
//     `body_progress` is unreachable while `Items` borrows the connection.
//  2. ANSWER THE PENDING EXPECTATION BEFORE WAITING. `Item::ExpectContinue` is
//     yielded by the BODY pump, so a driver that stopped at the head has never
//     seen it and re-derives the ask from the head's own `Expect` field. RFC
//     9110 §10.1.1 provides for a client that waits for its `100 (Continue)`
//     before sending content, so without this both ends wait.
#[test]
fn a_counted_body_arrives_as_one_borrowed_chunk_when_the_driver_waits() {
  const HEAD: &[u8] =
    b"POST /x HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 11\r\n\r\n";
  const BODY: &[u8] = b"hello world";

  let mut c = Connection::<Server, General>::new();
  let mut out = [0u8; 64];

  // 1. Pull to the head and STOP.
  let expects_continue = {
    let mut it = c.handle(HEAD);
    let Some(Item::Head { view, .. }) = it.next().unwrap() else {
      panic!("expected the head")
    };
    assert_eq!(it.consumed(), HEAD.len());
    // The ask is re-derived from the head the driver is holding, because the
    // item that would have stated it comes out of the body pump.
    view.header("expect") == Some(b"100-continue".as_slice())
  };
  // The iterator is dropped here: `body_progress` borrows the connection.

  let progress = c.body_progress().expect("a body is being received");
  assert_eq!(
    progress.announced,
    Some(11),
    "item 6 states the whole body in the head"
  );
  assert_eq!(progress.received, 0);

  // 2. Answer the expectation BEFORE waiting for the octets it invites.
  assert!(expects_continue);
  let n = c.send_interim(100, NO_FIELDS, &mut out).unwrap();
  assert_eq!(&out[..n], b"HTTP/1.1 100 \r\n\r\n");

  // 3. WAIT until the driver's buffer holds `announced` more octets. The head
  //    was consumed in full, so the next offer begins at the body's first byte.
  let wanted = usize::try_from(progress.announced.unwrap()).unwrap();
  let buffered = BODY.get(..wanted).unwrap();
  assert_eq!(buffered, BODY, "the wait is over when the count is met");

  // 4. One offer, ONE chunk, borrowed straight out of that buffer — no copy
  //    anywhere in this core, and no second `handle`.
  {
    let mut it = c.handle(buffered);
    let Some(Item::BodyChunk { data, .. }) = it.next().unwrap() else {
      panic!("expected the whole body in one chunk")
    };
    assert_eq!(data, BODY);
    assert!(matches!(
      it.next().unwrap(),
      Some(Item::ExchangeComplete { .. })
    ));
    assert!(it.next().unwrap().is_none());
    assert_eq!(it.consumed(), BODY.len());
  }
  assert_eq!(c.body_progress(), None, "the body is over");
}

// The negative control for the recipe above, and what the wait BUYS: a driver
// that pulls again over a buffer holding less than `announced` is handed the
// partial chunk the counted framing can serve from what is there. Nothing is
// wrong with that — it is the streaming shape, and it is why the recipe says to
// stop at the head — but it is not one contiguous body, so a consumer that
// wanted one would have to copy the pieces together itself.
#[test]
fn pulling_before_the_announced_count_has_arrived_hands_back_a_partial_chunk() {
  let mut c = Connection::<Server, General>::new();
  let mut it = c.handle(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\nhello");
  assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  let Some(Item::BodyChunk { data, .. }) = it.next().unwrap() else {
    panic!("expected a chunk")
  };
  assert_eq!(data, b"hello", "only what the buffer held");
}

// THE WINDOW BETWEEN `BodyChunk` AND `ExchangeComplete`. A counted body whose
// octets have all arrived leaves the decoder complete while the exchange is
// not: `ExchangeComplete` has not been pulled, so `Items` is still usable and a
// route may still narrow. The octets are already out, so a ceiling below that
// total was not met and saying `Ok` would tell a route its bound was applied to
// content that had already crossed it.
#[test]
fn narrowing_below_a_body_already_delivered_in_full_refuses() {
  let mut c = bounded_server(1 << 20);
  let error = {
    let mut it = c.handle(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\nhello world");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
    let Some(Item::BodyChunk { data, .. }) = it.next().unwrap() else {
      panic!("expected the whole body in one chunk")
    };
    assert_eq!(data, b"hello world");
    it.limit_body(4).unwrap_err()
  };
  let Error::Refused(Refusal::BodyTooLarge { exchange, limit }) = error else {
    panic!("expected a policy refusal, got {error:?}")
  };
  assert_eq!(limit, 4, "the route's max, not the ceiling it replaced");
  assert_eq!(exchange.get(), 1);
  assert_eq!(
    error.suggested_status(),
    Some(SuggestedStatus::ContentTooLarge)
  );
  // Policy, not a violation: the connection is answerable and the one answer
  // owed still has to state `close` (RFC 9112 §9.3).
  assert!(!matches!(c.lifecycle, Lifecycle::Failed));
  assert!(c.is_awaiting_send());
  assert_eq!(c.transport(), Transport::Ending);
  let mut out = [0u8; 128];
  let without_close = c
    .send_response(
      413,
      b"Content Too Large",
      LENGTH_0,
      BodyPlan::None,
      &mut out,
    )
    .unwrap_err();
  assert!(
    matches!(without_close, Error::InvalidState(m) if m == REFUSED_BODY_NEEDS_CLOSE),
    "{without_close:?}"
  );
}

// The size budget is a module-level `const _` (below the type, in `mod.rs`), so
// this only pins that the connection stays a state machine rather than a buffer:
// no fed byte is ever copied into it.
#[test]
fn connection_holds_no_buffer() {
  assert!(core::mem::size_of::<Connection<Server, General>>() <= 256);
  assert!(core::mem::size_of::<Connection<Client, General>>() <= 256);
  assert!(core::mem::size_of::<Connection<Server, Tunnel>>() <= 256);
  assert!(core::mem::size_of::<Connection<Client, Tunnel>>() <= 256);
}

/// Tunnel-mode tests: the ONE protocol switch a `Connection<_, Tunnel>` exists
/// to complete, and the byte stream it hands over when that switch is through.
///
/// Its own module rather than more free functions above, because nothing here
/// shares the General fixtures: a tunnel has no exchange, no body, and no
/// keep-alive, so the state these tests set up is a handshake and nothing else.
mod tunnel {
  use super::*;
  use crate::{
    connection::tunnel::{
      CONNECT_INDICATES_NO_PROTOCOL, CONNECT_NEEDS_A_PORT, CONTINUE_BEFORE_SWITCH,
      HANDSHAKE_HAS_NO_CONTENT, HANDSHAKE_STATES_CLOSE, INTERIM_NEEDS_HTTP_11, NO_HANDSHAKE,
      NOT_A_HANDSHAKE, NOTHING_TO_ANSWER, OFFER_NEEDS_BOTH_HALVES, ONE_HANDSHAKE,
      SWITCH_HAS_NO_FRAMING, SWITCH_NEEDS_BOTH_HALVES, SWITCH_TARGET_FORM, SWITCH_THROUGH_ACCEPT,
      SWITCH_WAS_NEVER_OFFERED,
    },
    error::H1Error,
  };

  /// RFC 9110 §7.8 wants BOTH halves of an upgrade offer: the `upgrade`
  /// connection option ("A sender of Upgrade MUST also send an `Upgrade`
  /// connection option in the Connection header field") and the `Upgrade` field
  /// that names the protocol.
  const OFFER: &[(&str, &[u8])] = &[
    ("Host", b"example.com"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
  ];

  /// The answer to that offer, which RFC 9110 §15.2.2 makes a MUST for the
  /// server: "The server MUST generate an Upgrade header field in the response
  /// that indicates which protocol(s) will be in effect after this response."
  const SWITCH: &[(&str, &[u8])] = &[("Upgrade", b"websocket"), ("Connection", b"Upgrade")];

  /// The RFC 9112 §3.2.1 origin-form target of the upgrade requests here.
  const CHAT: Target<'static> = Target::Origin {
    path_and_query: "/chat",
  };

  /// A tunnel destination in the RFC 9112 §3.2.3 `uri-host ":" port` form.
  const DESTINATION: &str = "example.com:443";

  /// The one field a CONNECT request needs (RFC 9110 §7.2, and §9.3.6's own
  /// example sends it).
  const CONNECT_HOST: &[(&str, &[u8])] = &[("Host", b"example.com:443")];

  /// A client that has written its upgrade offer and is reading the response.
  fn offered() -> Connection<Client, Tunnel> {
    let mut c = Connection::<Client, Tunnel>::new();
    let mut out = [0u8; 128];
    let n = c.open_upgrade(&CHAT, OFFER, &mut out).unwrap();
    assert_eq!(
      &out[..n],
      b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    );
    c
  }

  /// A client that has written a CONNECT and is reading the response.
  fn connected() -> Connection<Client, Tunnel> {
    let mut c = Connection::<Client, Tunnel>::new();
    let mut out = [0u8; 128];
    let n = c.open_connect(DESTINATION, CONNECT_HOST, &mut out).unwrap();
    assert_eq!(
      &out[..n],
      b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    );
    c
  }

  // A handshake needs an ANSWER, so a client whose read side has ended has no
  // handshake to open — General's `open_request` refuses exactly this ordering,
  // and the Tunnel EOF path did not inherit the guard. Without it a request went
  // out and the phase advanced to `Handshaking`, where nothing could ever move it.
  #[test]
  fn a_client_opens_no_handshake_after_its_read_side_ended() {
    // Both openers, and the refusal costs the caller only the call: nothing is
    // written and no handshake begins.
    let mut out = [0xAAu8; 160];
    let mut c = Connection::<Client, Tunnel>::new();
    c.handle_eof().unwrap();
    assert_eq!(
      c.open_upgrade(&CHAT, OFFER, &mut out),
      Err(Error::InvalidState(READ_SIDE_ENDED))
    );
    assert_eq!(out, [0xAAu8; 160]);

    let mut c = Connection::<Client, Tunnel>::new();
    c.handle_eof().unwrap();
    assert_eq!(
      c.open_connect(DESTINATION, CONNECT_HOST, &mut out),
      Err(Error::InvalidState(READ_SIDE_ENDED))
    );
    assert_eq!(out, [0xAAu8; 160]);

    // The phase is untouched, which is what "nothing began" means here: the
    // refusal is not a latch, and the same connection is still the idle one it
    // was. Proved by the answer a handshake in flight would have given instead.
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 200 OK\r\n\r\n"),
      Err(Error::InvalidState(NO_HANDSHAKE))
    ));

    // The check is BEFORE the headers are walked: a section this core would
    // otherwise refuse on its own terms still answers the ordering, so a caller
    // is told the connection is over rather than sent to fix a field that no
    // longer matters.
    let mut c = Connection::<Client, Tunnel>::new();
    c.handle_eof().unwrap();
    let broken: &[(&str, &[u8])] = &[("Host", b"h"), ("Connection", b"@")];
    assert_eq!(
      c.open_upgrade(&CHAT, broken, &mut out),
      Err(Error::InvalidState(READ_SIDE_ENDED))
    );
    assert_eq!(out, [0xAAu8; 160]);

    // The same after a PARTIAL response: an EOF mid-head ends the handshake and
    // leaves nothing to open either.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 101 Switch"),
      Ok(ClientTunnelOutcome::NeedMore)
    ));
    c.handle_eof().unwrap();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 101 Switch"),
      Err(Error::Protocol(H1Error::Framing(CLOSED_MID_HEAD)))
    ));

    // THE HALF-CLOSE MUST NOT REGRESS. A server that has already read its
    // request answers it, whatever the read side did afterwards: RFC 9112 §9.6
    // ends this end's READING, not its writing.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      ),
      Ok(ServerTunnelRequest::Upgrade { .. })
    ));
    s.handle_eof().unwrap();
    let n = s.send_interim(103, NO_FIELDS, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 103 \r\n\r\n");
    let n = s.accept(SWITCH, &mut out).unwrap();
    assert_eq!(
      &out[..n],
      b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    );

    // …and the refusal half of the same rule, on a CONNECT.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
      Ok(ServerTunnelRequest::Connect { .. })
    ));
    s.handle_eof().unwrap();
    assert!(s.reject(502, b"Bad Gateway", NO_FIELDS, &mut out).is_ok());
  }

  // THE API HOLE: Tunnel mode had no end-of-file operation at all —
  // `Connection::handle_eof` is General's — so a driver holding a closed
  // transport and a half-arrived handshake response got `NeedMore` for ever and
  // could never terminate the handshake.
  //
  // The three shapes below are the ones a handshake can be in when the transport
  // ends, each in both roles and both handshake kinds. The verdicts are General's
  // own, from `no_more_input`: the same bytes ending the same way must not mean
  // two different things because of which mode is reading them.
  #[test]
  fn a_closed_transport_ends_the_handshake() {
    // CLIENT, both kinds: nothing of the response arrived. RFC 9112 §9.5 with
    // RFC 9110 §15.2 — the request went out and no FINAL response came back.
    for mut c in [offered(), connected()] {
      c.handle_eof().unwrap();
      assert!(matches!(
        c.handle_response(b""),
        Err(Error::Protocol(H1Error::Framing(CLOSED_BEFORE_RESPONSE)))
      ));
      // Latched: the violation is handed back exactly once.
      assert!(matches!(
        c.handle_response(b""),
        Err(Error::InvalidState(FAILED))
      ));
    }

    // CLIENT, both kinds: the response started and stopped mid-sentence (RFC
    // 9112 §2.1). The sharper diagnosis, and it outranks the one above.
    for mut c in [offered(), connected()] {
      assert!(matches!(
        c.handle_response(b"HTTP/1.1 200 OK\r\nX: "),
        Ok(ClientTunnelOutcome::NeedMore)
      ));
      c.handle_eof().unwrap();
      assert!(matches!(
        c.handle_response(b"HTTP/1.1 200 OK\r\nX: "),
        Err(Error::Protocol(H1Error::Framing(CLOSED_MID_HEAD)))
      ));
    }

    // CLIENT: interim responses do not make an answer. §15.2 makes them
    // informational, so the verdict after any number of them is the same one —
    // and the head that completed cleared the watermark, so it is the
    // no-response verdict rather than the truncation.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 103 Early Hints\r\n\r\n"),
      Ok(ClientTunnelOutcome::Interim { .. })
    ));
    c.handle_eof().unwrap();
    assert!(matches!(
      c.handle_response(b""),
      Err(Error::Protocol(H1Error::Framing(CLOSED_BEFORE_RESPONSE)))
    ));

    // SERVER: a boundary with nothing behind it. The client closed without
    // asking, which is a clean ending — nothing was owed, so there is nothing to
    // answer and nothing to latch. Re-offering says the same thing, because the
    // fact it reports is the transport's.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(b""),
      Ok(ServerTunnelRequest::NeedMore)
    ));
    s.handle_eof().unwrap();
    assert!(matches!(
      s.handle_request(b""),
      Ok(ServerTunnelRequest::Closed)
    ));
    assert!(matches!(
      s.handle_request(b""),
      Ok(ServerTunnelRequest::Closed)
    ));
    // The §9.2 stray empty lines are discardable, so a peer that sent only those
    // ended just as cleanly.
    let mut s = Connection::<Server, Tunnel>::new();
    s.handle_eof().unwrap();
    assert!(matches!(
      s.handle_request(b"\r\n\r\n"),
      Ok(ServerTunnelRequest::Closed)
    ));

    // SERVER: a request that started and stopped. Latched, and NO rejection
    // owed — the same call General's `truncated` makes with `answerable = false`.
    let mut s = Connection::<Server, Tunnel>::new();
    s.handle_eof().unwrap();
    assert!(matches!(
      s.handle_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: e"),
      Err(Error::Protocol(H1Error::Framing(CLOSED_MID_HEAD)))
    ));
    let mut out = [0xAAu8; 96];
    assert!(matches!(
      s.reject(400, b"Bad Request", NO_FIELDS, &mut out),
      Err(Error::InvalidState(_))
    ));
    assert_eq!(out, [0xAAu8; 96]);

    // A rejection this connection already owed is untouched by the peer's
    // close, and `reject` still writes it. The EOF report itself answers
    // `FAILED`, exactly as General's does on a latched connection: the violation
    // was handed back once, by the call that found it, and the driver already
    // knows the connection is over.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(
      s.handle_request(b"GET /chat HTTP/1.1\r\nHost: h\r\n\r\n")
        .is_err(),
      "neither an offer nor a CONNECT"
    );
    assert!(matches!(s.handle_eof(), Err(Error::InvalidState(FAILED))));
    assert!(matches!(s.handle_eof(), Err(Error::InvalidState(FAILED))));
    let n = s.reject(400, b"Bad Request", NO_FIELDS, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 400 Bad Request\r\n\r\n");

    // A connection that has left HTTP has nothing to say about the ending: the
    // bytes were the other protocol's already.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      ),
      Ok(ClientTunnelOutcome::Switched { .. })
    ));
    c.handle_eof().unwrap();
  }

  // The inbound Tunnel site: an interim that states RFC 9112 §9.6's `close` ENDS
  // the handshake — no switch may follow it.
  //
  // §9.6 makes a sender of the option close "after it sends the response
  // containing the close connection option", and a 1xx is a response message
  // (RFC 9110 §15.2). So the peer has committed to closing after that head, and
  // the 101 that would switch is not a legal continuation of it. Left as an
  // `Interim`, a driver would go on waiting for a switch that may never come —
  // and if a non-conforming peer sent one anyway, this end would hand over a
  // byte stream on a connection already committed to closing.
  //
  // Both handshakes, because both end at a head this rule reaches.
  #[test]
  fn an_interim_that_states_close_ends_the_handshake() {
    const CLOSING_INTERIM: &[u8] = b"HTTP/1.1 100 \r\nConnection: close\r\n\r\n";

    // The upgrade half: the 101 that follows is refused rather than switching.
    let mut c = offered();
    let ClientTunnelOutcome::Refused {
      head,
      status,
      leftover,
    } = c.handle_response(CLOSING_INTERIM).unwrap()
    else {
      panic!("an interim stating `close` ends the handshake")
    };
    assert_eq!(status.code, 100, "the status says which refusal this was");
    assert_eq!(head.header("connection"), Some(b"close".as_slice()));
    assert_eq!(leftover, b"");
    // Terminal: the switch the peer might still send is not taken.
    assert!(matches!(
      c.handle_response(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
      ),
      Err(Error::InvalidState(_))
    ));

    // The CONNECT twin, whose switch is any 2xx (RFC 9110 §9.3.6).
    let mut c = connected();
    assert!(matches!(
      c.handle_response(CLOSING_INTERIM).unwrap(),
      ClientTunnelOutcome::Refused { .. }
    ));
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
      Err(Error::InvalidState(_))
    ));

    // And an interim WITHOUT the option is untouched: §15.2 lets any number of
    // them precede the switch, and this core still reads them as interim.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 100 \r\n\r\n").unwrap(),
      ClientTunnelOutcome::Interim { .. }
    ));
    assert!(matches!(
      c.handle_response(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
      )
      .unwrap(),
      ClientTunnelOutcome::Switched { .. }
    ));
  }

  // The outbound Tunnel site: the identical rule on the server's own interim,
  // stated in the identical words as General mode's.
  //
  // A 100 with `close` would commit this end to closing before the switch it is
  // still deciding — §9.6 binds the option to the response carrying it — so it is
  // refused before encoding. A driver that means to decline says so with
  // `reject`, which is the call that ends a handshake.
  #[test]
  fn a_tunnel_interim_may_not_state_a_close() {
    let mut s = asked_for_a_tunnel();
    let mut out = [0xAAu8; 128];
    let closing: &[(&str, &[u8])] = &[("Connection", b"close")];
    assert_eq!(
      s.send_interim(100, closing, &mut out),
      Err(Error::InvalidState(
        "an interim response states no Connection: close"
      ))
    );
    assert_eq!(
      out, [0xAAu8; 128],
      "a refused interim wrote into the buffer"
    );
    // Inert: the handshake is still live and the interim path still works.
    let n = s.send_interim(100, NO_FIELDS, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 100 \r\n\r\n");
    // And the way to end a handshake is unchanged.
    let closing_reject: &[(&str, &[u8])] = &[("Connection", b"close")];
    assert!(
      s.reject(426, b"Upgrade Required", closing_reject, &mut out)
        .is_ok()
    );
  }

  // gate-exempt: validate::has_close_option — names the predicate Tunnel's 101 arm asks IN PRODUCTION CODE; this test pins the outcome by
  // driving the public API and asserting on it, and never calls the predicate directly itself.
  // The same 101, the same verdict, in the mode that reads it natively. RFC 9112
  // §9.6: this peer has committed to closing, so it has nothing to continue
  // INTO — and Tunnel's 101 arm asks `validate::has_close_option` for it, the
  // same predicate General's asks. `ends_persistence` stays on the INTERIM arm
  // alone, where another HTTP message really does follow.
  //
  // Pinned as a PARITY test, over one buffer of bytes, because that is the
  // property that matters: a head one mode switches on must be a head the other
  // switches on (RFC 9112 §11.1). Two modes agreeing is not evidence that either
  // is right, so each mode's own verdict is asserted here beside the parity
  // rather than in place of it.
  #[test]
  fn a_101_stating_close_is_refused_in_both_modes() {
    const CLOSING_SWITCH: &[u8] =
      b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade, close\r\nupgrade: websocket\r\n\r\n";

    let mut t = offered();
    let Err(Error::Protocol(H1Error::Framing(tunnel_why))) = t.handle_response(CLOSING_SWITCH)
    else {
      panic!("Tunnel must not switch on a 101 that states close")
    };
    assert_eq!(tunnel_why, SWITCH_AFTER_CLOSE);
    assert_ne!(t.tunnel, TunnelPhase::Switched);

    let mut g = super::offered_upgrade();
    let mut items = g.handle(CLOSING_SWITCH);
    let Err(Error::Protocol(H1Error::Framing(general_why))) = items.next() else {
      panic!("General must not switch on it either")
    };

    // The SAME fault, not merely two refusals: one rule, one verdict, whichever
    // mode is holding the bytes.
    assert_eq!(general_why, tunnel_why);
  }

  // RFC 9112 §9.6 on the SEND side: "A server that sends a close connection
  // option MUST initiate closure of the connection … after it sends the response
  // containing close." A 101 that also states `close` promises to close the
  // connection it just handed to another protocol, so this end must not write
  // one — and after `1d2d731` both of this crate's CLIENTS refuse exactly these
  // bytes, so emitting them would make two endpoints of one crate disagree about
  // one wire message.
  #[test]
  fn a_switch_this_end_writes_states_no_close() {
    let mut s = asked_to_upgrade();
    let mut out = [0xAAu8; 128];
    let closing: &[(&str, &[u8])] = &[("Connection", b"Upgrade, close"), ("Upgrade", b"websocket")];
    assert_eq!(
      s.accept(closing, &mut out),
      Err(Error::InvalidState(TAKEOVER_STATES_NO_CLOSE))
    );
    assert_eq!(out, [0xAAu8; 128], "a refused accept wrote into the buffer");
    assert_ne!(s.tunnel, TunnelPhase::Switched, "the phase moved anyway");

    // NOT a false refusal: the ordinary 101 still goes out and still switches.
    let n = s
      .accept(SWITCH, &mut out)
      .expect("an ordinary 101 still switches");
    assert!(n > 0);
    assert_eq!(s.tunnel, TunnelPhase::Switched);
  }

  // The same rule where this end ORIGINATES the handshake: a request that offers
  // an upgrade while stating `close` asks for a switch onto a connection it has
  // just said it is ending. This crate must not originate a handshake it would
  // itself refuse to complete.
  #[test]
  fn an_offer_this_end_writes_states_no_close() {
    let mut c = Connection::<Client, Tunnel>::new();
    let mut out = [0xAAu8; 128];
    let closing: &[(&str, &[u8])] = &[
      ("Host", b"example.com"),
      ("Connection", b"Upgrade, close"),
      ("Upgrade", b"websocket"),
    ];
    assert_eq!(
      c.open_upgrade(&CHAT, closing, &mut out),
      Err(Error::InvalidState(TAKEOVER_STATES_NO_CLOSE))
    );
    assert_eq!(out, [0xAAu8; 128], "a refused open wrote into the buffer");
    // Inert: the handshake never began, so the ordinary offer still opens it.
    assert!(c.open_upgrade(&CHAT, OFFER, &mut out).is_ok());
  }

  // The RECEIVE side of the same fact, and the entry point that disagreed with
  // General about one wire request. RFC 9112 §9.6: "A server that receives a
  // close connection option MUST initiate closure of the connection … after it
  // sends the final response to the request that contained the close connection
  // option" — so a server owes a close after answering, and a switch is the
  // opposite promise.
  //
  // General already answered correctly: `commit_head` accumulates the close, the
  // lifecycle leaves `Open`, and `into_tunnel` refuses `NOT_OPEN`. Tunnel's
  // direct classification bypassed that accumulator and accepted the same bytes,
  // so ONE request had two answers depending on which entry point read it.
  #[test]
  fn an_offer_that_states_close_is_no_handshake_and_general_agrees() {
    const CLOSING_OFFER: &[u8] =
      b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: upgrade, close\r\nUpgrade: websocket\r\n\r\n";

    // Tunnel, classifying directly.
    let mut s = Connection::<Server, Tunnel>::new();
    let Err(Error::Protocol(H1Error::Framing(why))) = s.handle_request(CLOSING_OFFER) else {
      panic!("a close-bearing offer is not a handshake this connection can complete")
    };
    assert_eq!(why, HANDSHAKE_STATES_CLOSE);

    // General, reaching the same request through the transition edge.
    let mut g = Connection::<Server, General>::new();
    {
      let mut items = g.handle(CLOSING_OFFER);
      while items
        .next()
        .expect("the request itself is well formed")
        .is_some()
      {}
    }
    let (_, refused) = g
      .into_tunnel()
      .expect_err("General refuses the transition on the same bytes");
    assert_eq!(refused, TransitionRefused::NOT_OPEN);

    // NOT a false refusal: the same offer WITHOUT close still classifies.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"
      ),
      Ok(ServerTunnelRequest::Upgrade { .. })
    ));
  }

  // An EOF, then a switch out of bytes already buffered behind it — the shape a
  // queued answer gets wrong, as a stale instruction, a lost one, or a doubled
  // one.
  //
  // ASSERTED AS A LEVEL, and it has to be: `poll_event` can never return
  // anything in Tunnel mode, because the only notice left names an exchange and
  // this mode frames none. Asserting `poll_event() == None` here would be
  // VACUOUSLY true — it would pass with the transport reported completely wrong.
  #[test]
  fn an_eof_before_a_buffered_switch_signals_no_close_in_tunnel_mode() {
    let mut c = offered();
    c.handle_eof().expect("an EOF on a live handshake");
    assert!(c.read_closed, "the transport fact must latch at once");
    assert_eq!(
      c.transport(),
      Transport::Ending,
      "the read half ended; keep-alive is over whatever answers"
    );

    let switch =
      b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    assert!(matches!(
      c.handle_response(switch),
      Ok(ClientTunnelOutcome::Switched { .. })
    ));
    assert_eq!(
      c.transport(),
      Transport::HandedOver,
      "the driver was told to close a transport it had just been handed"
    );
  }

  // The CONNECT arm of the same site, which is a separate `TunnelPhase::Switched`
  // writer and so a separate member.
  #[test]
  fn an_eof_before_a_buffered_tunnel_signals_no_close() {
    let mut c = connected();
    c.handle_eof().expect("an EOF on a live handshake");
    assert_eq!(c.transport(), Transport::Ending);
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
      Ok(ClientTunnelOutcome::Tunneled { .. })
    ));
    assert_eq!(
      c.transport(),
      Transport::HandedOver,
      "the tunnel's transport is the driver's"
    );
  }

  // The SERVER's switch site: `accept` writes the phase, so it is a member too.
  #[test]
  fn an_eof_before_accept_signals_no_close() {
    let mut s = asked_to_upgrade();
    s.handle_eof().expect("an EOF on a live handshake");
    assert_eq!(s.transport(), Transport::Ending);
    let mut out = [0u8; 128];
    s.accept(SWITCH, &mut out)
      .expect("the switch still goes out");
    assert_eq!(s.tunnel, TunnelPhase::Switched);
    assert_eq!(
      s.transport(),
      Transport::HandedOver,
      "the driver was told to close what it handed over"
    );
  }

  // Post-switch, `handle_eof` is INERT here rather than invalid — this mode's own
  // contract, already stated and tested: a connection that has left HTTP has
  // nothing to say about the ending. What the invariant requires is only that it
  // does nothing: no latch to rewrite a spent connection, and no notice about a
  // transport already handed over.
  #[test]
  fn a_post_switch_eof_is_inert_in_tunnel_mode() {
    let mut c = offered();
    assert!(matches!(
      c.handle_response(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      ),
      Ok(ClientTunnelOutcome::Switched { .. })
    ));
    let before = c.read_closed;
    c.handle_eof().expect("inert, not invalid");
    assert_eq!(
      c.read_closed, before,
      "a spent connection's state was rewritten"
    );
    assert_eq!(
      c.transport(),
      Transport::HandedOver,
      "a spent connection reported something other than the handover"
    );
  }

  // The FALSE direction in this mode: a handshake that cannot hand over any more
  // must signal at once, exactly as it always did.
  #[test]
  fn an_eof_on_a_refused_handshake_signals_at_once() {
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n"),
      Ok(ClientTunnelOutcome::Refused { .. })
    ));
    c.handle_eof().expect("an EOF after the refusal");
    assert_eq!(c.transport(), Transport::Ending);

    // And one that never opened a handshake at all.
    let mut c = Connection::<Client, Tunnel>::new();
    c.handle_eof().expect("an EOF on an idle connection");
    assert_eq!(c.transport(), Transport::Ending);
  }

  // §9.3.6's tunnel is NOT excluded from the invariant, though reading `close`
  // on a CONNECT 2xx as "no HTTP reuse once the tunnel ends" invites an
  // exemption. RFC 9112 §9.6's text does not support that reading: it defines
  // the option unconditionally as an obligation to "close the connection after
  // reading the response message containing" it, and RFC 9110 §9.3.6 has the
  // same response switching to tunnel mode "immediately after the response
  // header section". One instant, opposite demands — so such a response is a
  // self-contradiction, not a working tunnel, and it is refused exactly as a
  // close-bearing 101 is.
  //
  // All four corners are covered here.
  #[test]
  fn a_connect_takeover_states_no_close_at_every_corner() {
    let mut out = [0xAAu8; 192];

    // ORIGINATE: the request this end writes.
    let closing: &[(&str, &[u8])] = &[("Host", b"example.com:443"), ("Connection", b"close")];
    let mut c = Connection::<Client, Tunnel>::new();
    assert_eq!(
      c.open_connect(DESTINATION, closing, &mut out),
      Err(Error::InvalidState(TAKEOVER_STATES_NO_CLOSE))
    );
    assert_eq!(out, [0xAAu8; 192], "a refused open wrote into the buffer");

    // RECEIVE: the request a server classifies.
    let mut s = Connection::<Server, Tunnel>::new();
    let Err(Error::Protocol(H1Error::Framing(why))) = s.handle_request(
      b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n",
    ) else {
      panic!("a close-bearing CONNECT is no handshake this connection can complete")
    };
    assert_eq!(why, HANDSHAKE_STATES_CLOSE);

    // EMIT: the 2xx this end writes.
    let mut s = asked_for_a_tunnel();
    let mut out = [0xAAu8; 192];
    let closing_2xx: &[(&str, &[u8])] = &[("Connection", b"close")];
    assert_eq!(
      s.accept(closing_2xx, &mut out),
      Err(Error::InvalidState(TAKEOVER_STATES_NO_CLOSE))
    );
    assert_eq!(out, [0xAAu8; 192], "a refused accept wrote into the buffer");
    assert_ne!(s.tunnel, TunnelPhase::Switched, "the phase moved anyway");

    // ACCEPT: the 2xx this end reads.
    let mut c = connected();
    let Err(Error::Protocol(H1Error::Framing(why))) =
      c.handle_response(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
    else {
      panic!("a 2xx that ends persistence is not a tunnel this end can enter")
    };
    assert_eq!(why, SWITCH_AFTER_CLOSE);
    assert_ne!(c.tunnel, TunnelPhase::Switched);
  }

  // `HTTP/1.0 200 Connection Established` is a legal answer to an HTTP/1.1
  // CONNECT and the classic form real proxies send. Reading §9.3's 1.0
  // non-persistence default here latches `Failed` and DISCARDS the tunnel bytes
  // that follow in the same read — so the leftover is what this asserts, not
  // merely the outcome.
  //
  // §9.3.6 establishes the tunnel "immediately after the response header
  // section" whatever version the response states, and response downgrading is
  // permitted. The default governs whether another HTTP MESSAGE may follow, and
  // after this one none can.
  #[test]
  fn an_http_10_connect_2xx_still_tunnels_with_its_leftover() {
    const TEN: &[u8] = b"HTTP/1.0 200 Connection Established\r\n\r\n\x16\x03\x01\x00\x05";
    let mut c = connected();
    let ClientTunnelOutcome::Tunneled { leftover, .. } = c
      .handle_response(TEN)
      .expect("a 1.0 2xx to CONNECT still establishes the tunnel")
    else {
      panic!("a 1.0 2xx to CONNECT must tunnel")
    };
    assert_eq!(
      leftover, b"\x16\x03\x01\x00\x05",
      "the tunnel's first bytes were discarded"
    );
    assert_eq!(c.tunnel, TunnelPhase::Switched);
    assert_eq!(c.transport(), Transport::HandedOver);
  }

  // The FALSE direction for the same head: the option is what the rule reads, so
  // a close-bearing 2xx is refused at EITHER version.
  #[test]
  fn a_connect_2xx_stating_close_is_refused_at_either_version() {
    for wire in [
      b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n".as_slice(),
      b"HTTP/1.0 200 Connection Established\r\nConnection: close\r\n\r\n",
    ] {
      let mut c = connected();
      let Err(Error::Protocol(H1Error::Framing(why))) = c.handle_response(wire) else {
        panic!("a 2xx that states close is not a tunnel this end can enter")
      };
      assert_eq!(why, SWITCH_AFTER_CLOSE);
      assert_ne!(c.tunnel, TunnelPhase::Switched);
    }
  }

  // The INTERIM arm asks `ends_persistence`, and that is the split: a 1xx IS an
  // HTTP message, and another one follows it, so §9.3's 1.0 default means
  // exactly what it says there. The takeover heads above are where it does not.
  #[test]
  fn an_http_10_interim_still_ends_the_handshake() {
    let mut c = connected();
    assert!(matches!(
      c.handle_response(b"HTTP/1.0 100 Continue\r\n\r\n"),
      Ok(ClientTunnelOutcome::Refused { .. })
    ));
    assert_eq!(c.tunnel, TunnelPhase::Refused);
  }

  // The FALSE direction at all four corners, in both roles: a CONNECT without
  // `close` still works exactly as it did.
  #[test]
  fn a_connect_without_close_still_tunnels_at_every_corner() {
    let mut out = [0u8; 192];

    let mut c = Connection::<Client, Tunnel>::new();
    assert!(c.open_connect(DESTINATION, CONNECT_HOST, &mut out).is_ok());

    let mut s = asked_for_a_tunnel();
    let n = s
      .accept(NO_FIELDS, &mut out)
      .expect("the 2xx still goes out");
    assert_eq!(&out[..n], b"HTTP/1.1 200 Connection Established\r\n\r\n");
    assert_eq!(s.tunnel, TunnelPhase::Switched);

    let mut c = connected();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
      Ok(ClientTunnelOutcome::Tunneled { .. })
    ));
    assert_eq!(c.transport(), Transport::HandedOver);

    // And an HTTP/1.0 CONNECT still classifies: §9.3 makes a 1.0 message
    // non-persistent without `keep-alive`, but that peer SAID nothing about
    // closing, and §9.3.6 puts no version on CONNECT. The request side reads the
    // stated option for exactly this reason.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(b"CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:443\r\n\r\n"),
      Ok(ServerTunnelRequest::Connect { .. })
    ));
  }

  // `TunnelPhase::Refused` is TERMINAL and the lifecycle cannot say so — all
  // three writers leave it `Open`. Asserted immediately after each refusal
  // producer, and that placement is the assertion: read AFTER an EOF, every arm
  // answers `Ending` whatever it was going to say, so a wrong arm survives.
  #[test]
  fn a_refused_handshake_reads_ending_at_every_producer() {
    // A client reading an ordinary final refusal.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n"),
      Ok(ClientTunnelOutcome::Refused { .. })
    ));
    assert_eq!(
      c.transport(),
      Transport::Ending,
      "a spent handshake read Live"
    );

    // A client reading a persistence-ending interim.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 100 Continue\r\nConnection: close\r\n\r\n"),
      Ok(ClientTunnelOutcome::Refused { .. })
    ));
    assert_eq!(c.transport(), Transport::Ending);

    // A server that successfully wrote `reject`.
    let mut s = asked_to_upgrade();
    let mut out = [0u8; 128];
    assert!(
      s.reject(426, b"Upgrade Required", NO_FIELDS, &mut out)
        .is_ok()
    );
    assert_eq!(s.tunnel, TunnelPhase::Refused);
    assert_eq!(
      s.transport(),
      Transport::Ending,
      "a spent handshake read Live"
    );
  }

  // The persistence decision is VERSION-AWARE, and Tunnel mode asks the same one
  // General mode does.
  //
  // RFC 9112 §9.3 makes an HTTP/1.0 message non-persistent unless it carries
  // `Connection: keep-alive`, so `HTTP/1.0 100` without one ends the connection
  // exactly as an explicit `close` does — and by §9.6 the peer closes after the
  // response carrying that decision. Reading the `close` option alone answered
  // half the question and left the handshake looking live on a connection that
  // was already over: the driver would wait for a 101 or a CONNECT 2xx that
  // cannot come.
  #[test]
  fn an_http_10_interim_without_keep_alive_ends_the_handshake() {
    // Non-persistent by version alone — no `close` field anywhere in it.
    let mut c = offered();
    let ClientTunnelOutcome::Refused { status, .. } =
      c.handle_response(b"HTTP/1.0 100 \r\n\r\n").unwrap()
    else {
      panic!("an HTTP/1.0 interim without keep-alive ends the handshake")
    };
    assert_eq!(status.code, 100);
    assert_eq!(status.version, Version::Http10);
    // Terminal: the switch the peer might still send is not taken.
    assert!(matches!(
      c.handle_response(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
      ),
      Err(Error::InvalidState(_))
    ));

    // The CONNECT twin.
    let mut c = connected();
    assert!(matches!(
      c.handle_response(b"HTTP/1.0 100 \r\n\r\n").unwrap(),
      ClientTunnelOutcome::Refused { .. }
    ));
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
      Err(Error::InvalidState(_))
    ));

    // …and WITH `keep-alive` the same 1.0 interim is an ordinary interim: §9.3's
    // other half, and the handshake goes on to its switch.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.0 100 \r\nConnection: keep-alive\r\n\r\n")
        .unwrap(),
      ClientTunnelOutcome::Interim { .. }
    ));
    assert!(matches!(
      c.handle_response(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
      )
      .unwrap(),
      ClientTunnelOutcome::Switched { .. }
    ));

    // A 1.0 interim that says BOTH is closed: `close` is the stronger signal.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.0 100 \r\nConnection: keep-alive, close\r\n\r\n")
        .unwrap(),
      ClientTunnelOutcome::Refused { .. }
    ));

    // The 1.1 controls, unchanged: persistent by default, so a plain interim
    // continues the handshake and only the explicit option ends it.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 100 \r\n\r\n").unwrap(),
      ClientTunnelOutcome::Interim { .. }
    ));
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 100 \r\nConnection: close\r\n\r\n")
        .unwrap(),
      ClientTunnelOutcome::Refused { .. }
    ));
  }

  // The tunnel REQUEST side of the same version question, confirmed rather than
  // assumed.
  //
  // An HTTP/1.0 UPGRADE request is not a handshake at all: RFC 9110 §7.8 makes
  // ignoring an `Upgrade` field in a 1.0 request a MUST, which `validate` applies
  // — so `has_upgrade` is false and classification refuses it.
  //
  // An HTTP/1.0 CONNECT is DIFFERENT and is accepted. §9.3.6 puts no version
  // condition on the method, and §9.3's persistence question is moot for it: the
  // connection does not carry another exchange afterwards, it BECOMES the tunnel.
  // What the version still decides there is §15.2's rule, which `send_interim`
  // already enforces — no 1xx to a 1.0 client.
  #[test]
  fn the_request_side_reads_the_version_where_it_matters() {
    let mut s = Connection::<Server, Tunnel>::new();
    let error = s
      .handle_request(
        b"GET /chat HTTP/1.0\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
      )
      .unwrap_err();
    assert_eq!(error.suggested_status(), Some(SuggestedStatus::BadRequest));

    // The 1.0 CONNECT classifies.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(b"CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:443\r\n\r\n"),
      Ok(ServerTunnelRequest::Connect { .. })
    ));
    // …and RFC 9110 §15.2 still refuses it an interim response.
    let mut out = [0xAAu8; 64];
    assert!(matches!(
      s.send_interim(100, NO_FIELDS, &mut out),
      Err(Error::InvalidState(_))
    ));
    assert_eq!(out, [0xAAu8; 64]);
    // The 2xx that establishes it is unaffected by the version.
    assert!(s.accept(NO_FIELDS, &mut out).is_ok());
  }

  // A head is a FAULT or it is not, and which mode is reading it cannot change that.
  //
  // Tunnel decided alone and so accepted heads General condemns. The case
  // replayed below: `HTTP/1.0 100` with `Connection: keep-alive` and
  // `Transfer-Encoding: chunked` — RFC 9112 §6.1 makes a message from a 1.0 peer
  // carrying that field faulty framing "even if a Content-Length is present", so
  // General fails the connection, while Tunnel returned `Interim` and went on
  // parsing subsequent bytes as a live handshake.
  //
  // Both handshakes, because both read responses through the same call.
  #[test]
  fn a_faulty_response_head_is_a_fault_in_tunnel_mode_too() {
    const FAULTY: &[u8] =
      b"HTTP/1.0 100 \r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n";

    for connect in [false, true] {
      let mut c = if connect { connected() } else { offered() };
      let error = c.handle_response(FAULTY).unwrap_err();
      assert!(
        matches!(
          error,
          Error::Protocol(H1Error::Framing(
            "HTTP/1.0 message carries Transfer-Encoding"
          ))
        ),
        "connect={connect}: {error:?}"
      );
      // Latched: no further byte of this connection is read as a handshake.
      assert!(
        matches!(
          c.handle_response(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
          ),
          Err(Error::InvalidState(_))
        ),
        "connect={connect}"
      );
    }

    // The GENERAL twin fails identically — same head, same constant.
    let mut g = Connection::<Client, General>::new();
    open_bodiless_request(&mut g, "GET");
    let error = {
      let mut it = g.handle(FAULTY);
      it.next().expect_err("§6.1 condemns this head")
    };
    assert!(matches!(
      error,
      Error::Protocol(H1Error::Framing(
        "HTTP/1.0 message carries Transfer-Encoding"
      ))
    ));

    // Split and re-offer: the fault is a property of the head, so where the
    // transport cut it cannot change the answer.
    for cut in 1..FAULTY.len() {
      let mut c = offered();
      assert!(matches!(
        c.handle_response(FAULTY.get(..cut).unwrap()).unwrap(),
        ClientTunnelOutcome::NeedMore
      ));
      assert!(c.handle_response(FAULTY).is_err(), "cut {cut}");
    }
  }

  // Each newly shared condemnation, exercised through the tunnel path — and each
  // paired with the head that is the same shape but LEGAL, so the check is
  // pinned as a rule rather than as a refusal of anything unusual.
  #[test]
  fn the_tunnel_applies_every_shared_response_head_check() {
    for (name, head) in [
      // RFC 9112 §6.3 item 3: both framing fields on a response items 1-2 did
      // not make bodiless.
      (
        "both framing fields",
        b"HTTP/1.1 426 Upgrade Required\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
          .as_slice(),
      ),
      // Items 5-6: a length that does not parse, and two that disagree.
      (
        "a length that is not 1*DIGIT",
        b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: three\r\n\r\n",
      ),
      (
        "two lengths that disagree",
        b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
      ),
      // §6.1 on a final response as well as on the interim above.
      (
        "an HTTP/1.0 response carrying a transfer coding",
        b"HTTP/1.0 426 Upgrade Required\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n",
      ),
    ] {
      let mut c = offered();
      assert!(
        c.handle_response(head).is_err(),
        "{name}: accepted a condemned head"
      );
    }

    // And the exemptions travel too. Items 1-2 answer "regardless of the header
    // fields present in the message", so the SAME field pair on a bodiless
    // status is ignored rather than condemning: a 1xx, and a 2xx to CONNECT,
    // which §9.3.6 makes a client MUST ignore.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(
        b"HTTP/1.1 100 \r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
      )
      .unwrap(),
      ClientTunnelOutcome::Interim { .. }
    ));
    let mut c = connected();
    assert!(matches!(
      c.handle_response(
        b"HTTP/1.1 200 Connection Established\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n"
      )
      .unwrap(),
      ClientTunnelOutcome::Tunneled { .. }
    ));

    // A legal HTTP/1.1 interim with keep-alive is untouched by any of it.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 100 \r\nConnection: keep-alive\r\n\r\n")
        .unwrap(),
      ClientTunnelOutcome::Interim { .. }
    ));
    assert!(matches!(
      c.handle_response(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
      )
      .unwrap(),
      ClientTunnelOutcome::Switched { .. }
    ));
  }

  // The REQUEST-side mirror, confirmed rather than assumed: `classify` runs
  // `validate_request` IN FULL before it classifies anything, so every
  // mode-independent request-head fault is already one shared check — the §3.2
  // `Host` rules, the §3.2.3/§3.2.4 target-method pairing, and the §6.3 framing
  // faults alike.
  //
  // What is Tunnel's own is cited where it is refused — §9.3.6: "A CONNECT
  // request message does not have content" (and no message this mode writes has
  // one), and §3.2.3's port. Those are rules about the HANDSHAKE, not about the
  // head, so they are properly mode-specific.
  #[test]
  fn the_tunnel_applies_every_shared_request_head_check() {
    for (name, head) in [
      ("no Host", b"GET /c HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice()),
      (
        "two Host lines",
        b"GET /c HTTP/1.1\r\nHost: a\r\nHost: b\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
      ),
      (
        "an invalid Host value",
        b"GET /c HTTP/1.1\r\nHost: bad host\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
      ),
      (
        "an asterisk target from a method that is not OPTIONS",
        b"GET * HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
      ),
      (
        "both framing fields",
        b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
      ),
      (
        "a length that is not 1*DIGIT",
        b"POST /c HTTP/1.1\r\nHost: h\r\nContent-Length: three\r\n\r\n",
      ),
      (
        "an HTTP/1.0 request carrying a transfer coding",
        b"POST /c HTTP/1.0\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
      ),
    ] {
      let mut s = Connection::<Server, Tunnel>::new();
      assert!(
        s.handle_request(head).is_err(),
        "{name}: classified a condemned head"
      );
    }
  }

  // A `#`-list field is ONE list however many lines carried it (RFC 9110 §5.2),
  // so a question about the LIST can only be asked of the combined value.
  //
  // `Upgrade:` followed by `Upgrade: websocket` combines to `, websocket`.
  // §5.6.1.2 makes that valid outright — its own examples give
  // `"foo , ,bar,charlie"` as a legal `1#element` and only `""`, `","` and
  // `",   ,"` as invalid, "since at least one non-empty element is required" —
  // and empty elements "MUST parse and ignore". Asking each LINE to satisfy the
  // whole grammar split one list into two and failed the first.
  #[test]
  fn an_upgrade_list_is_read_from_its_combined_value() {
    // The REQUEST direction: a server classifies the offer.
    const OFFER: &[u8] =
      b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: \r\nUpgrade: websocket\r\n\r\n";
    let mut s = Connection::<Server, Tunnel>::new();
    let Ok(ServerTunnelRequest::Upgrade { head, .. }) = s.handle_request(OFFER) else {
      panic!("an empty element beside a protocol is a valid list")
    };
    // Both lines are still surfaced verbatim: §5.2's combining is a reading, not
    // a rewrite.
    let mut lines = head.header_all("upgrade");
    assert_eq!(lines.next(), Some(b"".as_slice()));
    assert_eq!(lines.next(), Some(b"websocket".as_slice()));

    // The RESPONSE direction: a client reads the 101 built the same way.
    const SWITCH: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: \r\nUpgrade: websocket\r\n\r\nGO";
    let mut c = offered();
    let ClientTunnelOutcome::Switched { leftover, .. } = c.handle_response(SWITCH).unwrap() else {
      panic!("a 101 whose Upgrade spans two lines still switches")
    };
    assert_eq!(leftover, b"GO");

    // Split and re-offer: the list is a property of the head, not of the read,
    // so every cut through it reaches the same switch.
    let head_end = SWITCH.len().saturating_sub(b"GO".len());
    for cut in 1..head_end {
      let mut c = offered();
      assert!(
        matches!(
          c.handle_response(SWITCH.get(..cut).unwrap()).unwrap(),
          ClientTunnelOutcome::NeedMore
        ),
        "cut {cut}: a partial head is not a switch"
      );
      assert!(
        matches!(
          c.handle_response(SWITCH).unwrap(),
          ClientTunnelOutcome::Switched { .. }
        ),
        "cut {cut}"
      );
    }
  }

  // The boundaries of that tolerance, which the same combined reading decides.
  #[test]
  fn a_combined_upgrade_list_still_has_to_name_a_protocol() {
    // ALL elements empty across every line: §5.6.1.2's `","` case — no protocol
    // is named, so it is not an offer at all and §7.8 lets a server ignore it.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: \r\nUpgrade: ,\r\n\r\n"
      )
      .is_err(),
      "a list of nothing but empty elements names no protocol"
    );
    let mut c = offered();
    assert!(
      c.handle_response(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: \r\nUpgrade: ,\r\n\r\n"
      )
      .is_err(),
      "§15.2.2 makes the field a MUST, and an empty list states nothing"
    );

    // A malformed NON-empty element still fails the list, whichever line it is
    // on — §5.6.1.2 tolerates empty elements, not bad ones.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUpgrade: bad protocol\r\n\r\n"
      )
      .is_err()
    );
    let mut c = offered();
    assert!(
      c.handle_response(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: bad protocol\r\nUpgrade: websocket\r\n\r\n"
      )
      .is_err()
    );
  }

  // THE ASYMMETRY, and it is normative rather than a compromise: RFC 9110
  // §5.6.1.1 and §5.6.1.2 are adjacent sections stating opposite MUSTs for the
  // two roles. A recipient "MUST parse and ignore a reasonable number of empty
  // list elements"; a sender "MUST NOT generate empty list elements".
  //
  // So this core accepts on the way in exactly what it refuses on the way out.
  #[test]
  fn a_sender_may_not_generate_the_empty_element_a_recipient_tolerates() {
    let mut out = [0xAAu8; 192];
    let with_empty: &[(&str, &[u8])] = &[
      ("Host", b"h"),
      ("Connection", b"Upgrade"),
      ("Upgrade", b""),
      ("Upgrade", b"websocket"),
    ];
    let mut c = Connection::<Client, Tunnel>::new();
    assert_eq!(
      c.open_upgrade(&CHAT, with_empty, &mut out),
      Err(Error::InvalidState(SENDER_LIST_EMPTY_ELEMENT)),
      "§5.6.1.1: a sender does not generate an empty list element"
    );
    assert_eq!(out, [0xAAu8; 192]);

    // The same refusal on the server's 101 — which needs an UPGRADE handshake,
    // since a CONNECT's 2xx names no protocol and never asks.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      )
      .unwrap(),
      ServerTunnelRequest::Upgrade { .. }
    ));
    let switch_with_empty: &[(&str, &[u8])] = &[
      ("Connection", b"Upgrade"),
      ("Upgrade", b""),
      ("Upgrade", b"websocket"),
    ];
    assert_eq!(
      s.accept(switch_with_empty, &mut out),
      Err(Error::InvalidState(SENDER_LIST_EMPTY_ELEMENT))
    );
    // …and the same server still switches with a single well-formed line.
    let ok: &[(&str, &[u8])] = &[("Connection", b"Upgrade"), ("Upgrade", b"websocket")];
    assert!(s.accept(ok, &mut out).is_ok());

    // …and two well-formed lines are fine in both directions: what §5.6.1.1
    // forbids is the EMPTY element, not the second line.
    let mut c = Connection::<Client, Tunnel>::new();
    let two_lines: &[(&str, &[u8])] = &[
      ("Host", b"h"),
      ("Connection", b"Upgrade"),
      ("Upgrade", b"websocket"),
      ("Upgrade", b"h2c"),
    ];
    assert!(c.open_upgrade(&CHAT, two_lines, &mut out).is_ok());
  }

  // RFC 9110 §7.8 (the offer) and §15.2.2 (the 101 that answers it): "the data
  // stream switches to [the new protocol]" immediately after that head, so the
  // bytes behind it are handed over verbatim rather than parsed as HTTP.
  #[test]
  fn client_upgrade_switches_and_hands_the_leftover_over() {
    let mut c = offered();
    const RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x03abc";

    let ClientTunnelOutcome::Switched { head, leftover } = c.handle_response(RESPONSE).unwrap()
    else {
      panic!("expected a switch")
    };
    assert_eq!(head.header("upgrade"), Some(b"websocket".as_slice()));
    assert_eq!(leftover, b"\x81\x03abc");
    // Terminal: the stream belongs to the next protocol, so this connection has
    // nothing more to say about any byte on it.
    assert!(matches!(
      c.handle_response(leftover),
      Err(Error::InvalidState(_))
    ));
  }

  // RFC 9112 §2.1: a message begins with a complete head, so every prefix of one
  // is need-more and consumes NOTHING — the leftover is measured from the head's
  // end and from nowhere else, whatever the read boundaries were.
  #[test]
  fn a_partial_response_head_consumes_nothing() {
    const RESPONSE: &[u8] =
      b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nXY";
    let end = RESPONSE.len().saturating_sub(2);
    let mut c = offered();
    for n in 0..end {
      assert!(
        matches!(
          c.handle_response(RESPONSE.get(..n).unwrap()).unwrap(),
          ClientTunnelOutcome::NeedMore
        ),
        "prefix {n}"
      );
    }
    let ClientTunnelOutcome::Switched { leftover, .. } = c.handle_response(RESPONSE).unwrap()
    else {
      panic!("expected a switch")
    };
    assert_eq!(leftover, b"XY");
  }

  // RFC 9110 §7.8: "A server MAY ignore a received Upgrade header field if it
  // wishes to continue using the current protocol on that connection. Upgrade
  // cannot be used to insist on a protocol change." Any final response that is
  // not a 101 is therefore an ordinary answer, and this connection — which
  // exists to complete ONE switch — is over.
  #[test]
  fn client_upgrade_refused_by_a_final_response_is_terminal() {
    let mut c = offered();
    const RESPONSE: &[u8] = b"HTTP/1.1 426 Upgrade Required\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n";
    let ClientTunnelOutcome::Refused {
      head,
      status,
      leftover,
    } = c.handle_response(RESPONSE).unwrap()
    else {
      panic!("expected a refusal")
    };
    assert_eq!(head.header("upgrade"), Some(b"websocket".as_slice()));
    // WHY it refused is the caller's next move: RFC 9110 §15.5.22's 426 asks for
    // a different protocol, which is not what a 401 or a 403 asks for — so the
    // status-line this core already parsed travels with the head.
    assert_eq!(status.code, 426);
    assert_eq!(status.reason, b"Upgrade Required".as_slice());
    // `Content-Length: 0` announces no octets, so the head is the whole message.
    assert_eq!(leftover, b"");
    assert!(matches!(
      c.handle_response(RESPONSE),
      Err(Error::InvalidState(_))
    ));

    // The same for a plain 200: the server answered the GET instead of switching.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        .unwrap(),
      ClientTunnelOutcome::Refused { .. }
    ));
  }

  // A refusal reports its leftover like every other outcome that consumed a head
  // — the reason being the one RFC 9110 §11.7 states: a `407` "MUST send a
  // Proxy-Authenticate header field … containing at least one challenge", and a
  // client that means to retry with credentials reads the challenge and usually
  // the content beside it. Without the leftover a caller holding a complete
  // response in one read could not say where that content began, since the head
  // codec that would tell it is crate-private.
  //
  // The leftover is the head-end SUFFIX, verbatim, under every §6.3 delimitation
  // a refusal can carry — this core reports where the content STARTS and never
  // where it ends, which stays the caller's reading of the head.
  #[test]
  fn a_refusal_hands_over_the_bytes_behind_its_head() {
    // Item 6: a counted body, with the count in the head the caller was handed.
    let mut c = connected();
    let outcome = c
      .handle_response(
        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 5\r\n\r\nnope!",
      )
      .unwrap();
    let ClientTunnelOutcome::Refused {
      head,
      status,
      leftover,
    } = outcome
    else {
      panic!("expected a refusal")
    };
    assert_eq!(status.code, 407);
    assert_eq!(
      head.header("proxy-authenticate"),
      Some(b"Basic realm=\"p\"".as_slice())
    );
    assert_eq!(head.header("content-length"), Some(b"5".as_slice()));
    assert_eq!(leftover, b"nope!");

    // Item 4: a chunked body. The framing lines are IN the leftover — this core
    // decodes nothing here, so what it hands over is the wire bytes.
    let mut c = offered();
    let ClientTunnelOutcome::Refused { leftover, .. } = c
      .handle_response(
        b"HTTP/1.1 426 Upgrade Required\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwhy?\r\n0\r\n\r\n",
      )
      .unwrap()
    else {
      panic!("expected a refusal")
    };
    assert_eq!(leftover, b"4\r\nwhy?\r\n0\r\n\r\n");

    // Item 8: neither framing field, so the body is whatever arrives before the
    // close. The leftover is what arrived in THIS offer, which is exactly the
    // contract — a suffix of the bytes handed in, not a framed message.
    let mut c = offered();
    let ClientTunnelOutcome::Refused { leftover, .. } = c
      .handle_response(b"HTTP/1.1 403 Forbidden\r\n\r\nno tunnel for you")
      .unwrap()
    else {
      panic!("expected a refusal")
    };
    assert_eq!(leftover, b"no tunnel for you");

    // And a head that has not all arrived still consumes nothing: the refusal
    // path does not report a leftover for a message it has not delimited.
    let mut c = offered();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 403 Forbidden\r\nX: ").unwrap(),
      ClientTunnelOutcome::NeedMore
    ));
  }

  // RFC 9110 §15.2: "A client MUST be able to parse one or more 1xx responses
  // received prior to a final response" — an interim head is consumed and the
  // switch is still to come, so the outcome says where the next head begins.
  #[test]
  fn client_reads_interim_responses_before_the_switch() {
    let mut c = offered();
    const RESPONSE: &[u8] = b"HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGO";

    let ClientTunnelOutcome::Interim {
      head,
      status,
      leftover,
    } = c.handle_response(RESPONSE).unwrap()
    else {
      panic!("expected an interim response")
    };
    assert_eq!(head.field_count(), 0);
    // WHICH interim arrived is readable without re-parsing the start line: §15.2
    // lets any number of them precede the final answer, so the code is the only
    // thing that tells two of them apart.
    assert_eq!(status.code, 102);
    assert_eq!(status.reason, b"Processing");
    let ClientTunnelOutcome::Switched { leftover, .. } = c.handle_response(leftover).unwrap()
    else {
      panic!("expected a switch")
    };
    assert_eq!(leftover, b"GO");
  }

  // RFC 9110 §9.3.6: "Any 2xx (Successful) response indicates that the sender
  // (and all inbound proxies) will switch to tunnel mode immediately after the
  // response header section", and "A client MUST ignore any Content-Length or
  // Transfer-Encoding header fields received in a successful response to
  // CONNECT" — the octets behind the head are the tunnel's, not a body's.
  #[test]
  fn client_connect_tunnels_after_a_2xx() {
    let mut c = connected();
    const RESPONSE: &[u8] =
      b"HTTP/1.1 200 Connection Established\r\nContent-Length: 5\r\n\r\n\x16\x03\x01\x00\x05";
    let ClientTunnelOutcome::Tunneled {
      head,
      status,
      leftover,
    } = c.handle_response(RESPONSE).unwrap()
    else {
      panic!("expected a tunnel")
    };
    assert_eq!(head.header("content-length"), Some(b"5".as_slice()));
    // §9.3.6 admits "any 2xx", so WHICH one established the tunnel travels with
    // the outcome rather than being lost with the start line.
    assert_eq!(status.code, 200);
    assert_eq!(status.reason, b"Connection Established");
    assert_eq!(leftover, b"\x16\x03\x01\x00\x05");
    assert!(matches!(
      c.handle_response(leftover),
      Err(Error::InvalidState(_))
    ));
  }

  // RFC 9110 §9.3.6: "Any response other than a successful response indicates
  // that the tunnel has not yet been formed."
  #[test]
  fn client_connect_refused_by_a_non_2xx() {
    let mut c = connected();
    assert!(matches!(
      c.handle_response(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
        .unwrap(),
      ClientTunnelOutcome::Refused { .. }
    ));
  }

  // RFC 9110 §7.8: a 101's sender "MUST send an Upgrade header field to indicate
  // the new protocol(s)" and "MUST also send an `Upgrade` connection option in
  // the Connection header field". A 101 that states neither is a switch to a
  // protocol this end cannot name — the connection is latched, since every byte
  // after that head would be read under a protocol nobody agreed on.
  #[test]
  fn a_101_that_names_no_protocol_is_a_violation() {
    for bad in [
      b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".as_slice(),
      b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n",
      b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: web socket\r\n\r\n",
    ] {
      let mut c = offered();
      let error = c.handle_response(bad).unwrap_err();
      assert_eq!(
        error,
        Error::Protocol(H1Error::Framing(SWITCH_NEEDS_BOTH_HALVES)),
        "{bad:?}"
      );
      assert_eq!(error.suggested_status(), Some(SuggestedStatus::BadRequest));
      // Latched: the violation is handed back exactly once.
      assert!(
        matches!(c.handle_response(bad), Err(Error::InvalidState(_))),
        "{bad:?}"
      );
    }
  }

  // RFC 9110 §7.8: "A server MUST NOT switch to a protocol that was not
  // indicated by the client in the corresponding request's Upgrade header
  // field" — a CONNECT names none, so a 101 answering one is a switch this end
  // never offered.
  //
  // "A CONNECT names none" is ENFORCED, not assumed —
  // `a_connect_indicates_no_protocol` is the guard that makes it so. Delete that
  // guard and this verdict becomes reachable against a server that switched on
  // an `Upgrade` field this end itself wrote — blaming a peer for acting on our
  // own bytes.
  #[test]
  fn a_101_to_a_connect_is_a_switch_that_was_never_offered() {
    let mut c = connected();
    assert_eq!(
      c.handle_response(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
      )
      .unwrap_err(),
      Error::Protocol(H1Error::Framing(SWITCH_WAS_NEVER_OFFERED))
    );
  }

  // The send-side half of the rule above. A CONNECT already states RFC 9110
  // §9.3.6's takeover; an `Upgrade` field on it invites §7.8's as well, and this
  // handshake has no answer that could carry one — `ClientTunnelOutcome` makes a
  // CONNECT's success the 2xx tunnel, and the test above condemns the 101. So
  // the request that would create the contradiction is refused before a byte.
  //
  // Both spellings are refused, and the SECOND is the point: the predicate is
  // §7.8's INDICATION — the `Upgrade` field alone, which is what a server may
  // legally act on — not both halves of an offer. A both-halves predicate would
  // pass the un-optioned field straight through to the wire.
  #[test]
  fn a_connect_indicates_no_protocol() {
    let both: &[(&str, &[u8])] = &[
      ("Host", b"example.com:443"),
      ("Connection", b"Upgrade"),
      ("Upgrade", b"websocket"),
    ];
    let field_only: &[(&str, &[u8])] = &[("Host", b"example.com:443"), ("Upgrade", b"websocket")];

    for headers in [both, field_only] {
      let mut out = [0xAAu8; 128];
      let mut c = Connection::<Client, Tunnel>::new();
      assert_eq!(
        c.open_connect(DESTINATION, headers, &mut out),
        Err(Error::InvalidState(CONNECT_INDICATES_NO_PROTOCOL)),
        "{headers:?}: a CONNECT indicates no protocol"
      );
      assert_eq!(out, [0xAAu8; 128], "a refused open wrote into the buffer");
      // Inert: the handshake never began, so an ordinary CONNECT still opens it.
      assert!(c.open_connect(DESTINATION, CONNECT_HOST, &mut out).is_ok());
    }

    // The connection option ALONE names no protocol, so it indicates nothing and
    // this stays an ordinary CONNECT — the same asymmetry `open_request` keeps.
    let option_only: &[(&str, &[u8])] = &[("Host", b"example.com:443"), ("Connection", b"Upgrade")];
    let mut out = [0u8; 128];
    let mut c = Connection::<Client, Tunnel>::new();
    assert!(
      c.open_connect(DESTINATION, option_only, &mut out).is_ok(),
      "the option alone is not an indication"
    );
  }

  // RFC 9110 §10.1.1: "A client MUST NOT generate a 100-continue expectation in
  // a request that does not include content." Neither request this mode writes
  // has content — §9.3.6 says so of CONNECT in as many words, and the upgrade
  // offer this core writes is a bodiless GET — so on both paths the expectation
  // asks for a `100 Continue` that nothing would follow, and the exchange would
  // stall on an interim response the server has no reason to send.
  //
  // Here rather than only in the outbound corpus because the rule is applied by
  // ONE routine that all three request paths call, and these are the two the
  // corpus reaches through a different mode.
  #[test]
  fn a_handshake_request_asks_for_no_continue_it_has_no_content_for() {
    let asking: &[(&str, &[u8])] = &[
      ("Host", b"h"),
      ("Connection", b"Upgrade"),
      ("Upgrade", b"websocket"),
      ("Expect", b"100-continue"),
    ];
    let mut out = [0xAAu8; 160];
    let mut c = Connection::<Client, Tunnel>::new();
    assert_eq!(
      c.open_upgrade(&CHAT, asking, &mut out),
      Err(Error::InvalidState(CONTINUE_NEEDS_CONTENT))
    );
    assert_eq!(out, [0xAAu8; 160]);

    let mut c = Connection::<Client, Tunnel>::new();
    assert_eq!(
      c.open_connect(
        "example.com:443",
        &[
          ("Host", b"example.com:443".as_slice()),
          ("Expect", b"100-continue")
        ][..],
        &mut out
      ),
      Err(Error::InvalidState(CONTINUE_NEEDS_CONTENT))
    );
    assert_eq!(out, [0xAAu8; 160]);

    // The twin: an expectation §10.1.1 does not define carries no such ask, so
    // it is the caller's field to send and this core writes it through.
    let mut c = Connection::<Client, Tunnel>::new();
    let other: &[(&str, &[u8])] = &[
      ("Host", b"h"),
      ("Connection", b"Upgrade"),
      ("Upgrade", b"websocket"),
      ("Expect", b"vendor-thing"),
    ];
    let n = c.open_upgrade(&CHAT, other, &mut out).unwrap();
    assert_eq!(
      &out[..n],
      b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nExpect: vendor-thing\r\n\r\n"
    );
  }

  // RFC 9110 §15.2: "Since HTTP/1.0 did not define any 1xx status codes, a
  // server MUST NOT send a 1xx response to an HTTP/1.0 client." A CONNECT is the
  // one handshake a 1.0 peer can still make — §7.8 makes a 1.0 `Upgrade` field a
  // MUST-ignore — so it is where the rule bites in Tunnel mode.
  #[test]
  fn an_interim_response_is_refused_to_an_http_10_client() {
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(b"CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:443\r\n\r\n")
        .unwrap(),
      ServerTunnelRequest::Connect { .. }
    ));
    let mut out = [0u8; 64];
    let none: &[(&str, &[u8])] = &[];
    assert_eq!(
      s.send_interim(100, none, &mut out),
      Err(Error::InvalidState(INTERIM_NEEDS_HTTP_11))
    );
    // The switch itself is version-agnostic: RFC 9110 §9.3.6 puts no version on
    // CONNECT, and RFC 9112 §2.3 makes the version in a response this end's own.
    let n = s.accept(none, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 200 Connection Established\r\n\r\n");
  }

  // RFC 9110 §7.8's two halves, checked on the way OUT: an offer that states one
  // without the other asks for a switch no conformant server will make, and a
  // protocol name that is not a `token` names nothing at all
  // (`protocol = protocol-name ["/" protocol-version]`).
  #[test]
  fn an_upgrade_offer_states_both_halves() {
    for bad in [
      &[("Host", b"h".as_slice()), ("Upgrade", b"websocket")][..],
      &[("Host", b"h"), ("Connection", b"Upgrade")],
      &[("Host", b"h"), ("Connection", b"close"), ("Upgrade", b"ws")],
    ] {
      let mut out = [0xAAu8; 128];
      let mut c = Connection::<Client, Tunnel>::new();
      assert_eq!(
        c.open_upgrade(&CHAT, bad, &mut out),
        Err(Error::InvalidState(OFFER_NEEDS_BOTH_HALVES)),
        "{bad:?}"
      );
      // Nothing was written, so nothing was sent: the refusal costs the caller
      // only the call — the handshake has not begun, and a corrected offer opens
      // it.
      assert_eq!(out, [0xAAu8; 128]);
      assert!(c.open_upgrade(&CHAT, OFFER, &mut out).is_ok(), "{bad:?}");
    }

    // A section that states both halves BADLY is refused for what is actually
    // wrong with it — the `Upgrade` value is not §7.8's `#protocol` — rather
    // than for a half it did state. The offer question is asked of a value that
    // parsed, so it is never the one a malformed value answers.
    let mut out = [0xAAu8; 128];
    let malformed: &[(&str, &[u8])] = &[
      ("Host", b"h"),
      ("Connection", b"Upgrade"),
      ("Upgrade", b"web socket"),
    ];
    let mut c = Connection::<Client, Tunnel>::new();
    assert_eq!(
      c.open_upgrade(&CHAT, malformed, &mut out),
      Err(Error::InvalidState(FIELD_STATES_ITS_GRAMMAR))
    );
    assert_eq!(out, [0xAAu8; 128]);
    assert!(c.open_upgrade(&CHAT, OFFER, &mut out).is_ok());
  }

  // RFC 9112 §3.2.3 ("The authority-form of request-target is only used for
  // CONNECT requests") and §3.2.4 (the asterisk-form is the server-wide OPTIONS
  // request's): an upgrade offer is a GET, so neither form addresses anything it
  // could be answered for.
  #[test]
  fn an_upgrade_offer_takes_an_origin_or_absolute_target() {
    let mut out = [0u8; 128];
    for bad in [
      Target::Authority {
        host_port: DESTINATION,
      },
      Target::Asterisk,
    ] {
      let mut c = Connection::<Client, Tunnel>::new();
      assert_eq!(
        c.open_upgrade(&bad, OFFER, &mut out),
        Err(Error::InvalidState(SWITCH_TARGET_FORM)),
        "{bad:?}"
      );
    }
    let mut c = Connection::<Client, Tunnel>::new();
    assert!(
      c.open_upgrade(
        &Target::Absolute {
          uri: "http://example.com/chat"
        },
        OFFER,
        &mut out
      )
      .is_ok()
    );
  }

  // RFC 9110 §9.3.6: "A CONNECT request message does not have content", and an
  // upgrade offer this core writes has none either — it has no body machinery in
  // Tunnel mode, so a head announcing octets would leave the peer waiting for
  // bytes that never come (RFC 9112 §6.3 item 6).
  #[test]
  fn a_tunnel_handshake_request_carries_no_content() {
    let mut out = [0u8; 128];
    let counted: &[(&str, &[u8])] = &[
      ("Host", b"example.com"),
      ("Connection", b"Upgrade"),
      ("Upgrade", b"websocket"),
      ("Content-Length", b"5"),
    ];
    let mut c = Connection::<Client, Tunnel>::new();
    assert_eq!(
      c.open_upgrade(&CHAT, counted, &mut out),
      Err(Error::InvalidState(HANDSHAKE_HAS_NO_CONTENT))
    );

    let chunked: &[(&str, &[u8])] = &[
      ("Host", b"example.com:443"),
      ("Transfer-Encoding", b"chunked"),
    ];
    let mut c = Connection::<Client, Tunnel>::new();
    assert_eq!(
      c.open_connect(DESTINATION, chunked, &mut out),
      Err(Error::InvalidState(HANDSHAKE_HAS_NO_CONTENT))
    );

    // `Content-Length: 0` says the same thing this core is about to do, so it is
    // the one framing field a handshake head may carry.
    let mut c = Connection::<Client, Tunnel>::new();
    let zero: &[(&str, &[u8])] = &[("Host", b"example.com:443"), ("Content-Length", b"0")];
    assert!(c.open_connect(DESTINATION, zero, &mut out).is_ok());
  }

  // RFC 9112 §3.2's client MUST reaches Tunnel mode too: both handshakes write
  // an HTTP/1.1 request, and §3.2.3's authority-form target is CONNECT's
  // addressing rule rather than an exemption from the field (RFC 9110 §7.2
  // wants the authority stated in both places).
  #[test]
  fn a_handshake_request_states_its_host() {
    let mut out = [0xAAu8; 128];

    // The offer states both §7.8 halves and still owes the field.
    let hostless: &[(&str, &[u8])] = &[("Connection", b"Upgrade"), ("Upgrade", b"websocket")];
    let mut c = Connection::<Client, Tunnel>::new();
    assert_eq!(
      c.open_upgrade(&CHAT, hostless, &mut out),
      Err(Error::InvalidState(REQUEST_NEEDS_HOST))
    );
    assert_eq!(out, [0xAAu8; 128]);
    // The handshake has not begun, so a corrected offer still opens it.
    assert!(c.open_upgrade(&CHAT, OFFER, &mut out).is_ok());

    // CONNECT names its destination in the target, and owes the field anyway.
    // A fresh destination buffer, since the accepted offer above wrote into the
    // first one and the untouched-ness below is the point.
    let mut out = [0xAAu8; 128];
    let mut c = Connection::<Client, Tunnel>::new();
    assert_eq!(
      c.open_connect(DESTINATION, NO_FIELDS, &mut out),
      Err(Error::InvalidState(REQUEST_NEEDS_HOST))
    );
    assert_eq!(out, [0xAAu8; 128]);
    assert!(c.open_connect(DESTINATION, CONNECT_HOST, &mut out).is_ok());

    // The empty value §3.2 asks for when the target authority is undefined is
    // the field, on this path as on the General one.
    let empty: &[(&str, &[u8])] = &[
      ("Host", b""),
      ("Connection", b"Upgrade"),
      ("Upgrade", b"websocket"),
    ];
    let mut c = Connection::<Client, Tunnel>::new();
    let n = c
      .open_upgrade(&CHAT, empty, &mut out)
      .expect("an empty Host is the field RFC 9112 §3.2 asks for");
    assert_eq!(
      &out[..n],
      b"GET /chat HTTP/1.1\r\nHost: \r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    );
  }

  // RFC 9112 §3.2.3 `authority-form = uri-host ":" port` with RFC 9110 §9.3.6:
  // "There is no default port; a client MUST send the port number even if the
  // CONNECT request is based on a URI reference that contains an authority
  // component with an elided port", and "A server MUST reject a CONNECT request
  // that targets an empty or invalid port number".
  //
  // "Invalid" is enforced as well as "empty", and in BOTH directions: RFC 3986
  // §3.2.3 spells `port = *DIGIT` because a URI scheme decides what its port
  // means, while here it is the TCP port of the tunnel's far end — so a number
  // past 65535 addresses nothing, and `0` is the kernel's "choose one for me"
  // rather than a destination a peer can be asked to reach.
  #[test]
  fn a_connect_target_states_its_port() {
    let mut out = [0u8; 128];
    for bad in [
      // Empty, in every spelling: absent, present-but-blank, and an IP-literal
      // with nothing behind its `]`.
      "example.com",
      "example.com:",
      "[::1]",
      "[::1]:",
      // Invalid: one past the 16-bit range, far past it, and a digit string no
      // integer holds. None of these is refused by the RFC 3986 grammar.
      "example.com:65536",
      "example.com:99999",
      "example.com:184467440737095516160",
      "[::1]:65536",
      // Invalid: port zero, which is a well-formed u16 and not a destination.
      "example.com:0",
      "example.com:00000",
      "[::1]:0",
    ] {
      let mut c = Connection::<Client, Tunnel>::new();
      assert_eq!(
        c.open_connect(bad, CONNECT_HOST, &mut out),
        Err(Error::InvalidState(CONNECT_NEEDS_A_PORT)),
        "{bad}"
      );
      assert!(
        c.open_connect("example.com:443", CONNECT_HOST, &mut out)
          .is_ok(),
        "{bad}: a refused open spent the handshake"
      );
    }
    // The whole 16-bit range is a port, leading zeros included (`1*DIGIT` takes
    // them, so `00080` is 80 and no number of them overflows).
    for good in ["example.com:1", "example.com:65535", "example.com:00080"] {
      let mut c = Connection::<Client, Tunnel>::new();
      assert!(
        c.open_connect(good, CONNECT_HOST, &mut out).is_ok(),
        "{good}"
      );
    }

    // The server half of the same rule, answered with the 400 §9.3.6 suggests —
    // and it is the same classifier, so it refuses the same set.
    for bad in [
      b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
      b"CONNECT example.com: HTTP/1.1\r\nHost: example.com\r\n\r\n",
      b"CONNECT example.com:65536 HTTP/1.1\r\nHost: example.com\r\n\r\n",
      b"CONNECT example.com:184467440737095516160 HTTP/1.1\r\nHost: example.com\r\n\r\n",
      b"CONNECT example.com:0 HTTP/1.1\r\nHost: example.com\r\n\r\n",
      b"CONNECT [::1]:65536 HTTP/1.1\r\nHost: [::1]\r\n\r\n",
    ] {
      let mut s = Connection::<Server, Tunnel>::new();
      let error = s.handle_request(bad).unwrap_err();
      assert_eq!(
        error.suggested_status(),
        Some(SuggestedStatus::BadRequest),
        "{:?}",
        core::str::from_utf8(bad)
      );
    }
    // …and classifies 65535, which is one below the first refusal.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(b"CONNECT example.com:65535 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
      Ok(ServerTunnelRequest::Connect { .. })
    ));

    // An IPv6 literal's own colons are the address's, not a port's.
    let mut c = Connection::<Client, Tunnel>::new();
    let host: &[(&str, &[u8])] = &[("Host", b"[::1]:443")];
    let n = c.open_connect("[::1]:443", host, &mut out).unwrap();
    assert_eq!(
      &out[..n],
      b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n"
    );
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(b"CONNECT [::1]:65535 HTTP/1.1\r\nHost: [::1]:65535\r\n\r\n"),
      Ok(ServerTunnelRequest::Connect { .. })
    ));
  }

  // RFC 9110 §7.8 with RFC 9112 §9.3.2: a tunnel completes ONE handshake, so a
  // response nobody asked for — and a second request on a connection that has
  // already classified one — are both caller-side misuse.
  #[test]
  fn a_tunnel_carries_exactly_one_handshake() {
    let mut c = Connection::<Client, Tunnel>::new();
    assert_eq!(
      c.handle_response(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
        .unwrap_err(),
      Error::InvalidState(NO_HANDSHAKE)
    );

    let mut c = offered();
    let mut out = [0u8; 128];
    assert!(matches!(
      c.open_upgrade(&CHAT, OFFER, &mut out),
      Err(Error::InvalidState(ONE_HANDSHAKE))
    ));

    let mut s = Connection::<Server, Tunnel>::new();
    const REQUEST: &[u8] =
      b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    assert!(matches!(
      s.handle_request(REQUEST).unwrap(),
      ServerTunnelRequest::Upgrade { .. }
    ));
    assert_eq!(
      s.handle_request(REQUEST).unwrap_err(),
      Error::InvalidState(ONE_HANDSHAKE)
    );
  }

  // RFC 9110 §7.8 on the server side: the offer is classified, the bytes the
  // client pipelined behind it are handed back untouched (they are the new
  // protocol's), and the 101 that accepts states the protocol it switched to
  // (§15.2.2).
  #[test]
  fn server_classifies_an_upgrade_request_with_its_pipelined_leftover() {
    let mut s = Connection::<Server, Tunnel>::new();
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x03abc";

    let ServerTunnelRequest::Upgrade {
      head,
      request,
      leftover,
    } = s.handle_request(REQUEST).unwrap()
    else {
      panic!("expected an upgrade")
    };
    assert_eq!(head.header("upgrade"), Some(b"websocket".as_slice()));
    // The parsed request-line comes with it: §7.8 scopes an offer to the FIELDS,
    // so a consumer that has its own method rule (a WebSocket handshake is a
    // GET) reads the method here rather than re-parsing a start line.
    assert_eq!(request.method, "GET");
    assert_eq!(
      request.target,
      Target::Origin {
        path_and_query: "/chat"
      }
    );
    assert_eq!(request.version, Version::Http11);
    assert_eq!(leftover, b"\x81\x03abc");

    let mut out = [0u8; 128];
    let n = s.accept(SWITCH, &mut out).unwrap();
    assert_eq!(
      &out[..n],
      b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    );
    // Terminal on this end too: the connection is the new protocol's now.
    assert!(matches!(
      s.accept(SWITCH, &mut out),
      Err(Error::InvalidState(_))
    ));
    assert!(matches!(
      s.handle_request(leftover),
      Err(Error::InvalidState(_))
    ));
  }

  // RFC 9110 §9.3.6 with RFC 9112 §3.2.3: a CONNECT is classified by its
  // authority-form target, and the octets a client sent behind the head are
  // already tunnel data — "data received after that header section is from the
  // server identified by the request target".
  #[test]
  fn server_classifies_a_connect_request_with_its_leftover() {
    let mut s = Connection::<Server, Tunnel>::new();
    const REQUEST: &[u8] =
      b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n\x16\x03\x01\x00\x05";

    let ServerTunnelRequest::Connect {
      head,
      request,
      leftover,
    } = s.handle_request(REQUEST).unwrap()
    else {
      panic!("expected a CONNECT")
    };
    assert_eq!(head.header("host"), Some(b"example.com:443".as_slice()));
    // The destination the driver is being asked to reach is in the target, and
    // RFC 9112 §3.2.3 puts it nowhere else.
    assert_eq!(request.method, "CONNECT");
    assert_eq!(
      request.target,
      Target::Authority {
        host_port: DESTINATION
      }
    );
    assert_eq!(leftover, b"\x16\x03\x01\x00\x05");

    let mut out = [0u8; 128];
    let none: &[(&str, &[u8])] = &[];
    let n = s.accept(none, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 200 Connection Established\r\n\r\n");
  }

  // RFC 9110 §7.8: "A server that receives an Upgrade header field in an
  // HTTP/1.0 request MUST ignore that Upgrade field." With the field ignored the
  // request is an ordinary 1.0 GET, which a connection that exists only to switch
  // protocols cannot serve — and the one answer it may still send is the rejection.
  #[test]
  fn an_http_10_upgrade_request_is_not_an_upgrade() {
    let mut s = Connection::<Server, Tunnel>::new();
    let error = s
      .handle_request(b"GET /chat HTTP/1.0\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
      .unwrap_err();
    assert_eq!(error, Error::Protocol(H1Error::Framing(NOT_A_HANDSHAKE)));
    assert_eq!(error.suggested_status(), Some(SuggestedStatus::BadRequest));

    let mut out = [0u8; 128];
    let n = s
      .reject(426, b"Upgrade Required", SWITCH, &mut out)
      .unwrap();
    assert_eq!(
      &out[..n],
      b"HTTP/1.1 426 Upgrade Required\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    );
    // Exactly one answer, and nothing else afterwards.
    assert_eq!(
      s.reject(400, b"", SWITCH, &mut out),
      Err(Error::InvalidState(NOTHING_TO_ANSWER))
    );
    assert!(matches!(
      s.accept(SWITCH, &mut out),
      Err(Error::InvalidState(_))
    ));
  }

  // RFC 9110 §7.8: "If a server receives both an Upgrade and an Expect header
  // field with the 100-continue expectation, the server MUST send a 100
  // (Continue) response before sending a 101 (Switching Protocols) response."
  // The ORDER is the MUST, so the core enforces it rather than documenting it.
  #[test]
  fn a_100_continue_is_owed_before_the_101() {
    let mut s = Connection::<Server, Tunnel>::new();
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nExpect: 100-continue\r\n\r\n";
    assert!(matches!(
      s.handle_request(REQUEST).unwrap(),
      ServerTunnelRequest::Upgrade { .. }
    ));

    let mut out = [0xAAu8; 128];
    assert_eq!(
      s.accept(SWITCH, &mut out),
      Err(Error::InvalidState(CONTINUE_BEFORE_SWITCH))
    );
    assert_eq!(out, [0xAAu8; 128]);

    let none: &[(&str, &[u8])] = &[];
    let n = s.send_interim(100, none, &mut out).unwrap();
    // RFC 9112 §4 makes the SP before an absent reason-phrase mandatory.
    assert_eq!(&out[..n], b"HTTP/1.1 100 \r\n\r\n");
    let n = s.accept(SWITCH, &mut out).unwrap();
    assert_eq!(
      &out[..n],
      b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    );
  }

  // The same RFC 9110 §7.8 obligation, asked ABOUT rather than tripped over: a
  // caller that can read the fact off the connection does not re-derive it by
  // parsing `Expect` a second time, which is the rule this crate already owns.
  #[test]
  fn the_outstanding_continue_obligation_is_visible_to_the_caller() {
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nExpect: 100-continue\r\n\r\n";
    let mut s = Connection::<Server, Tunnel>::new();
    // Nothing classified yet, so there is no handshake to owe anything.
    assert!(!s.owes_continue());
    assert!(matches!(
      s.handle_request(REQUEST).unwrap(),
      ServerTunnelRequest::Upgrade { .. }
    ));
    assert!(s.owes_continue());

    let none: &[(&str, &[u8])] = &[];
    let mut out = [0u8; 128];
    s.send_interim(100, none, &mut out).unwrap();
    // Discharged by the 100 that went out, which is the same transition `accept`
    // reads — the accessor and the gate answer from one fact.
    assert!(!s.owes_continue());
  }

  // The other side of §7.8's condition: the rule needs BOTH the `Upgrade` field
  // and the expectation, so an offer without the expectation owes nothing.
  #[test]
  fn a_handshake_without_the_expectation_owes_nothing() {
    const REQUEST: &[u8] =
      b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(REQUEST).unwrap(),
      ServerTunnelRequest::Upgrade { .. }
    ));
    assert!(!s.owes_continue());
  }

  // RFC 9110 §15.2 (any number of interim responses may precede the final one)
  // with §15.2.2: a 101 is not informational — it ENDS the HTTP conversation —
  // so it goes through `accept`, and a final status never comes out of the
  // interim path at all.
  #[test]
  fn send_interim_takes_only_a_non_101_1xx() {
    let mut s = Connection::<Server, Tunnel>::new();
    let none: &[(&str, &[u8])] = &[];
    let mut out = [0u8; 128];
    assert!(matches!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      )
      .unwrap(),
      ServerTunnelRequest::Upgrade { .. }
    ));
    assert_eq!(
      s.send_interim(101, none, &mut out),
      Err(Error::InvalidState(SWITCH_THROUGH_ACCEPT))
    );
    assert!(matches!(
      s.send_interim(200, none, &mut out),
      Err(Error::InvalidState(_))
    ));
    // RFC 9112 §6.1 and RFC 9110 §8.6: neither framing field belongs in a 1xx.
    let counted: &[(&str, &[u8])] = &[("Content-Length", b"0")];
    assert!(matches!(
      s.send_interim(100, counted, &mut out),
      Err(Error::InvalidState(_))
    ));
    // Interim responses do not end the handshake: the switch is still available.
    let n = s.send_interim(103, none, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 103 \r\n\r\n");
    assert!(s.accept(SWITCH, &mut out).is_ok());
  }

  // RFC 9110 §15.2.2 ("The server MUST generate an Upgrade header field in the
  // response") and §7.8 (its `upgrade` connection option) on the way out; RFC
  // 9112 §6.1 with RFC 9110 §8.6 and §9.3.6 for the framing fields, which a 101
  // and a 2xx-to-CONNECT MUST NOT carry.
  #[test]
  fn accept_states_the_switch_it_makes() {
    let mut out = [0xAAu8; 128];
    for bad in [
      &[("Upgrade", b"websocket".as_slice())][..],
      &[("Connection", b"Upgrade")],
    ] {
      let mut s = Connection::<Server, Tunnel>::new();
      assert!(
        s.handle_request(
          b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        )
        .is_ok()
      );
      assert_eq!(
        s.accept(bad, &mut out),
        Err(Error::InvalidState(SWITCH_NEEDS_BOTH_HALVES)),
        "{bad:?}"
      );
      assert_eq!(out, [0xAAu8; 128]);
    }

    // …and the same ordering on the server's half of the switch: an `Upgrade`
    // that does not parse is refused as such, not as a missing half.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      )
      .is_ok()
    );
    assert_eq!(
      s.accept(
        &[
          ("Upgrade", b"web socket".as_slice()),
          ("Connection", b"Upgrade")
        ][..],
        &mut out
      ),
      Err(Error::InvalidState(FIELD_STATES_ITS_GRAMMAR))
    );
    assert_eq!(out, [0xAAu8; 128]);
    assert!(s.accept(SWITCH, &mut out).is_ok());

    // A framing field on either switch: after the head there is no body to frame
    // — the octets are the tunnel's.
    let framed: &[(&str, &[u8])] = &[
      ("Upgrade", b"websocket"),
      ("Connection", b"Upgrade"),
      ("Content-Length", b"0"),
    ];
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      )
      .is_ok()
    );
    assert_eq!(
      s.accept(framed, &mut out),
      Err(Error::InvalidState(SWITCH_HAS_NO_FRAMING))
    );

    let mut s = Connection::<Server, Tunnel>::new();
    assert!(
      s.handle_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .is_ok()
    );
    let zero: &[(&str, &[u8])] = &[("Content-Length", b"0")];
    assert_eq!(
      s.accept(zero, &mut out),
      Err(Error::InvalidState(SWITCH_HAS_NO_FRAMING))
    );
  }

  // RFC 9110 §9.3.6: "A CONNECT request message does not have content", and an
  // upgrade offer cannot carry one either — this core switches protocols at the
  // head, so a body it would have to read first is a message it cannot serve.
  #[test]
  fn a_handshake_request_with_content_is_refused() {
    for bad in [
      b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: 5\r\n\r\nhello".as_slice(),
      b"POST /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 5\r\n\r\nhello",
    ] {
      let mut s = Connection::<Server, Tunnel>::new();
      assert_eq!(
        s.handle_request(bad).unwrap_err(),
        Error::Protocol(H1Error::Framing(HANDSHAKE_HAS_NO_CONTENT)),
        "{bad:?}"
      );
    }
  }

  // A request that is neither RFC 9110 §7.8's offer nor §9.3.6's tunnel is a
  // message this connection has no way to answer — and, like the single error
  // response, the rejection is the one thing it may still write.
  #[test]
  fn a_request_that_is_neither_a_switch_nor_a_tunnel_is_refused() {
    for bad in [
      // No offer at all.
      b"GET /chat HTTP/1.1\r\nHost: h\r\n\r\n".as_slice(),
      // RFC 9110 §7.8's two halves again, this time on the way in: one without
      // the other offers nothing, and neither does a list that names no
      // `protocol-name`.
      b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n",
      b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\n\r\n",
      b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: web socket\r\n\r\n",
    ] {
      let mut s = Connection::<Server, Tunnel>::new();
      assert_eq!(
        s.handle_request(bad).unwrap_err(),
        Error::Protocol(H1Error::Framing(NOT_A_HANDSHAKE)),
        "{bad:?}"
      );
    }

    let mut s = Connection::<Server, Tunnel>::new();
    assert_eq!(
      s.handle_request(b"GET /chat HTTP/1.1\r\nHost: h\r\n\r\n")
        .unwrap_err(),
      Error::Protocol(H1Error::Framing(NOT_A_HANDSHAKE))
    );
    let mut out = [0u8; 128];
    let none: &[(&str, &[u8])] = &[];
    let n = s.reject(400, b"Bad Request", none, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 400 Bad Request\r\n\r\n");
  }

  // RFC 9112 §2.1 again, from the server's side: a head that has not terminated
  // consumes nothing, and the leftover is measured from the head's end however
  // the transport split the bytes.
  #[test]
  fn a_partial_request_head_consumes_nothing() {
    const REQUEST: &[u8] =
      b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n\x16\x03";
    let end = REQUEST.len().saturating_sub(2);
    let mut s = Connection::<Server, Tunnel>::new();
    for n in 0..end {
      assert!(
        matches!(
          s.handle_request(REQUEST.get(..n).unwrap()).unwrap(),
          ServerTunnelRequest::NeedMore
        ),
        "prefix {n}"
      );
    }
    let ServerTunnelRequest::Connect { leftover, .. } = s.handle_request(REQUEST).unwrap() else {
      panic!("expected a CONNECT")
    };
    assert_eq!(leftover, b"\x16\x03");
  }

  /// A server that has classified a CONNECT and owes the answer to it.
  /// A server that has classified an RFC 9110 §7.8 upgrade offer and owes its
  /// answer — the state `accept` writes the 101 from.
  fn asked_to_upgrade() -> Connection<Server, Tunnel> {
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"
      )
      .unwrap(),
      ServerTunnelRequest::Upgrade { .. }
    ));
    s
  }

  fn asked_for_a_tunnel() -> Connection<Server, Tunnel> {
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(matches!(
      s.handle_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .unwrap(),
      ServerTunnelRequest::Connect { .. }
    ));
    s
  }

  // RFC 9110 §9.3.6: "Any 2xx (Successful) response indicates that the sender
  // (and all inbound proxies) will switch to tunnel mode immediately after the
  // response header section". A 2xx therefore ACCEPTS a CONNECT — writing one as
  // a refusal would leave the peer tunnelling while this end had recorded the
  // handshake as refused, which is the two ends disagreeing about whether the
  // connection is still HTTP. It is the same rule the 101 gets on the upgrade
  // side, and `accept` is the call that writes both.
  #[test]
  fn a_2xx_never_refuses_a_connect_handshake() {
    for code in [200u16, 204, 299] {
      let mut s = asked_for_a_tunnel();
      let mut out = [0xAAu8; 128];
      let none: &[(&str, &[u8])] = &[];
      assert_eq!(
        s.reject(code, b"", none, &mut out),
        Err(Error::InvalidState(SWITCH_THROUGH_ACCEPT)),
        "{code}"
      );
      // Nothing written, and the handshake is still answerable: the refusal cost
      // the caller only the call.
      assert_eq!(out, [0xAAu8; 128], "{code}");
      let n = s.reject(403, b"Forbidden", none, &mut out).unwrap();
      assert_eq!(&out[..n], b"HTTP/1.1 403 Forbidden\r\n\r\n", "{code}");
    }

    // Every non-2xx still refuses a CONNECT — §9.3.6: "Any response other than a
    // successful response indicates that the tunnel has not yet been formed".
    for code in [407u16, 502] {
      let mut s = asked_for_a_tunnel();
      let mut out = [0u8; 128];
      let none: &[(&str, &[u8])] = &[];
      assert!(s.reject(code, b"", none, &mut out).is_ok(), "{code}");
    }

    // The upgrade side is untouched: only the 101 switches there, so a 200 is an
    // ordinary refusal (§7.8: "A server MAY ignore a received Upgrade header
    // field if it wishes to continue using the current protocol").
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      )
      .is_ok()
    );
    let mut out = [0u8; 128];
    let zero: &[(&str, &[u8])] = &[("Content-Length", b"0")];
    let n = s.reject(200, b"OK", zero, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  }

  // The same rule where the METHOD is no longer known. A request that failed
  // classification leaves a rejection owed, and that phase cannot tell whether
  // the peer sent a CONNECT: a portless or content-bearing one is refused by
  // rules of OURS (RFC 9112 §3.2.3, RFC 9110 §9.3.6) after the wire has already
  // said CONNECT, and §9.3.6 binds the peer's reading of a 2xx, not our
  // classifier's conclusion. So the whole class is refused here — and
  // independently of the method, a phase whose meaning is "a rejection is owed"
  // has no success class to state.
  #[test]
  fn a_2xx_is_refused_while_a_rejection_is_owed() {
    for bad in [
      // The wire said CONNECT; we refused it for want of a port.
      b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
      // The wire said CONNECT; we refused it on §9.3.6: "A CONNECT request
      // message does not have content".
      b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: 5\r\n\r\nhello",
      // Not a CONNECT at all — the blanket's second half: a malformed request
      // owes a rejection, and no 2xx is one.
      b"GET /chat HTTP/1.1\r\nHost : h\r\n\r\n",
    ] {
      let mut s = Connection::<Server, Tunnel>::new();
      assert!(s.handle_request(bad).is_err(), "{bad:?}");

      let mut out = [0xAAu8; 128];
      let none: &[(&str, &[u8])] = &[];
      for code in [200u16, 204, 299] {
        assert_eq!(
          s.reject(code, b"OK", none, &mut out),
          Err(Error::InvalidState(SWITCH_THROUGH_ACCEPT)),
          "{code} {bad:?}"
        );
        // Nothing written, and the single answer is NOT spent by the refusal.
        assert_eq!(out, [0xAAu8; 128], "{code} {bad:?}");
      }
      let n = s.reject(400, b"Bad Request", none, &mut out).unwrap();
      assert_eq!(&out[..n], b"HTTP/1.1 400 Bad Request\r\n\r\n", "{bad:?}");
    }

    // The boundary the blanket must NOT cross: a classified upgrade offer keeps
    // its 2xx, because only the 101 switches there — RFC 9110 §7.8 lets a server
    // "continue using the current protocol on that connection" and answer the
    // request as it stands.
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      )
      .is_ok()
    );
    let mut out = [0u8; 128];
    let zero: &[(&str, &[u8])] = &[("Content-Length", b"0")];
    let n = s.reject(200, b"OK", zero, &mut out).unwrap();
    assert_eq!(&out[..n], b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  }

  // The checks this core DELEGATES upward have to be reachable from outside the
  // crate: the start-line codecs are crate-private, so a consumer holding an
  // outcome could not read a method, a target or a status code for itself. Both
  // outcomes therefore carry the line this core already parsed, and this test
  // reads them the way a PR2 consumer would — through the crate's public names
  // alone.
  #[test]
  fn outcomes_carry_the_start_lines_a_consumer_acts_on() {
    use crate::{
      ClientTunnelOutcome as Outcome, Connection as PublicConnection, RequestLine,
      ServerTunnelRequest as Request, StatusLine, Target as PublicTarget, Version as PublicVersion,
    };

    let mut server = PublicConnection::<Server, Tunnel>::new();
    let Ok(Request::Upgrade { request, .. }) = server.handle_request(
      b"OPTIONS * HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: HTTP/2.0\r\n\r\n",
    ) else {
      panic!("expected an upgrade")
    };
    // RFC 9110 §7.8: "an OPTIONS request can be honored by any protocol" — the
    // core classifies it, and the method the consumer's own rule turns on is
    // right here rather than behind a private codec.
    let RequestLine {
      method,
      target,
      version,
    } = request;
    assert_eq!(method, "OPTIONS");
    assert_eq!(target, PublicTarget::Asterisk);
    assert_eq!(version, PublicVersion::Http11);

    let mut client = PublicConnection::<Client, Tunnel>::new();
    let mut out = [0u8; 128];
    client.open_upgrade(&CHAT, OFFER, &mut out).unwrap();
    let Ok(Outcome::Refused { status, .. }) =
      client.handle_response(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
    else {
      panic!("expected a refusal")
    };
    let StatusLine {
      code,
      reason,
      version,
    } = status;
    assert_eq!(code, 401);
    assert_eq!(reason, b"Unauthorized".as_slice());
    assert_eq!(version, PublicVersion::Http11);
  }

  // RFC 9110 §15.5.22 (426) as a POLICY refusal rather than a fault: the request
  // was well formed and classified, and the server simply declines the switch.
  // The rejection ends the handshake — this connection completes one, and a
  // refused one is completed.
  #[test]
  fn server_reject_encodes_the_status_and_ends_the_handshake() {
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(
      s.handle_request(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      )
      .is_ok()
    );
    let mut out = [0u8; 128];
    let fields: &[(&str, &[u8])] = &[
      ("Upgrade", b"h2c"),
      ("Connection", b"Upgrade"),
      ("Content-Length", b"0"),
    ];
    // The two statuses a refusal is not: a 101 IS the switch (RFC 9110 §15.2.2),
    // and any other 1xx ends nothing at all (§15.2).
    assert_eq!(
      s.reject(101, b"Switching Protocols", fields, &mut out),
      Err(Error::InvalidState(SWITCH_THROUGH_ACCEPT))
    );
    assert!(matches!(
      s.reject(100, b"", fields, &mut out),
      Err(Error::InvalidState(_))
    ));
    let n = s
      .reject(426, b"Upgrade Required", fields, &mut out)
      .unwrap();
    assert_eq!(
      &out[..n],
      b"HTTP/1.1 426 Upgrade Required\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n"
    );
    assert_eq!(
      s.accept(SWITCH, &mut out),
      Err(Error::InvalidState(NO_HANDSHAKE))
    );
    assert_eq!(
      s.reject(400, b"", SWITCH, &mut out),
      Err(Error::InvalidState(NOTHING_TO_ANSWER))
    );

    // The rejection head is the whole message: a body this core will not write
    // must not be announced either (RFC 9112 §6.3 item 6).
    let mut s = Connection::<Server, Tunnel>::new();
    assert!(
      s.handle_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .is_ok()
    );
    let counted: &[(&str, &[u8])] = &[("Content-Length", b"12")];
    assert!(matches!(
      s.reject(403, b"Forbidden", counted, &mut out),
      Err(Error::InvalidState(_))
    ));
  }

  // RFC 9112 §2.2: a head that breaks the grammar is a message this end cannot
  // frame, so the connection latches — and the server is left owing exactly one answer.
  #[test]
  fn a_malformed_request_latches_and_leaves_one_answer_owed() {
    let mut s = Connection::<Server, Tunnel>::new();
    let error = s
      .handle_request(b"GET /chat HTTP/1.1\r\nHost : h\r\n\r\n")
      .unwrap_err();
    assert!(matches!(error, Error::Protocol(H1Error::Malformed(_))));
    assert_eq!(
      s.handle_request(b"GET /chat HTTP/1.1\r\nHost: h\r\n\r\n")
        .unwrap_err(),
      Error::InvalidState(FAILED)
    );
    let mut out = [0u8; 128];
    let none: &[(&str, &[u8])] = &[];
    assert!(s.reject(400, b"Bad Request", none, &mut out).is_ok());
  }

  /// The offer with the one framing field a handshake head may carry, which RFC
  /// 9110 §8.6 makes the way a message says it has no content.
  const OFFER_LENGTH_0: &[(&str, &[u8])] = &[
    ("Host", b"example.com"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
    ("Content-Length", b"0"),
  ];

  /// The same, for CONNECT.
  const CONNECT_LENGTH_0: &[(&str, &[u8])] =
    &[("Host", b"example.com:443"), ("Content-Length", b"0")];

  /// Writes an upgrade offer with `fields` and hands the bytes to a fresh server.
  ///
  /// The round trip in one line: whatever the client encoded is exactly what the
  /// server is offered, with no test-written wire in between to disagree with
  /// either end.
  #[track_caller]
  fn upgrade_round_trip(fields: &[(&str, &[u8])]) {
    let mut client = Connection::<Client, Tunnel>::new();
    let mut wire = [0u8; 192];
    let n = client
      .open_upgrade(&CHAT, fields, &mut wire)
      .expect("this core writes its own upgrade offer");

    let mut server = Connection::<Server, Tunnel>::new();
    let request = wire.get(..n).unwrap();
    let ServerTunnelRequest::Upgrade {
      request: line,
      leftover,
      ..
    } = server
      .handle_request(request)
      .expect("what one end of this core writes, the other end reads")
    else {
      panic!("an offer this core wrote classifies as an upgrade")
    };
    assert_eq!(line.method, "GET");
    assert_eq!(
      line.target,
      Target::Origin {
        path_and_query: "/chat"
      }
    );
    assert!(leftover.is_empty());

    // And the answer goes back the other way: `accept` writes the 101 the client
    // it came from reads as the switch.
    let mut answer = [0u8; 192];
    let n = server
      .accept(SWITCH, &mut answer)
      .expect("the server switches");
    let ClientTunnelOutcome::Switched { head, leftover } = client
      .handle_response(answer.get(..n).unwrap())
      .expect("this core reads the 101 this core wrote")
    else {
      panic!("the server switched")
    };
    assert_eq!(head.header("upgrade"), Some(b"websocket".as_slice()));
    assert!(leftover.is_empty());
  }

  /// The CONNECT twin of [`upgrade_round_trip`].
  #[track_caller]
  fn connect_round_trip(fields: &[(&str, &[u8])]) {
    let mut client = Connection::<Client, Tunnel>::new();
    let mut wire = [0u8; 192];
    let n = client
      .open_connect(DESTINATION, fields, &mut wire)
      .expect("this core writes its own CONNECT");

    let mut server = Connection::<Server, Tunnel>::new();
    let ServerTunnelRequest::Connect {
      request: line,
      leftover,
      ..
    } = server
      .handle_request(wire.get(..n).unwrap())
      .expect("what one end of this core writes, the other end reads")
    else {
      panic!("a CONNECT this core wrote classifies as a CONNECT")
    };
    assert_eq!(line.method, "CONNECT");
    assert_eq!(
      line.target,
      Target::Authority {
        host_port: DESTINATION
      }
    );
    assert!(leftover.is_empty());

    let mut answer = [0u8; 192];
    let n = server
      .accept(NO_FIELDS, &mut answer)
      .expect("the server opens the tunnel");
    let ClientTunnelOutcome::Tunneled {
      status, leftover, ..
    } = client
      .handle_response(answer.get(..n).unwrap())
      .expect("this core reads the 2xx this core wrote")
    else {
      panic!("the server tunnelled")
    };
    assert_eq!(status.code, 200);
    assert!(leftover.is_empty());
  }

  // THE ROUND TRIP, which is the class of test whose absence let a
  // self-incompatibility survive every review of the pieces: what ONE end of
  // this core writes, the OTHER end of this core must read. Both handshakes,
  // both directions, with and without the `Content-Length: 0` that RFC 9110 §8.6
  // makes the explicit way to say "no content" and that `open_upgrade` /
  // `open_connect` permit on the way out — so the §6.3 decision reports
  // `ContentLength(0)` rather than `None` and the receive side's shape check has
  // to accept both.
  //
  // Every byte compared here was produced by this crate. A hand-written wire
  // vector cannot state this property: it can only ever agree with the end that
  // the person writing it had in mind.
  #[test]
  fn a_handshake_this_core_writes_is_one_it_classifies() {
    upgrade_round_trip(OFFER);
    upgrade_round_trip(OFFER_LENGTH_0);
    connect_round_trip(CONNECT_HOST);
    connect_round_trip(CONNECT_LENGTH_0);
  }

  // The refusal half of the same round trip: RFC 9110 §15.5.22's 426 is the
  // canonical answer to an offer a server will not take, and the client that
  // sent the offer has to read what the server wrote as exactly that.
  #[test]
  fn a_refusal_this_core_writes_is_one_it_reads() {
    let mut client = offered();
    let mut server = Connection::<Server, Tunnel>::new();
    let mut wire = [0u8; 192];
    let n = Connection::<Client, Tunnel>::new()
      .open_upgrade(&CHAT, OFFER, &mut wire)
      .expect("the offer encodes");
    assert!(matches!(
      server.handle_request(wire.get(..n).unwrap()),
      Ok(ServerTunnelRequest::Upgrade { .. })
    ));

    let mut answer = [0u8; 192];
    let n = server
      .reject(426, b"Upgrade Required", SWITCH, &mut answer)
      .expect("a 426 declines the offer");
    let ClientTunnelOutcome::Refused { status, .. } = client
      .handle_response(answer.get(..n).unwrap())
      .expect("this core reads the refusal this core wrote")
    else {
      panic!("the server refused")
    };
    assert_eq!(status.code, 426);
    assert_eq!(status.reason, b"Upgrade Required");
  }
}

/// Mode-edge tests: the seam where a `Connection<_, General>` becomes the
/// `Connection<_, Tunnel>` that finishes a protocol switch.
///
/// Its own module because it is the one place that needs BOTH sets of fixtures
/// above — a request read through the General pump, and the tunnel that answers
/// it — and because the argument every test here makes is the same one: the
/// connection an edge produces is indistinguishable from the one the native path
/// builds, field for field.
mod mode_edges {
  use super::*;

  /// The conforming bodyless upgrade request both paths are fed. RFC 9110 §7.8's
  /// two halves, on the HTTP/1.1 the same section requires.
  const UPGRADE: &[u8] =
    b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

  /// The framing of an answer that has BEGUN but is not through: a counted body
  /// leaves `send` at `Sending` with the exchange and the receive side intact,
  /// which is what makes `ANSWER_BEGUN` the deterministically first failure.
  const LENGTH_3: &[(&str, &[u8])] = &[("Content-Length", b"3")];

  /// Has read the head of a `POST` that states BOTH halves of RFC 9110 §7.8 and
  /// a `Content-Length`, with the body not yet fed.
  ///
  /// The offer is not decoration: without it gate 2 fires before gate 3 and the
  /// test below would assert the wrong constant while still passing.
  fn server_mid_body() -> Connection<Server, General> {
    let mut c = Connection::<Server, General>::new();
    drain(
      &mut c,
      b"POST /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nContent-Length: 3\r\n\r\n",
    );
    c
  }

  /// Has read a conforming bodyless upgrade request to `AwaitingRearm`, so
  /// gates 1-5 pass and a single later mutation pins a single later gate.
  fn server_with_upgrade_read() -> Connection<Server, General> {
    let mut c = Connection::<Server, General>::new();
    drain(&mut c, UPGRADE);
    c
  }

  #[test]
  fn the_server_edge_lands_where_the_native_path_lands() {
    let mut native = Connection::<Server, Tunnel>::new();
    native
      .handle_request(UPGRADE)
      .expect("a conforming upgrade");

    let mut general = Connection::<Server, General>::new();
    drain(&mut general, UPGRADE);
    let edged = general.into_tunnel().expect("every gate passes");

    assert_eq!(native.fingerprint(), edged.fingerprint());
  }

  // The sharpest case of the class, and the one `Exchange::expect_unanswered`
  // exists for: RFC 9110 §7.8 puts the 100 before the 101, and
  // `RecvState::Body`'s copy of the ask is gone by the time this edge runs.
  #[test]
  fn the_server_edge_carries_the_expect_obligation() {
    const REQ: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nExpect: 100-continue\r\n\r\n";

    let mut native = Connection::<Server, Tunnel>::new();
    native.handle_request(REQ).unwrap();

    let mut general = Connection::<Server, General>::new();
    drain(&mut general, REQ);
    let edged = general.into_tunnel().unwrap();

    assert_eq!(native.fingerprint(), edged.fingerprint());
    assert!(
      edged.owes_continue(),
      "RFC 9110 §7.8: the 100 goes before the 101"
    );
  }

  /// A second conforming upgrade request, differing from `UPGRADE` only in a
  /// field value — so a head-to-head comparison that read the OFFER rather than
  /// the request would call the two the same.
  const OTHER_UPGRADE: &[u8] =
    b"GET /other HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

  /// A conforming CONNECT, which is the OTHER takeover and made no §7.8 offer.
  const CONNECT_REQUEST: &[u8] = b"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n";

  /// RFC 9110 §15.2.2's two halves, which `accept` requires in the 101.
  const SWITCH_FIELDS: &[(&str, &[u8])] = &[("Upgrade", b"websocket"), ("Connection", b"Upgrade")];

  fn view(bytes: &[u8]) -> crate::head::HeadView<'_> {
    crate::head::scan_head(bytes).expect("the fixture is a well-formed head")
  }

  /// The identity a caller-supplied head is measured against, on BOTH paths: a
  /// connection answers `Matches` for the head that armed it and `Mismatch` for
  /// any other, whichever way it was armed.
  ///
  /// The two halves are one test on purpose — the transition and the native
  /// classification have to agree about the digest as well as about the phase,
  /// and the fingerprint differentials above prove the agreement while this
  /// proves what the agreement is FOR.
  #[test]
  fn an_armed_connection_matches_only_the_head_that_armed_it() {
    let mut native = Connection::<Server, Tunnel>::new();
    native
      .handle_request(UPGRADE)
      .expect("a conforming upgrade");

    let mut general = Connection::<Server, General>::new();
    drain(&mut general, UPGRADE);
    let edged = general.into_tunnel().expect("every gate passes");

    for connection in [&native, &edged] {
      assert_eq!(
        connection.head_binding(&view(UPGRADE)),
        HeadBinding::Matches
      );
      assert_eq!(
        connection.head_binding(&view(OTHER_UPGRADE)),
        HeadBinding::Mismatch
      );
    }
  }

  /// RFC 9110 §9.3.6's takeover made no §7.8 upgrade offer, so the question has
  /// no affirmative answer for ANY head — its own included. Without this, a
  /// caller could classify a CONNECT and then answer a synthetic upgrade head on
  /// the same connection, whose `accept` would write `200 Connection
  /// Established` beside the other layer's 101.
  #[test]
  fn a_connect_armed_connection_matches_nothing() {
    let mut connection = Connection::<Server, Tunnel>::new();
    connection
      .handle_request(CONNECT_REQUEST)
      .expect("a CONNECT naming a port");
    assert_eq!(
      connection.head_binding(&view(CONNECT_REQUEST)),
      HeadBinding::Mismatch
    );
    assert_eq!(
      connection.head_binding(&view(UPGRADE)),
      HeadBinding::Mismatch
    );
  }

  /// No handshake, no armed request, nothing for a head to contradict — which is
  /// what keeps `Connection::new()` usable as the throwaway a caller
  /// pre-validates a head against before spending the one-way transition.
  #[test]
  fn a_connection_holding_no_handshake_contradicts_no_head() {
    assert_eq!(
      Connection::<Server, Tunnel>::new().head_binding(&view(UPGRADE)),
      HeadBinding::NoHandshake
    );

    // And after the switch: the phase is terminal, so the armed request is no
    // longer a request anything can still be bound to.
    let mut switched = Connection::<Server, Tunnel>::new();
    switched
      .handle_request(UPGRADE)
      .expect("a conforming upgrade");
    let mut out = [0u8; 128];
    switched
      .accept(SWITCH_FIELDS, &mut out)
      .expect("the 101 states both halves of §7.8");
    assert_eq!(
      switched.head_binding(&view(UPGRADE)),
      HeadBinding::NoHandshake
    );
  }

  // RFC 9110 §15.2 makes a 1xx not the answer, so an interim already sent leaves
  // the exchange being answered rather than answered: the edge still switches,
  // and the ordering MUST §7.8 states is discharged rather than carried.
  #[test]
  fn an_interim_already_sent_does_not_begin_the_answer() {
    const REQ: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nExpect: 100-continue\r\n\r\n";
    let mut c = Connection::<Server, General>::new();
    drain(&mut c, REQ);
    let mut out = [0u8; 64];
    c.send_interim(100, NO_FIELDS, &mut out)
      .expect("RFC 9110 §7.8's 100 goes out before the 101");
    let edged = c.into_tunnel().expect("an interim is not the answer");
    assert!(
      !edged.owes_continue(),
      "the 100 that was sent discharged the ordering MUST"
    );
  }

  // A capability the edge ADDS. The native path refuses a content-carrying
  // upgrade request outright, because a tunnel has no body machinery; the edge
  // accepts it once General has drained the body, which RFC 9110 §7.8 permits —
  // the request has by then been completely sent, which is the only thing the
  // rule asks.
  #[test]
  fn an_upgrade_request_with_content_switches_once_its_body_is_drained() {
    const REQ: &[u8] = b"POST /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nContent-Length: 3\r\n\r\nabc";

    let mut native = Connection::<Server, Tunnel>::new();
    assert!(
      native.handle_request(REQ).is_err(),
      "HANDSHAKE_HAS_NO_CONTENT"
    );

    let mut general = Connection::<Server, General>::new();
    drain(&mut general, REQ);
    general
      .into_tunnel()
      .expect("the request was completely sent");
  }

  // Nothing is in flight to switch, so gate 1 is the first and only failure.
  #[test]
  fn a_connection_with_nothing_in_flight_cannot_switch() {
    let c = Connection::<Server, General>::new();
    let (_, why) = c.into_tunnel().expect_err("no request has arrived");
    assert_eq!(why, TransitionRefused::NO_EXCHANGE);
  }

  // `the_upgrade_offer_is_recorded_only_when_both_halves_name_a_protocol` pins
  // where `upgrade_offered` is recorded; this pins the gate that reads it.
  // HTTP/1.0 is the second row because RFC 9110 §7.8 makes ignoring its
  // `Upgrade` field a MUST, which is a refusal rather than an omission.
  #[test]
  fn a_request_that_offered_no_upgrade_cannot_switch() {
    for req in [
      &b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"[..],
      &b"GET / HTTP/1.0\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"[..],
    ] {
      let mut c = Connection::<Server, General>::new();
      drain(&mut c, req);
      let (mut back, why) = c.into_tunnel().expect_err("nothing was offered");
      assert_eq!(why, TransitionRefused::NO_UPGRADE_OFFERED);
      let mut out = [0u8; 128];
      assert!(
        back
          .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
          .is_ok(),
        "the ordinary answer is still owed and still writable"
      );
    }
  }

  // RFC 9110 §7.8: the request must have been COMPLETELY sent, and a body still
  // arriving is a body whose remaining octets are HTTP.
  #[test]
  fn a_request_still_arriving_cannot_switch() {
    let c = server_mid_body();
    let (mut back, why) = c.into_tunnel().expect_err("the body is still arriving");
    assert_eq!(why, TransitionRefused::REQUEST_INCOMPLETE);
    let mut out = [0u8; 128];
    assert!(
      back
        .send_response(400, b"Bad Request", LENGTH_0, BodyPlan::None, &mut out)
        .is_ok(),
      "the response is still owed and still writable"
    );
  }

  // The 101 IS this exchange's answer, so an answer already going out makes it a
  // second response to one request. Begun with an UNFINISHED body on purpose: a
  // `send_interim` leaves `send` at `Owed` — neither the exchange nor the
  // connection moves — so the edge would succeed instead.
  #[test]
  fn a_server_that_has_begun_its_answer_cannot_switch() {
    let mut c = server_with_upgrade_read();
    let mut out = [0u8; 128];
    c.send_response(200, b"OK", LENGTH_3, BodyPlan::ContentLength(3), &mut out)
      .expect("the head announces the three octets that follow it");
    let (mut back, why) = c
      .into_tunnel()
      .expect_err("this exchange is already being answered");
    assert_eq!(why, TransitionRefused::ANSWER_BEGUN);
    assert!(
      back.send_body(b"abc", &mut out).is_ok(),
      "the body the head announced is still writable"
    );
  }

  // The only construction that can pin the lifecycle gate on this edge:
  // `Connection: close` sets `peer_close` at commit and signals `Closing`, while
  // the owed response keeps `settle` from clearing the exchange — so gates 1-4
  // pass and gate 5 is the first failure.
  #[test]
  fn an_upgrade_request_stating_close_cannot_switch_but_can_still_be_answered() {
    const REQ: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
Connection: Upgrade, close\r\n\r\n";
    let mut c = Connection::<Server, General>::new();
    drain(&mut c, REQ);
    let (mut back, why) = c.into_tunnel().expect_err("the peer asked to close");
    assert_eq!(why, TransitionRefused::NOT_OPEN);
    let mut out = [0u8; 256];
    let n = back
      .send_response(426, b"Upgrade Required", LENGTH_0, BodyPlan::None, &mut out)
      .expect("the response is still owed and still writable");
    assert!(
      out
        .get(..n)
        .is_some_and(|w| w.starts_with(b"HTTP/1.1 426 "))
    );
  }

  // `handle_eof` also queues an event, but gate 6 precedes the EVENT_UNDRAINED
  // gate `take_over` checks last, so READ_CLOSED is what is reported.
  #[test]
  fn a_half_closed_peer_stops_the_edge() {
    let mut c = server_with_upgrade_read();
    c.handle_eof().expect("the transport fact is recordable");
    let (_, why) = c.into_tunnel().expect_err("the peer stopped writing");
    assert_eq!(why, TransitionRefused::READ_CLOSED);
  }

  // RFC 9112 §9.3.2: `AwaitingRearm` means the pipelined bytes were never
  // consumed, and the edge must not consume them either.
  #[test]
  fn a_pipelined_request_survives_the_edge() {
    // One const rather than a `Vec` built from two: this module states it uses
    // no `Vec` and no `format!`, so that the whole of it runs on the bare
    // `no_std` tier. Dev-dependencies happen to pull `alloc` into the test graph
    // today, so a `Vec` would compile — which is exactly how a stated invariant
    // stops being true without anything failing.
    const PIPELINED: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\n\r\nGET /next HTTP/1.1\r\nHost: h\r\n\r\n";
    const SECOND: &[u8] = b"GET /next HTTP/1.1\r\nHost: h\r\n\r\n";

    let mut c = Connection::<Server, General>::new();
    let consumed = drain(&mut c, PIPELINED);
    assert_eq!(PIPELINED.get(consumed..), Some(SECOND));
    c.into_tunnel()
      .expect("the edge does not touch what it did not consume");
  }

  // The client transition. `take_over`'s own gates (5-8) are proven above
  // against the server's native path; what is left is this edge's own three
  // gates, and the two gate-5-8 cases only a client can reach at all.

  /// RFC 9110 §7.8's two halves, on the `Host` field `open_upgrade` also
  /// requires (RFC 9112 §3.2) — what a caller of the client edge already
  /// knows it wants to offer once the connection becomes a tunnel.
  const UPGRADE_FIELDS: &[(&str, &[u8])] = &[
    ("Host", b"h"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
  ];

  /// Has written a request and read its complete response back to the idle
  /// boundary, so `exchange` is `None`, both FSMs are `Idle`, and RFC 9112
  /// §9.2's tail barrier is lifted — the ordinary shape of a pooled connection
  /// sitting between two exchanges.
  fn client_after_one_completed_exchange() -> Connection<Client, General> {
    let mut c = Connection::<Client, General>::new();
    open_bodiless_request(&mut c, "GET");
    let mut it = c.handle(b"HTTP/1.1 204 \r\n\r\n");
    while it.next().unwrap().is_some() {}
    c
  }

  /// Has read a bodiless response through `ExchangeComplete` and stopped
  /// pulling before the boundary pass that would clear the tail: `exchange`
  /// is `None`, both FSMs are `Idle`, and `tail_unresolved` is still `true`,
  /// so a switch attempt reports gate 7 rather than gate 1.
  ///
  /// NOT "a response whose body is not fully read" — that leaves `recv: Body`
  /// and `exchange: Some`, which would report `EXCHANGE_IN_FLIGHT` instead.
  fn client_with_unread_tail() -> Connection<Client, General> {
    // The tail is a second response this client never asked for, the same
    // construction `a_client_cannot_open_a_request_over_an_unread_tail` uses.
    const STREAM: &[u8] = b"HTTP/1.1 204 \r\n\r\nHTTP/1.1 204 \r\n\r\n";
    let mut c = Connection::<Client, General>::new();
    open_bodiless_request(&mut c, "GET");
    {
      let mut it = c.handle(STREAM);
      assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
      assert!(matches!(
        it.next().unwrap(),
        Some(Item::ExchangeComplete { .. })
      ));
    }
    c
  }

  /// Has opened a request with a body still owed, then read a final response
  /// stating RFC 9112 §9.6's `close` option: that option's close-after-reading
  /// MUST — not its "cease sending", whose object is requests — abandons the
  /// unfinished body (`send: Abandoned`) at the same response that re-arms
  /// the connection (`exchange: None`, `recv: Idle`) — the only construction
  /// that leaves `send` anywhere but `Idle` on an otherwise idle connection.
  fn client_with_an_abandoned_body() -> Connection<Client, General> {
    let mut c = Connection::<Client, General>::new();
    let mut out = [0u8; 64];
    let counted: &[(&str, &[u8])] = &[("Host", b"h"), ("Content-Length", b"3")];
    c.open_request(
      "POST",
      &ORIGIN,
      counted,
      BodyPlan::ContentLength(3),
      &mut out,
    )
    .expect("a three-octet body is announced and not yet written");
    {
      let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      while it.next().unwrap().is_some() {}
    }
    c
  }

  /// Has completed one exchange whose response stated RFC 9112 §9.6's `close`
  /// option — the same shape as `client_after_one_completed_exchange`, except
  /// keep-alive is over: `settle` drops `Lifecycle::Closing` to `Draining` the
  /// moment it re-arms.
  fn client_after_a_closing_exchange() -> Connection<Client, General> {
    let mut c = Connection::<Client, General>::new();
    open_bodiless_request(&mut c, "GET");
    {
      let mut it = c.handle(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      while it.next().unwrap().is_some() {}
    }
    c
  }

  #[test]
  fn the_client_edge_lands_where_a_fresh_tunnel_lands() {
    let native = Connection::<Client, Tunnel>::new();
    let edged = Connection::<Client, General>::new()
      .into_tunnel()
      .expect("a fresh connection is idle");
    assert_eq!(native.fingerprint(), edged.fingerprint());
  }

  #[test]
  fn a_pooled_connection_upgrades_after_serving_ordinary_exchanges() {
    let c = client_after_one_completed_exchange();
    let mut tunnel = c.into_tunnel().expect("idle between exchanges");
    let mut out = [0u8; 256];
    // The host rides in the headers and the path in the target — `open_upgrade`
    // takes `(&Target<'_>, &H, &mut [u8])`, not a host/path pair.
    let target = Target::Origin {
      path_and_query: "/chat",
    };
    assert!(
      tunnel
        .open_upgrade(&target, UPGRADE_FIELDS, &mut out)
        .is_ok()
    );
  }

  #[test]
  fn a_connection_with_an_unresolved_tail_cannot_switch() {
    let c = client_with_unread_tail();
    let (_, why) = c.into_tunnel().expect_err("§9.2's barrier is up");
    assert_eq!(why, TransitionRefused::TAIL_UNRESOLVED);
  }

  #[test]
  fn a_half_closed_client_connection_cannot_switch() {
    // The handshake response can never arrive, so the upgrade could only time out.
    let mut c = Connection::<Client, General>::new();
    c.handle_eof().ok();
    let (_, why) = c.into_tunnel().expect_err("the peer stopped writing");
    assert_eq!(why, TransitionRefused::READ_CLOSED);
  }

  // Nothing about the connection is idle: a request opened moments ago is
  // still outstanding, so gate 1 is the first and only failure.
  #[test]
  fn a_connection_with_a_request_outstanding_cannot_switch() {
    let mut c = Connection::<Client, General>::new();
    open_bodiless_request(&mut c, "GET");
    let (mut back, why) = c.into_tunnel().expect_err("the response has not arrived");
    assert_eq!(why, TransitionRefused::EXCHANGE_IN_FLIGHT);
    // The exchange the gate refused to drop is still exactly the one this
    // connection was holding.
    let mut it = back.handle(b"HTTP/1.1 204 \r\n\r\n");
    assert!(matches!(it.next().unwrap(), Some(Item::Head { .. })));
  }

  // The only construction that leaves `send` anywhere but `Idle` on an
  // otherwise idle connection, so gate 3 is the first and only failure.
  #[test]
  fn a_connection_with_an_abandoned_body_cannot_switch() {
    let c = client_with_an_abandoned_body();
    let (_, why) = c.into_tunnel().expect_err("an abandoned body is not idle");
    assert_eq!(why, TransitionRefused::SEND_NOT_IDLE);
  }

  // The peer asked to close, so keep-alive is over even though every message
  // gate passes: gate 5 is the first failure.
  #[test]
  fn a_connection_told_to_close_cannot_switch() {
    let c = client_after_a_closing_exchange();
    let (_, why) = c.into_tunnel().expect_err("the peer asked to close");
    assert_eq!(why, TransitionRefused::NOT_OPEN);
  }

  // RFC 9112 §2.2's own gate, isolated: the tail is already resolved
  // (`client_after_one_completed_exchange` clears it before the CR arrives),
  // so a lone CR sitting at the idle cursor is the only unresolved fact left.
  #[test]
  fn a_connection_with_a_pending_cr_cannot_switch() {
    let mut c = client_after_one_completed_exchange();
    {
      let mut it = c.handle(b"\r");
      assert!(it.next().unwrap().is_none());
    }
    let (_, why) = c.into_tunnel().expect_err("the CR is still undecided");
    assert_eq!(why, TransitionRefused::PENDING_CR);
  }

  // The ordering gate 7 exists to prove: a completed exchange whose
  // re-offered tail ends in a lone CR sets BOTH `tail_unresolved` and
  // `pending_cr`, and `take_over` checks the barrier before its one-byte
  // special case — so TAIL_UNRESOLVED, not PENDING_CR, is what a switch
  // attempt reports.
  #[test]
  fn a_completed_exchange_with_a_trailing_cr_reports_the_barrier_first() {
    const STREAM: &[u8] = b"HTTP/1.1 204 \r\n\r\n\r";
    let mut c = Connection::<Client, General>::new();
    open_bodiless_request(&mut c, "GET");
    {
      let mut it = c.handle(STREAM);
      while it.next().unwrap().is_some() {}
    }
    let (_, why) = c.into_tunnel().expect_err("both facts are unresolved");
    assert_eq!(why, TransitionRefused::TAIL_UNRESOLVED);
  }

  // `Display` writes the reason and nothing else, so a driver logging a refusal
  // does not have to `{:?}` a tuple struct to see which gate failed. Rendered
  // into a comparison rather than a buffer, so the check costs no allocation and
  // runs on the bare tier with the rest of this module.
  #[test]
  fn a_refusal_renders_the_gate_it_names() {
    use core::fmt::Write as _;

    /// Accepts a rendering only if every piece written is the next slice of
    /// `rest`; what is left over afterwards is what the rendering omitted.
    struct Verbatim<'a> {
      rest: &'a str,
    }

    impl core::fmt::Write for Verbatim<'_> {
      fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let Some(rest) = self.rest.strip_prefix(s) else {
          return Err(core::fmt::Error);
        };
        self.rest = rest;
        Ok(())
      }
    }

    const GATES: &[TransitionRefused] = &[
      TransitionRefused::NO_EXCHANGE,
      TransitionRefused::NO_UPGRADE_OFFERED,
      TransitionRefused::REQUEST_INCOMPLETE,
      TransitionRefused::ANSWER_BEGUN,
      TransitionRefused::SWITCHED,
      TransitionRefused::NOT_OPEN,
      TransitionRefused::READ_CLOSED,
      TransitionRefused::TAIL_UNRESOLVED,
      TransitionRefused::PENDING_CR,
      TransitionRefused::EVENT_UNDRAINED,
      TransitionRefused::EXCHANGE_IN_FLIGHT,
      TransitionRefused::RECV_NOT_IDLE,
      TransitionRefused::SEND_NOT_IDLE,
    ];
    for gate in GATES {
      assert!(!gate.reason().is_empty(), "{gate:?}");
      let mut rendered = Verbatim {
        rest: gate.reason(),
      };
      write!(rendered, "{gate}").expect("the rendering is the reason");
      assert!(rendered.rest.is_empty(), "{gate:?} rendered short");
    }
  }
}
