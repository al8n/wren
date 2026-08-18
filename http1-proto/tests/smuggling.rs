//! Anti-smuggling vectors, driven END TO END through `Connection<Server,
//! General>`.
//!
//! RFC 9112 §11.2 defines request smuggling as two recipients disagreeing about
//! where one message ends and the next begins. Every vector below is a byte
//! stream built to produce that disagreement — two framing fields, two lengths,
//! a line terminator only one parser recognizes, a chunk-size only one parser
//! can read — and this file states what THIS recipient does with it.
//!
//! # Why an E2E file when the parsers are already pinned
//!
//! Almost every vector here has a unit-level pin somewhere in the crate:
//! `head::scan` pins the field-line grammar, `validate` pins the RFC 9112 §6.3
//! framing decision, `body::chunked` pins §7.1. Those tests answer "does the
//! parser refuse these bytes?". They cannot answer the questions a driver
//! actually has, because a parser has no lifecycle:
//!
//! - **What did the driver already act on?** A fault inside a body does not
//!   un-deliver the head that was handed over before it, and a fault in a head
//!   must deliver nothing at all. The item stream up to the fault is asserted
//!   for every vector.
//! - **Where did the message END?** The accept-side vectors pipeline a second
//!   request behind the first, and several of them put a DECOY REQUEST inside
//!   the first message's body. A recipient that framed the body one octet short
//!   would parse the decoy as a request; the item stream is what proves it did
//!   not. That assertion has no parser-level equivalent — it is a statement
//!   about two messages on one connection.
//! - **Is the connection still usable, and what does it owe?** A violation
//!   latches (the error is handed back exactly once, everything after it is
//!   `Error::InvalidState`), `wants_read` goes false, and a server is left
//!   owing exactly ONE error response — the 400/501 the violation suggests,
//!   carrying `Connection: close`, refused if asked for twice.
//!
//! So the assertions here are at the lifecycle layer: items observed, the latch,
//! the suggested status, and the error-response bytes. The parser-level
//! `is_err()` checks stay where they are.
//!
//! The OUTBOUND mirror of this file is `tests/smuggling_outbound.rs`: RFC 9112
//! §11.1/§11.2 are about two recipients disagreeing, and nothing in that says the
//! disagreement has to be the peer's fault.
//!
//! # The reason column
//!
//! Every refusal names the exact rule it earns — the `H1Error` variant AND its
//! `&'static str` payload — through [`Reason`]. The class alone is far too
//! coarse for an adversarial corpus: nearly everything here is a
//! `SuggestedStatus::BadRequest` protocol error, so a vector that started failing
//! for a NEIGHBOURING reason (a `Host` rule where a framing rule was meant, a
//! grammar fault in a byte the author did not intend to change) would keep
//! passing while testing nothing it names.
//!
//! # The status column
//!
//! Every refusal also asserts `Error::suggested_status()`, which is what a driver
//! answers with. Two of them are the interesting ones and they come from RFC
//! 9112 §6.3 item 4 versus §6.1: a `chunked` that has been placed where it
//! frames nothing is a MUST-400, while a coding this core cannot decode — with
//! the framing still intact — is §6.1's 501. So `chunked, gzip` is a 400 and
//! `gzip, chunked` is a 501, and the pair is asserted rather than described.

use http1_proto::{
  BodyPlan, Connection, Error, Event, General, H1Error, HeadView, Item, Server, StartLine,
  SuggestedStatus, Target,
};

/// The pipelined request every accept-side vector puts behind the message under
/// test.
///
/// It is what makes the framing assertion an E2E one: this request becomes
/// exchange 2 only if the message in front of it ended exactly where its head
/// said it would.
const FOLLOWER: &[u8] = b"GET /next HTTP/1.1\r\nHost: h\r\n\r\n";

/// A 42-octet body that IS a request (RFC 9112 §11.2's payload).
///
/// A recipient that framed the message anywhere short of the announced 42
/// octets would hand these bytes to the head parser and route a request the
/// client never sent. `/smuggled` never appears in a correct item stream, and
/// [`assert_nothing_smuggled`] is what says so.
const DECOY: &[u8] = b"GET /smuggled HTTP/1.1\r\nHost: h\r\n\r\nPADDING";

/// The target of that decoy, as the driver would see it if the framing slipped.
const SMUGGLED: &str = "/smuggled";

/// A bodiless request, used to prove a latched connection refuses even a
/// perfectly good one afterwards.
const BODILESS: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";

/// What the driver's stock answer announces. RFC 9112 §6.3 item 8 makes a
/// response carrying NO framing field close-delimited, which is not what a
/// keep-alive answer means — so a bodiless one says `Content-Length: 0`.
const LENGTH_0: &[(&str, &[u8])] = &[("Content-Length", b"0")];

/// The bytes that answer, spelled out so the harness pins the message rather
/// than counting it.
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

/// No field lines at all — what the owed error response is asked for, since
/// `send_error_response` states the one field it needs itself.
const NO_FIELDS: &[(&str, &[u8])] = &[];

/// Turns the driver takes before it is declared stuck.
///
/// A bound rather than a bare `loop`: each exchange costs one read turn and one
/// answer turn, so the two-exchange vectors settle in five, and a harness or a
/// core that stopped making progress should fail the test rather than hang it.
const MAX_TURNS: usize = 16;

/// The refusal constants these vectors name, mirroring the crate's own
/// `&'static str` payloads.
///
/// Spelled out here because they are `pub(crate)` on the far side of an
/// integration test's crate boundary — and that is what makes them useful: a
/// reworded refusal reds the vector that depends on it, and the wording is what
/// a driver logs.
mod why {
  /// RFC 9112 §6.3 item 3 with §6.2: both framing fields in one message.
  pub const BOTH_FRAMINGS: &str = "both Transfer-Encoding and Content-Length";
  /// RFC 9112 §6.3 item 5: two `Content-Length` values that are not the same.
  pub const LENGTHS_DISAGREE: &str = "Content-Length values disagree";
  /// RFC 9110 §8.6 `Content-Length = 1*DIGIT`.
  pub const LENGTH_NOT_DIGITS: &str = "Content-Length is not 1*DIGIT";
  /// RFC 9112 §6.3 item 4: `chunked` present but not last.
  pub const CHUNKED_NOT_FINAL: &str = "chunked is not the final transfer coding";
  /// RFC 9112 §7.1: "The chunked coding does not define any parameters".
  pub const CHUNKED_PARAMETERIZED: &str = "chunked transfer coding carries parameters";
  /// A `Transfer-Encoding` whose list is empty (RFC 9110 §5.6.1.2 drops empty
  /// elements, so a value of nothing but OWS names no coding at all).
  pub const NO_CODING: &str = "Transfer-Encoding lists no transfer coding";
  /// RFC 9112 §6.1: the coding this core cannot decode.
  pub const ONLY_CHUNKED: &str = "this core decodes only chunked";
  /// RFC 9112 §2.2: a line ends at CRLF and nowhere else.
  pub const BARE_CR_OR_LF: &str = "bare CR or LF in the head";
  /// RFC 9112 §5.2: obs-fold.
  pub const OBS_FOLD: &str = "obsolete line folding";
  /// RFC 9112 §5.1: no whitespace between a field name and its colon.
  pub const WS_BEFORE_COLON: &str = "whitespace between the field name and colon";
  /// RFC 9112 §2.2: no whitespace between the start-line and the first field.
  pub const WS_BEFORE_FIELDS: &str = "whitespace between the start-line and the first field line";
  /// RFC 9112 §7.1: `chunk-size = 1*HEXDIG` read into a `u64`.
  pub const CHUNK_SIZE_OVERFLOW: &str = "chunk-size does not fit in 64 bits";
  /// RFC 9112 §7.1.1: the bounded `chunk-ext`.
  pub const CHUNK_LINE_TOO_LONG: &str = "chunk-size line is too long";
  /// RFC 9112 §7.1: no whitespace after the size.
  pub const WS_AFTER_CHUNK_SIZE: &str = "whitespace after the chunk-size";
  /// RFC 9112 §3 `request-line`, one fault per vector.
  pub const EMPTY_TARGET: &str = "empty request-target";
  /// The same.
  pub const EXPECTED_VERSION: &str = "expected HTTP-version";
  /// The same.
  pub const METHOD_NOT_TOKEN: &str = "method is not a token";
  /// The same.
  pub const NO_SP_AFTER_TARGET: &str = "request-line has no SP after the request-target";
  /// The same.
  pub const TRAILING_AFTER_VERSION: &str = "trailing bytes after the HTTP-version";
  /// The same.
  pub const EMPTY_METHOD: &str = "empty method";
}

/// One owned copy of something the driver observed.
///
/// Owned because the real items borrow the stream, and comparable because these
/// tests assert the item SEQUENCE rather than poking at one item. `Item` is
/// deliberately neither (see its own doc), so this states exactly which parts of
/// a head these vectors hold the core to: the exchange it belongs to, the RFC
/// 9112 §3 method and request-target a server routes on, and every field line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
  /// `Item::Head`.
  Head {
    /// The exchange the head opened.
    exchange: u64,
    /// The method (RFC 9110 §9.1), case-sensitive.
    method: String,
    /// The request-target, as text.
    target: String,
    /// The field lines, in arrival order, OWS-trimmed.
    fields: Vec<(String, Vec<u8>)>,
  },
  /// A run of `Item::BodyChunk`s, coalesced: RFC 9112 §6.3 delivers body octets
  /// "as they arrive", so the SPLIT into items is the transport's and the octet
  /// sequence is the message's. These vectors are fed in one offer anyway; the
  /// coalescing is what keeps the expected sequences about framing.
  Body {
    /// The exchange whose body these octets are.
    exchange: u64,
    /// The octets, in arrival order.
    data: Vec<u8>,
  },
  /// `Item::Trailer` (RFC 9112 §7.1.2).
  Trailer {
    /// The exchange whose trailer section carried the field.
    exchange: u64,
    /// The field name.
    name: String,
    /// The field value.
    value: Vec<u8>,
  },
  /// `Item::ExchangeComplete`.
  Complete {
    /// The exchange that ended.
    exchange: u64,
  },
  /// `Item::ExpectContinue` (RFC 9110 §10.1.1).
  ExpectContinue {
    /// The exchange whose request carried the expectation.
    exchange: u64,
  },
}

/// Everything one drive of a vector produced, plus the connection it left
/// behind so the lifecycle can be interrogated afterwards.
#[derive(Debug, Default)]
struct Served {
  /// The items, in order, up to the fault if there was one.
  seen: Vec<Seen>,
  /// The connection-scoped notices, in order.
  events: Vec<Event>,
  /// The violation the stream produced, if any. Handed back exactly once, by
  /// the `next` that found it.
  failure: Option<Error>,
  /// Bytes of the stream the connection took ownership of.
  consumed: usize,
  /// How many stock responses the driver wrote — RFC 9112 §9.3.2's re-arm gate,
  /// discharged once per exchange.
  answers: usize,
  /// The connection, for the latch and owed-answer assertions.
  connection: Connection<Server, General>,
}

/// Concatenates the pieces of one wire stream.
fn stream(pieces: &[&[u8]]) -> Vec<u8> {
  pieces.concat()
}

/// Builds the expected mirror of a request head.
fn head(exchange: u64, method: &str, target: &str, fields: &[(&str, &[u8])]) -> Seen {
  Seen::Head {
    exchange,
    method: method.to_owned(),
    target: target.to_owned(),
    fields: fields
      .iter()
      .map(|&(name, value)| (name.to_owned(), value.to_vec()))
      .collect(),
  }
}

/// The field lines of a head, owned.
fn fields_of(view: &HeadView<'_>) -> Vec<(String, Vec<u8>)> {
  view
    .headers()
    .map(|(name, value)| (name.to_owned(), value.to_vec()))
    .collect()
}

/// The request-target as text. The four RFC 9112 §3.2 forms are textually
/// distinct, so flattening them loses nothing these vectors assert on.
fn target_text(target: Target<'_>) -> String {
  match target {
    Target::Origin { path_and_query } => path_and_query.to_owned(),
    Target::Absolute { uri } => uri.to_owned(),
    Target::Authority { host_port } => host_port.to_owned(),
    Target::Asterisk => "*".to_owned(),
  }
}

/// Mirrors one item, coalescing a body run into the entry before it.
fn record(seen: &mut Vec<Seen>, item: Item<'_>) {
  match item {
    Item::Head {
      exchange,
      view,
      line,
      interim,
    } => {
      assert!(!interim, "a request head is never interim");
      let StartLine::Request(request) = line else {
        panic!("a server reads request-lines, not status-lines")
      };
      seen.push(Seen::Head {
        exchange: exchange.get(),
        method: request.method.to_owned(),
        target: target_text(request.target),
        fields: fields_of(&view),
      });
    }
    Item::BodyChunk { exchange, data } => {
      if let Some(Seen::Body {
        exchange: at,
        data: run,
      }) = seen.last_mut()
        && *at == exchange.get()
      {
        run.extend_from_slice(data);
      } else {
        seen.push(Seen::Body {
          exchange: exchange.get(),
          data: data.to_vec(),
        });
      }
    }
    Item::Trailer {
      exchange,
      name,
      value,
    } => seen.push(Seen::Trailer {
      exchange: exchange.get(),
      name: name.to_owned(),
      value: value.to_vec(),
    }),
    Item::ExchangeComplete { exchange } => seen.push(Seen::Complete {
      exchange: exchange.get(),
    }),
    Item::ExpectContinue { exchange } => seen.push(Seen::ExpectContinue {
      exchange: exchange.get(),
    }),
    // `Item` is `#[non_exhaustive]`, so a consumer outside the crate owes this
    // arm. It PANICS rather than being ignored: an item this mirror silently
    // dropped would make a vector that produced it compare equal to one that
    // produced nothing, which is the vacuity these vectors exist to rule out.
    other => panic!("an item this corpus does not model: {other:?}"),
  }
}

/// Drives `wire` through a fresh server connection, answering every request the
/// keep-alive gate stalls on and stopping at the first violation.
///
/// The loop is the one a real driver runs (see `tests/split_robustness.rs` for
/// the full reference shape): offer the unconsumed tail, drain the items,
/// advance by `Items::consumed`, drain the events, and answer when
/// `is_awaiting_send` says the LOCAL side is what is missing. RFC 9112 §9.3.2
/// holds a pipelined request unconsumed until the response in front of it is
/// written, so without that answer the second exchange of a vector would never
/// appear.
fn serve(wire: &[u8]) -> Served {
  let mut served = Served::default();
  let mut turns = 0usize;
  loop {
    turns += 1;
    assert!(
      turns <= MAX_TURNS,
      "the driver did not settle in {MAX_TURNS} turns"
    );

    let consumed = {
      let offer = wire.get(served.consumed..).unwrap_or_default();
      let mut items = served.connection.handle(offer);
      loop {
        match items.next() {
          Ok(Some(item)) => record(&mut served.seen, item),
          Ok(None) => break,
          // Terminal for the connection, not merely for this call: nothing can
          // surface after it, so the drive stops here too.
          Err(error) => {
            served.failure = Some(error);
            break;
          }
        }
      }
      items.consumed()
    };
    served.consumed = served.consumed.saturating_add(consumed);
    assert!(
      served.consumed <= wire.len(),
      "the connection consumed bytes it was never offered"
    );
    while let Some(event) = served.connection.poll_event() {
      served.events.push(event);
    }

    if served.failure.is_some() {
      break;
    }
    if served.connection.is_awaiting_send() {
      let mut out = [0u8; 64];
      let written = served
        .connection
        .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
        .expect("a bodiless 200 answers every request these vectors accept");
      assert_eq!(out.get(..written), Some(RESPONSE));
      served.answers += 1;
      // The bytes already offered become the next exchange now, without a read.
      continue;
    }
    break;
  }
  served
}

/// WHICH refusal a vector earns, not merely that one happened.
///
/// The error CLASS on its own is far too coarse for an adversarial corpus:
/// nearly every vector here is a `SuggestedStatus::BadRequest` protocol error,
/// so a vector that started failing for an unrelated reason — a `Host` rule
/// instead of the framing rule it was written for, a grammar fault in a byte
/// the author did not mean to change — would keep passing while testing nothing
/// it names. Pinning the variant AND its payload is what makes each vector a
/// statement about the rule it cites.
///
/// The payloads are the crate's own `&'static str` refusal constants, spelled
/// out here because they are `pub(crate)` on the other side of an integration
/// test's crate boundary. That is a feature of this file rather than a
/// concession: a reworded refusal reds the vector that depends on it, and the
/// wording is what a driver logs.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Reason {
  /// `H1Error::Framing` — a framing rule (RFC 9112 §6.1 / §6.2 / §6.3).
  Framing(&'static str),
  /// `H1Error::Malformed`, matched on `MalformedDetail::what()`. The OFFSET is
  /// deliberately not part of the match: several vectors assert it separately,
  /// where its exact value is the point.
  Malformed(&'static str),
  /// `H1Error::UnsupportedCoding` — RFC 9112 §6.1's 501, whose payload names the
  /// coding this core cannot decode.
  UnsupportedCoding(&'static str),
}

/// Reduces a failure to the reason a vector states, or fails the test.
#[track_caller]
fn reason_of(error: &Error) -> Reason {
  let Error::Protocol(protocol) = error else {
    panic!("a wire violation is a protocol error, not {error:?}")
  };
  match protocol {
    H1Error::Framing(what) => Reason::Framing(what),
    H1Error::Malformed(detail) => Reason::Malformed(detail.what()),
    H1Error::UnsupportedCoding(coding) => Reason::UnsupportedCoding(coding),
    other => panic!("no vector in this corpus states {other:?}"),
  }
}

/// Drives `wire` and asserts the connection REFUSED it, with everything a
/// refusal implies at the lifecycle layer.
///
/// Five facts, and the last two are the ones no parser-level test can state:
/// the fault is a wire violation whose REASON is `reason` and whose advisory
/// status is `status`; it is handed back exactly once and the connection
/// latches, so a later `handle` — of a perfectly good request — is caller-side
/// misuse; reading cannot help; and the server is left owing exactly one error
/// response.
#[track_caller]
fn refused(wire: &[u8], status: SuggestedStatus, reason: Reason) -> Served {
  let mut served = serve(wire);
  let Some(failure) = served.failure.clone() else {
    panic!("the stream was accepted, yielding {:?}", served.seen)
  };
  assert!(
    matches!(failure, Error::Protocol(_)),
    "a wire violation is a protocol error, not {failure:?}"
  );
  assert_eq!(
    reason_of(&failure),
    reason,
    "the vector was refused for a different rule than it states"
  );
  assert_eq!(
    failure.suggested_status(),
    Some(status),
    "the violation suggests the wrong status: {failure:?}"
  );
  {
    let mut items = served.connection.handle(BODILESS);
    assert!(
      matches!(items.next(), Err(Error::InvalidState(_))),
      "the connection kept parsing after a violation"
    );
  }
  assert!(
    !served.connection.wants_read(),
    "a failed connection asked for bytes it cannot use"
  );
  assert!(
    served.connection.is_awaiting_send(),
    "a failed server still owes its single error response"
  );
  served
}

/// Drives `wire` and asserts the connection ACCEPTED it, having parsed at least
/// one message out of it.
#[track_caller]
fn accepted(wire: &[u8]) -> Served {
  let served = serve(wire);
  assert!(
    served.failure.is_none(),
    "the stream was refused: {:?}",
    served.failure
  );
  assert!(
    served
      .seen
      .iter()
      .any(|seen| matches!(seen, Seen::Head { .. })),
    "nothing was parsed out of the stream"
  );
  served
}

/// Asserts the decoy request inside a body never became a message (RFC 9112
/// §11.2).
#[track_caller]
fn assert_nothing_smuggled(served: &Served) {
  assert!(
    !served
      .seen
      .iter()
      .any(|seen| matches!(seen, Seen::Head { target, .. } if target == SMUGGLED)),
    "the body's decoy request was parsed as a request: {:?}",
    served.seen
  );
}

// RFC 9112 §6.3 item 3 with §6.1: a message carrying both framing fields is the
// smuggling primitive itself (§11.2) — one recipient frames it by the length,
// the next by the chunks — so it is refused as unresolvable framing rather than
// resolved by a precedence rule this end would be applying alone. Either field
// ALONE frames a message this core reads.
#[test]
fn transfer_encoding_beside_content_length_is_unframable() {
  let refusal = refused(
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\
      \r\n5\r\nhello\r\n0\r\n\r\n",
    SuggestedStatus::BadRequest,
    Reason::Framing(why::BOTH_FRAMINGS),
  );
  // The head never became a message, so the driver was handed nothing: the
  // fault is in the head itself, and a driver that had already routed it would
  // be acting on a request whose extent nobody agrees on.
  assert!(refusal.seen.is_empty(), "{:?}", refusal.seen);
  assert_eq!(refusal.consumed, 0);

  // Chunked alone (item 4), and the pipelined request behind it proves where
  // the body ended.
  let chunked = accepted(&stream(&[
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"5\r\nhello\r\n0\r\n\r\n",
    FOLLOWER,
  ]));
  assert_eq!(
    chunked.seen,
    [
      head(
        1,
        "POST",
        "/u",
        &[("Host", b"h"), ("Transfer-Encoding", b"chunked")]
      ),
      Seen::Body {
        exchange: 1,
        data: b"hello".to_vec(),
      },
      Seen::Complete { exchange: 1 },
      head(2, "GET", "/next", &[("Host", b"h")]),
      Seen::Complete { exchange: 2 },
    ]
  );

  // Content-Length alone (items 5-6).
  let counted = accepted(&stream(&[
    b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
    FOLLOWER,
  ]));
  assert_eq!(
    counted.seen,
    [
      head(1, "POST", "/u", &[("Host", b"h"), ("Content-Length", b"5")]),
      Seen::Body {
        exchange: 1,
        data: b"hello".to_vec(),
      },
      Seen::Complete { exchange: 1 },
      head(2, "GET", "/next", &[("Host", b"h")]),
      Seen::Complete { exchange: 2 },
    ]
  );
}

// RFC 9112 §6.3 item 5 with RFC 9110 §5.3 (repeated field lines are ONE
// comma-separated list): two lengths that disagree are unrecoverable, whether
// they arrived on two lines or as two elements of one. The exception item 5
// carves out is a list whose values are all valid and ALL THE SAME, and the
// vector below takes it: `42, 42` frames exactly 42 octets, which is what the
// decoy inside those octets is there to prove.
#[test]
fn content_lengths_must_agree_and_an_identical_list_frames_forty_two() {
  for (wire, reason) in [
    (
      b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 42\r\nContent-Length: 43\r\n\r\n".as_slice(),
      Reason::Framing(why::LENGTHS_DISAGREE),
    ),
    (
      b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 42, 43\r\n\r\n",
      Reason::Framing(why::LENGTHS_DISAGREE),
    ),
    // Not a number at all: a length this end cannot read is one the peer may
    // read differently (RFC 9110 §8.6 `Content-Length = 1*DIGIT`). A DIFFERENT
    // rule from the disagreement above, and the reason column is what keeps the
    // two vectors from silently collapsing into one.
    (
      b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 0x2A\r\n\r\n",
      Reason::Framing(why::LENGTH_NOT_DIGITS),
    ),
    (
      b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: +42\r\n\r\n",
      Reason::Framing(why::LENGTH_NOT_DIGITS),
    ),
  ] {
    let refusal = refused(wire, SuggestedStatus::BadRequest, reason);
    assert!(refusal.seen.is_empty(), "{:?}", refusal.seen);
  }

  assert_eq!(DECOY.len(), 42, "the decoy body is the announced length");
  const LISTED: &[u8] = b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 42, 42\r\n\r\n";
  let listed = accepted(&stream(&[LISTED, DECOY, FOLLOWER]));
  assert_eq!(
    listed.seen,
    [
      head(
        1,
        "POST",
        "/u",
        &[("Host", b"h"), ("Content-Length", b"42, 42")]
      ),
      Seen::Body {
        exchange: 1,
        data: DECOY.to_vec(),
      },
      Seen::Complete { exchange: 1 },
      head(2, "GET", "/next", &[("Host", b"h")]),
      Seen::Complete { exchange: 2 },
    ]
  );
  assert_nothing_smuggled(&listed);
  // Both messages whole, and nothing else: the connection took exactly the
  // bytes the two heads framed.
  assert_eq!(listed.consumed, LISTED.len() + DECOY.len() + FOLLOWER.len());
  assert_eq!(listed.answers, 2);

  // The same agreement across two field lines, which is where a recipient that
  // read only the first line would differ from one that folded them.
  let split = accepted(&stream(&[
    b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 42\r\nContent-Length: 42\r\n\r\n",
    DECOY,
    FOLLOWER,
  ]));
  assert_nothing_smuggled(&split);
  assert_eq!(
    split.seen.get(1),
    Some(&Seen::Body {
      exchange: 1,
      data: DECOY.to_vec(),
    })
  );
}

// obs-fold is a continuation line, and this core does not accept one. RFC 9112
// §5.2: "A sender MUST NOT generate a message that includes line folding", and a
// recipient that unfolded it would read a different field value than one that
// treated the continuation as a new field line. The value the sender meant is
// expressible on ONE line, which is the accept side.
#[test]
fn obsolete_line_folding_is_refused() {
  let refusal = refused(
    b"GET /a HTTP/1.1\r\nHost: h\r\nX-A: a\r\n b\r\n\r\n",
    SuggestedStatus::BadRequest,
    Reason::Malformed(why::OBS_FOLD),
  );
  assert!(refusal.seen.is_empty(), "{:?}", refusal.seen);

  let folded_by_the_sender = accepted(b"GET /a HTTP/1.1\r\nHost: h\r\nX-A: a b\r\n\r\n");
  assert_eq!(
    folded_by_the_sender.seen.first(),
    Some(&head(1, "GET", "/a", &[("Host", b"h"), ("X-A", b"a b")]))
  );
}

// RFC 9112 §2.2: a line ends at CRLF and nowhere else, so a bare CR is not a
// terminator — neither where a line should end nor inside one. §11.2 is why it
// is a refusal rather than a repair: a recipient that took a lone CR for a line
// break would end the head somewhere the next recipient does not.
#[test]
fn a_bare_cr_is_not_a_line_terminator() {
  for wire in [
    // A CR standing in for the request-line's terminator.
    b"GET /a HTTP/1.1\rHost: h\r\n\r\n".as_slice(),
    // A CR inside a field value, which is where a smuggled line would hide.
    b"GET /a HTTP/1.1\r\nHost: h\r\nX-A: a\rb\r\n\r\n",
    // A CR standing in for the empty line that ends the head.
    b"GET /a HTTP/1.1\r\nHost: h\r\r\n",
  ] {
    let refusal = refused(
      wire,
      SuggestedStatus::BadRequest,
      Reason::Malformed(why::BARE_CR_OR_LF),
    );
    assert!(refusal.seen.is_empty(), "{:?}", refusal.seen);
  }
  // The same head with a CRLF where each bare CR sat is a message.
  assert_eq!(accepted(BODILESS).seen.len(), 2);
}

// RFC 9112 §2.2 again, for the other half of the terminator: §2.2 lets a
// recipient "recognize a single LF as a line terminator and ignore any preceding
// CR" — a MAY this core does not take, because a bare LF is exactly how a
// message is made to end in one place for this recipient and another place for
// the next (§11.2).
#[test]
fn a_bare_lf_is_not_a_line_terminator() {
  for wire in [
    b"GET /a HTTP/1.1\nHost: h\r\n\r\n".as_slice(),
    b"GET /a HTTP/1.1\r\nHost: h\nX-A: b\r\n\r\n",
    b"GET /a HTTP/1.1\r\nHost: h\r\n\n",
  ] {
    let refusal = refused(
      wire,
      SuggestedStatus::BadRequest,
      Reason::Malformed(why::BARE_CR_OR_LF),
    );
    assert!(refusal.seen.is_empty(), "{:?}", refusal.seen);
  }
  // The same three heads with CRLF terminators are messages; the bare LF is the
  // whole of what is refused.
  assert_eq!(accepted(BODILESS).seen.len(), 2);
}

// RFC 9112 §5.1: "No whitespace is allowed between the field name and colon. In
// the past, differences in the handling of such whitespace have led to security
// vulnerabilities in request routing" — a recipient that trimmed it would
// disagree with one that did not about the field's very NAME, so a server MUST
// reject the message.
#[test]
fn whitespace_before_a_field_colon_is_refused() {
  for wire in [
    b"GET /a HTTP/1.1\r\nHost : h\r\n\r\n".as_slice(),
    b"GET /a HTTP/1.1\r\nHost\t: h\r\n\r\n",
    // The one that matters most: a second, whitespace-named `Content-Length`
    // that a lenient recipient would fold into the framing decision.
    b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length : 6\r\n\r\nhello",
  ] {
    let refusal = refused(
      wire,
      SuggestedStatus::BadRequest,
      Reason::Malformed(why::WS_BEFORE_COLON),
    );
    assert!(refusal.seen.is_empty(), "{:?}", refusal.seen);
  }
  // The same head with its one fault corrected is a message: what is refused
  // above is the whitespace, not the request.
  assert_eq!(accepted(BODILESS).seen.len(), 2);
}

// RFC 9112 §2.2: "A sender MUST NOT send whitespace between the start-line and
// the first header field", and a recipient that receives it "MUST either reject
// the message … or consume each whitespace-preceded line without further
// processing of it". This core rejects, which is the option that cannot be made
// to disagree with anything.
#[test]
fn whitespace_before_the_first_field_line_is_refused() {
  for wire in [
    b"GET /a HTTP/1.1\r\n Host: h\r\n\r\n".as_slice(),
    b"GET /a HTTP/1.1\r\n\tHost: h\r\n\r\n",
  ] {
    let refusal = refused(
      wire,
      SuggestedStatus::BadRequest,
      Reason::Malformed(why::WS_BEFORE_FIELDS),
    );
    assert!(refusal.seen.is_empty(), "{:?}", refusal.seen);
  }
  // The same head with its one fault corrected is a message: what is refused
  // above is the whitespace, not the request.
  assert_eq!(accepted(BODILESS).seen.len(), 2);
}

// RFC 9112 §3: `request-line = method SP request-target SP HTTP-version CRLF`.
// The section lets a recipient "parse the request-line into its component parts
// separated by whitespace" instead, and that MAY is deliberately not taken —
// §3's own warning is that "differences in the handling of such whitespace have
// led to security vulnerabilities in request routing", which is §11.2 again.
#[test]
fn the_request_line_takes_single_spaces_only() {
  // One fault per vector, and the reason column is what says WHICH element the
  // stray whitespace broke: a double SP before the target makes the TARGET
  // empty, one before the version makes the VERSION unparseable, an HTAB in
  // either position lands inside a different element again. All six are 400s, so
  // the status alone cannot tell them apart — and a vector that started failing
  // for a neighbouring reason would keep passing while proving nothing it names.
  for (wire, reason) in [
    (
      b"GET  /a HTTP/1.1\r\nHost: h\r\n\r\n".as_slice(), // double SP before the target
      Reason::Malformed(why::EMPTY_TARGET),
    ),
    (
      b"GET /a  HTTP/1.1\r\nHost: h\r\n\r\n", // double SP before the version
      Reason::Malformed(why::EXPECTED_VERSION),
    ),
    (
      b"GET\t/a HTTP/1.1\r\nHost: h\r\n\r\n", // HTAB for the first SP
      Reason::Malformed(why::METHOD_NOT_TOKEN),
    ),
    (
      b"GET /a\tHTTP/1.1\r\nHost: h\r\n\r\n", // HTAB for the second
      Reason::Malformed(why::NO_SP_AFTER_TARGET),
    ),
    (
      b"GET /a HTTP/1.1 \r\nHost: h\r\n\r\n", // trailing SP
      Reason::Malformed(why::TRAILING_AFTER_VERSION),
    ),
    (
      b" GET /a HTTP/1.1\r\nHost: h\r\n\r\n", // leading SP
      Reason::Malformed(why::EMPTY_METHOD),
    ),
  ] {
    let refusal = refused(wire, SuggestedStatus::BadRequest, reason);
    assert!(refusal.seen.is_empty(), "{:?}", refusal.seen);
  }
  // The same head with its one fault corrected is a message: what is refused
  // above is the whitespace, not the request.
  assert_eq!(accepted(BODILESS).seen.len(), 2);
}

// RFC 9112 §7.1 `chunk-size = 1*HEXDIG`, read into the same `u64` a
// `Content-Length` is (RFC 9110 §8.6): seventeen significant hex digits do not
// fit one, and a recipient that wrapped the value would turn an absurd announced
// length into a small plausible one — and then start reading the next chunk in
// the middle of this one's data. Sixteen digits is `u64::MAX`'s own width, so a
// fully zero-padded legal size still decodes.
#[test]
fn a_chunk_size_past_sixty_four_bits_is_refused() {
  const HEAD: &[u8] = b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
  let refusal = refused(
    &stream(&[HEAD, b"FFFFFFFFFFFFFFFFF\r\nhello\r\n0\r\n\r\n"]),
    SuggestedStatus::BadRequest,
    Reason::Malformed(why::CHUNK_SIZE_OVERFLOW),
  );
  // The head WAS delivered — it was well formed, and the driver has already
  // acted on it — and the body it framed produced nothing. That asymmetry is
  // the whole reason this file drives a connection instead of a decoder.
  assert_eq!(
    refusal.seen,
    [head(
      1,
      "POST",
      "/u",
      &[("Host", b"h"), ("Transfer-Encoding", b"chunked")]
    )]
  );
  assert_eq!(refusal.consumed, HEAD.len());

  let widest = accepted(&stream(&[
    HEAD,
    b"0000000000000001\r\na\r\n0\r\n\r\n",
    FOLLOWER,
  ]));
  assert_eq!(
    widest.seen.get(1),
    Some(&Seen::Body {
      exchange: 1,
      data: b"a".to_vec(),
    })
  );
  assert_eq!(widest.seen.last(), Some(&Seen::Complete { exchange: 2 }));
}

// RFC 9112 §7.1.1: `chunk-ext` is parsed and then IGNORED, which is exactly why
// it needs a bound — bytes a recipient skipped without reading are bytes it
// cannot claim to have delimited, and an unbounded skip is a buffer whose size
// the peer chooses. The budget is the chunk-size line's: `MAX_CHUNK_EXT_BYTES`
// (256) of extension inside a 16-digit-plus-extension line, so a 300-byte
// extension is over both, and the line bound is the outer of the two.
#[test]
fn an_over_long_chunk_extension_is_refused() {
  const HEAD: &[u8] = b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
  let long = format!("1;x={}\r\na\r\n0\r\n\r\n", "a".repeat(300));
  let refusal = refused(
    &stream(&[HEAD, long.as_bytes()]),
    SuggestedStatus::BadRequest,
    Reason::Malformed(why::CHUNK_LINE_TOO_LONG),
  );
  assert_eq!(refusal.seen.len(), 1, "{:?}", refusal.seen);

  // A short extension is parsed, dropped, and changes nothing about the body.
  let short = accepted(&stream(&[
    HEAD,
    b"1;x=y;q=\"a;b\"\r\na\r\n0\r\n\r\n",
    FOLLOWER,
  ]));
  assert_eq!(
    short.seen.get(1),
    Some(&Seen::Body {
      exchange: 1,
      data: b"a".to_vec(),
    })
  );
  assert_eq!(short.seen.last(), Some(&Seen::Complete { exchange: 2 }));
}

// RFC 9112 §7.1 with §7.1.1: the `BWS` §7.1.1 allows sits around the `;`, the
// extension name and the `=`, and NOWHERE else — so the space in `5 \r\n` has no
// repetition to belong to. It is refused rather than trimmed, because a
// recipient that trimmed it would read `5` where a stricter one reads a broken
// line, which is §11.2 at chunk granularity.
#[test]
fn whitespace_after_the_chunk_size_is_refused() {
  const HEAD: &[u8] = b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
  for body in [
    b"5 \r\nhello\r\n0\r\n\r\n".as_slice(),
    b"5\t\r\nhello\r\n0\r\n\r\n",
    // The same space on the last chunk, where it would end the body early.
    b"1\r\na\r\n0 \r\n\r\n",
  ] {
    let refusal = refused(
      &stream(&[HEAD, body]),
      SuggestedStatus::BadRequest,
      Reason::Malformed(why::WS_AFTER_CHUNK_SIZE),
    );
    assert_eq!(
      refusal.seen.first(),
      Some(&head(
        1,
        "POST",
        "/u",
        &[("Host", b"h"), ("Transfer-Encoding", b"chunked")]
      ))
    );
  }

  let clean = accepted(&stream(&[HEAD, b"5\r\nhello\r\n0\r\n\r\n", FOLLOWER]));
  assert_eq!(
    clean.seen.get(1),
    Some(&Seen::Body {
      exchange: 1,
      data: b"hello".to_vec(),
    })
  );
}

// RFC 9112 §7.1: `last-chunk = 1*("0") [ chunk-ext ] CRLF` — a chunk-size of
// zero IS the last chunk however many digits spelled it, so `00` and `000` end
// the body exactly where `0` does. A recipient that only recognized a single `0`
// would go on reading the trailer section as chunk data and swallow the request
// behind it, which is what the pipelined follower here rules out.
#[test]
fn a_multi_zero_last_chunk_ends_the_body() {
  const HEAD: &[u8] = b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
  for last in [b"00".as_slice(), b"000", b"0000000000000000"] {
    let observed = accepted(&stream(&[HEAD, b"1\r\na\r\n", last, b"\r\n\r\n", FOLLOWER]));
    assert_eq!(
      observed.seen,
      [
        head(
          1,
          "POST",
          "/u",
          &[("Host", b"h"), ("Transfer-Encoding", b"chunked")]
        ),
        Seen::Body {
          exchange: 1,
          data: b"a".to_vec(),
        },
        Seen::Complete { exchange: 1 },
        head(2, "GET", "/next", &[("Host", b"h")]),
        Seen::Complete { exchange: 2 },
      ],
      "last-chunk {last:?}"
    );
  }
}

// RFC 9112 §7.1: "The chunked coding does not define any parameters. Their
// presence SHOULD be treated as an error." This core treats a parameterized
// `chunked` as a coding that does not FRAME the message — the §6.3 item 4 class
// — so the suggested answer is the 400 that item 4 makes a MUST, decided ahead
// of §6.1's SHOULD-501 for a coding a server cannot decode. (501 is the
// tempting reading; the crate's classification, documented in `validate`, is
// the 400 asserted here. The ordering is the point: item 4's framing MUST
// outranks §6.1's decoding SHOULD, and a message whose length cannot be
// determined is a 400 whatever the reason.)
#[test]
fn a_parameterized_chunked_coding_does_not_frame_the_message() {
  for wire in [
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked;a=b\r\n\r\n".as_slice(),
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked ; a=b\r\n\r\n",
  ] {
    let refusal = refused(
      wire,
      SuggestedStatus::BadRequest,
      Reason::Framing(why::CHUNKED_PARAMETERIZED),
    );
    assert!(refusal.seen.is_empty(), "{:?}", refusal.seen);
  }
}

// RFC 9112 §6.3 item 4 versus §6.1, and the ORDER they are applied in — which is
// the whole content of this vector pair. Item 4: "If a Transfer-Encoding header
// field is present in a request and the chunked transfer coding is not the final
// encoding, the message body length cannot be determined reliably; the server
// MUST respond with the 400 (Bad Request) status code and then close the
// connection." §6.1: a server that receives a transfer coding it does not
// understand "SHOULD respond with 501". So `chunked, gzip` frames nothing → 400,
// while `gzip, chunked` still ends where its chunked stream ends → 501, and the
// difference is a status a driver will actually send.
#[test]
fn a_misplaced_chunked_is_a_400_and_an_undecodable_one_a_501() {
  let misplaced = refused(
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
    SuggestedStatus::BadRequest,
    Reason::Framing(why::CHUNKED_NOT_FINAL),
  );
  assert!(misplaced.seen.is_empty(), "{:?}", misplaced.seen);

  let undecodable = refused(
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
    SuggestedStatus::NotImplemented,
    Reason::UnsupportedCoding(why::ONLY_CHUNKED),
  );
  assert!(undecodable.seen.is_empty(), "{:?}", undecodable.seen);

  for (wire, status, reason) in [
    // RFC 9110 §5.3 folds repeated field lines into one comma-separated list, so
    // the SAME two lists arrive spread over two lines — and a recipient that
    // framed the message off the first line alone would read a chunked body
    // where the sender wrote none. The fold decides both statuses identically.
    (
      b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n"
        .as_slice(),
      SuggestedStatus::BadRequest,
      Reason::Framing(why::CHUNKED_NOT_FINAL),
    ),
    (
      b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
      SuggestedStatus::NotImplemented,
      Reason::UnsupportedCoding(why::ONLY_CHUNKED),
    ),
    // A coding with no chunked anywhere is the same 501: nothing frames it, and
    // nothing here can decode it either.
    (
      b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n",
      SuggestedStatus::NotImplemented,
      Reason::UnsupportedCoding(why::ONLY_CHUNKED),
    ),
    // A list naming no coding at all frames nothing and names nothing to
    // decode, so item 4's 400 is what is left — and the REASON is what tells
    // this vector apart from the misplaced-chunked one above, which shares its
    // status.
    (
      b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: \r\n\r\n",
      SuggestedStatus::BadRequest,
      Reason::Framing(why::NO_CODING),
    ),
  ] {
    let refusal = refused(wire, status, reason);
    assert!(refusal.seen.is_empty(), "{:?}", refusal.seen);
  }
}

// RFC 9110 §5.3 with RFC 9112 §9.6: a `Connection` field spread over two lines is
// ONE list, so a `close` on the second line ends keep-alive exactly as it would
// on the first. A recipient that read only the first line would keep the
// connection alive and go on processing the request pipelined behind it — a
// request the sender has already stopped expecting an answer to, and the shape
// §9.6 makes a MUST-not.
#[test]
fn split_connection_lines_fold_into_one_list() {
  const CLOSING: &[u8] =
    b"GET /a HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n";
  let closed = accepted(&stream(&[CLOSING, FOLLOWER]));
  assert_eq!(
    closed.seen,
    [
      head(
        1,
        "GET",
        "/a",
        &[
          ("Host", b"h"),
          ("Connection", b"keep-alive"),
          ("Connection", b"close"),
        ]
      ),
      Seen::Complete { exchange: 1 },
    ]
  );
  assert_eq!(closed.events, [Event::CloseSignaled]);
  // The follower was never read: §9.6 stops the connection at the message that
  // announced the close, whatever is buffered behind it. The consumed count is
  // the closing request and NOT one byte more.
  assert_eq!(closed.answers, 1);
  assert_eq!(closed.consumed, CLOSING.len());
  assert!(!closed.connection.wants_read());

  // The accept side of the same fold: with only the `keep-alive` line, the
  // connection survives and the follower becomes exchange 2.
  let kept = accepted(&stream(&[
    b"GET /a HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\n\r\n",
    FOLLOWER,
  ]));
  assert_eq!(kept.events, []);
  assert_eq!(kept.seen.last(), Some(&Seen::Complete { exchange: 2 }));
  assert_eq!(kept.answers, 2);
}

// RFC 9112 §7.1.2 with §6.3 item 3: a trailer section is a field section, and
// nothing more. A `Content-Length` that arrives AFTER the last chunk cannot
// re-frame a body the chunked coding has already delimited — the framing
// decision was made from the head, before a single body octet — so it surfaces
// as a plain `Item::Trailer` and the message still ends at the trailer section's
// empty line. A recipient that let it re-frame would read the next request as 99
// octets of this one's body, which is the pipelined follower's job to disprove.
#[test]
fn a_content_length_trailer_is_a_trailer_and_frames_nothing() {
  let observed = accepted(&stream(&[
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"1\r\na\r\n0\r\nContent-Length: 99\r\nX-Sum: ok\r\n\r\n",
    FOLLOWER,
  ]));
  assert_eq!(
    observed.seen,
    [
      head(
        1,
        "POST",
        "/u",
        &[("Host", b"h"), ("Transfer-Encoding", b"chunked")]
      ),
      Seen::Body {
        exchange: 1,
        data: b"a".to_vec(),
      },
      Seen::Trailer {
        exchange: 1,
        name: "Content-Length".to_owned(),
        value: b"99".to_vec(),
      },
      Seen::Trailer {
        exchange: 1,
        name: "X-Sum".to_owned(),
        value: b"ok".to_vec(),
      },
      Seen::Complete { exchange: 1 },
      head(2, "GET", "/next", &[("Host", b"h")]),
      Seen::Complete { exchange: 2 },
    ]
  );
  assert_eq!(observed.answers, 2);

  // The same trailer with a `Transfer-Encoding` in it: also just a field.
  let coded = accepted(&stream(&[
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"1\r\na\r\n0\r\nTransfer-Encoding: chunked\r\n\r\n",
    FOLLOWER,
  ]));
  assert_eq!(
    coded.seen.get(2),
    Some(&Seen::Trailer {
      exchange: 1,
      name: "Transfer-Encoding".to_owned(),
      value: b"chunked".to_vec(),
    })
  );
  assert_eq!(coded.seen.last(), Some(&Seen::Complete { exchange: 2 }));
}

// RFC 9112 §6.3 items 4-5 and §6.1 taken literally: a server that cannot frame
// what it received "MUST respond with a 400 (Bad Request) status code and then
// close the connection". The answer goes out ONCE, carries the `close` the MUST
// requires, and leaves the connection draining — and it is owed from BOTH latch
// shapes, which is why this test drives two.
#[test]
fn the_single_error_response_goes_out_once_and_states_close() {
  // Shape 1: the fault is in the head, so no exchange was ever opened and the
  // 400 answers a message this connection never accepted.
  let mut in_the_head = refused(
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
    SuggestedStatus::BadRequest,
    Reason::Framing(why::BOTH_FRAMINGS),
  );
  let status = in_the_head
    .failure
    .as_ref()
    .and_then(Error::suggested_status)
    .expect("a wire violation always suggests a status");
  let mut out = [0u8; 128];
  let written = in_the_head
    .connection
    .send_error_response(status.code(), b"Bad Request", NO_FIELDS, &mut out)
    .expect("the single error response a failed server still owes");
  assert_eq!(
    out.get(..written),
    Some(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".as_slice())
  );
  // §9.6's notice, exactly once, and then a drained connection.
  assert_eq!(
    in_the_head.connection.poll_event(),
    Some(Event::CloseSignaled)
  );
  assert_eq!(in_the_head.connection.poll_event(), None);
  assert!(!in_the_head.connection.is_awaiting_send());
  assert!(!in_the_head.connection.wants_read());
  // A second answer would be appended to bytes the peer is already reading as
  // the first (§11.1), so there is no second answer.
  assert!(matches!(
    in_the_head
      .connection
      .send_error_response(400, b"Bad Request", NO_FIELDS, &mut out),
    Err(Error::InvalidState(_))
  ));

  // Shape 2: the fault is in the BODY, so the request was already handed over
  // and its response was already owed — the error response takes that response's
  // place rather than following it.
  let mut in_the_body = refused(
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5 \r\nhello\r\n",
    SuggestedStatus::BadRequest,
    Reason::Malformed(why::WS_AFTER_CHUNK_SIZE),
  );
  assert_eq!(in_the_body.seen.len(), 1, "the head was delivered");
  let written = in_the_body
    .connection
    .send_error_response(400, b"Bad Request", NO_FIELDS, &mut out)
    .expect("a fault found in the body owes the same single error response");
  assert_eq!(
    out.get(..written),
    Some(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".as_slice())
  );
  assert!(matches!(
    in_the_body
      .connection
      .send_error_response(400, b"Bad Request", NO_FIELDS, &mut out),
    Err(Error::InvalidState(_))
  ));

  // The 501 vector answers with the status IT suggests, which is the whole point
  // of `suggested_status` being read rather than hard-coded (RFC 9110 §15.6.2).
  let mut undecodable = refused(
    b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
    SuggestedStatus::NotImplemented,
    Reason::UnsupportedCoding(why::ONLY_CHUNKED),
  );
  let status = undecodable
    .failure
    .as_ref()
    .and_then(Error::suggested_status)
    .expect("a wire violation always suggests a status");
  assert_eq!(status.code(), 501);
  let written = undecodable
    .connection
    .send_error_response(status.code(), b"Not Implemented", NO_FIELDS, &mut out)
    .expect("the single error response a failed server still owes");
  assert_eq!(
    out.get(..written),
    Some(b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n".as_slice())
  );
}

// The harness's own regression test, kept rather than run once by hand: every
// assertion this file makes rests on the mirror recording what the stream
// states, so each field of it has to be able to FAIL. One mutation per field,
// plus the two properties the accept/refuse helpers are built on.
#[test]
fn the_harness_records_what_the_stream_states() {
  let truth = accepted(&stream(&[
    b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 42, 42\r\n\r\n",
    DECOY,
    FOLLOWER,
  ]));

  // A changed target, which is the field `assert_nothing_smuggled` reads.
  let mut retargeted = truth.seen.clone();
  match retargeted.first_mut() {
    Some(Seen::Head { target, .. }) => target.push('x'),
    other => panic!("the first item is the request head, not {other:?}"),
  }
  assert_ne!(retargeted, truth.seen);

  // Changed body octets, same length: the mirror compares the sequence rather
  // than counting it, which is what makes the framing assertion real.
  let mut rewritten = truth.seen.clone();
  match rewritten.get_mut(1) {
    Some(Seen::Body { data, .. }) => data.reverse(),
    other => panic!("the second item is the body, not {other:?}"),
  }
  assert_ne!(rewritten, truth.seen);

  // A missing item, and a re-ordered pair.
  let mut dropped = truth.seen.clone();
  dropped.remove(1);
  assert_ne!(dropped, truth.seen);
  let mut swapped = truth.seen.clone();
  swapped.swap(0, 1);
  assert_ne!(swapped, truth.seen);

  // The framing is the announced 42 and not "whatever arrived": one octet short
  // leaves the body incomplete, so the exchange never completes, nothing is
  // answered, and the follower is never read.
  let short = serve(&stream(&[
    b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 42, 42\r\n\r\n",
    DECOY.get(..41).expect("the decoy is 42 octets"),
  ]));
  assert!(short.failure.is_none(), "a short body is not a violation");
  assert!(
    !short
      .seen
      .iter()
      .any(|seen| matches!(seen, Seen::Complete { .. })),
    "a body one octet short completed the exchange"
  );
  assert_eq!(short.answers, 0);
  assert!(short.connection.wants_read());

  // And the refusal helper is not vacuous either: a stream this core accepts
  // produces no failure at all, so a `refused` that passed on it would be
  // reporting a fault that is not there.
  assert!(serve(BODILESS).failure.is_none());
}

/// This file's own source, for the corpus floor below.
const SOURCE: &str = include_str!("smuggling.rs");

// A FLOOR on the corpus, and a check that every refusal constant it carries is
// actually named by a vector.
//
// Measured off the source text because the vectors live inside their test
// functions rather than in one list — a deliberate shape, since each carries its
// own accept side and its own item-sequence assertion. What that shape cannot do
// is notice a silently deleted vector, which is what this adds. The floor sits
// below the current count so ordinary additions need not touch it, and high
// enough that removing a table would fail.
#[test]
fn the_corpus_keeps_its_vectors() {
  let refusals = SOURCE.matches("Reason::").count();
  assert!(
    refusals >= 30,
    "the corpus lost vectors: {refusals} `Reason::` references"
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
