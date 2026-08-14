//! Split robustness: WHERE the transport split the bytes must not change WHAT
//! the connection says about them.
//!
//! A Sans-I/O core is handed whatever the socket happened to return. RFC 9112
//! §2.1 defines a message over the byte stream and nowhere over the reads that
//! carried it, so a driver that saw `GET / HTTP/1.1\r\n\r\n` in one read and one
//! that saw it in twenty-eight must reach the same conclusion. This suite states
//! that as a property and checks it over a corpus of valid full-connection
//! streams, in three feed shapes: one shot, one byte at a time, and
//! proptest-generated cut vectors.
//!
//! An INTEGRATION test on purpose: everything below is written against the
//! crate's public API alone, so it doubles as an audit of whether that API is
//! enough to write a driver with.
//!
//! # The reference driver
//!
//! [`drive`] is the pattern a real caller follows, and the one the README
//! example will teach:
//!
//! 1. Append what the transport returned to an APPEND-ONLY buffer.
//! 2. Offer the buffer FROM ITS UNCONSUMED START to `handle`, and pull
//!    `Items::next` until it answers `Ok(None)`.
//! 3. Advance the unconsumed cursor by `Items::consumed`. Nothing is copied
//!    back, nothing is compacted: the tail that was not consumed is re-offered
//!    next time with the new bytes behind it, which is how a message split
//!    across reads gets assembled without a buffer inside the core.
//! 4. Drain `poll_event`.
//! 5. Ask WHY the items ran out — `Ok(None)` alone cannot say whether to read
//!    the socket or to write to it, so [`Connection::wants_read`] and
//!    [`Connection::is_awaiting_send`] are what the loop branches on. The two
//!    are disjoint answers, which the driver asserts on every pass.
//! 6. At end of input, call `handle_eof` once, then re-offer the buffer until
//!    the connection stops producing — an empty offer is sufficient.
//!
//! The pipelined corpus entry needs step 5 to be real: RFC 9112 §9.3.2 holds the
//! second request's bytes unconsumed until the first response is written, so the
//! driver ANSWERS with `send_response` whenever `is_awaiting_send` reports the
//! stall, and the response boundary is mirrored as `Mirror::Sent`. Without that
//! interleave the second exchange never appears in any feed shape.
//!
//! # What "identical" means, exactly
//!
//! Structural equality over an owned [`Mirror`] of every item, every outcome and
//! every send boundary, plus the event sequence, plus the total consumed count.
//! Two normalizations are built into the mirror, and neither weakens the
//! property:
//!
//! - **Body chunks are coalesced per exchange.** RFC 9112 §6.3 delivers body
//!   octets "as they arrive": the SPLIT of a body into `Item::BodyChunk`s is the
//!   transport's, and asserting it were asserting that the core re-frames the
//!   caller's reads, which it deliberately does not. The octet SEQUENCE and its
//!   position among the other items are the message's, and those are compared.
//! - **Events are their own sequence.** An `Event` is a fact about the
//!   connection rather than about any byte, and `poll_event` is drained after
//!   the items of a feed — so how many items sit between an event and the one
//!   that queued it is a function of how much input that feed carried. The event
//!   ORDER is not, and it is compared in full.
//!
//! Start lines are compared in both modes — `Item::Head` carries the parsed
//! `StartLine` — but "in full" would overstate it, so here is exactly what the
//! mirror keeps and what it drops:
//!
//! - A REQUEST line contributes its method and its request-target (RFC 9112 §3).
//! - A STATUS line contributes its status-code (§4).
//! - The VERSION is dropped from both, and the REASON-PHRASE from the status
//!   line. Neither can vary with the split — the version is a fixed field of the
//!   corpus entry's own bytes and §4 makes the reason-phrase advisory — so
//!   mirroring them would add no failure mode this property can produce.
//!   [`a_driver_reads_the_start_line_through_public_names`] is where both ARE
//!   asserted, over the same public names, which is why dropping them here costs
//!   no coverage.
//! - A TUNNEL outcome contributes its head's field lines, and for a refusal its
//!   status-code; the `StatusLine` the `Interim` and `Tunneled` variants also
//!   carry is not mirrored, for the same reason the version is not.
//!
//! [`a_driver_reads_the_start_line_through_public_names`] is the other half of
//! the start-line coverage: not a split property, but the consumption shape
//! this suite's mirror depends on, written the way a driver outside this crate
//! has to write it.
//!
//! # The linearity probe
//!
//! [`byte_at_a_time_head_parse_stays_linear`] pins the cost shape: the head
//! scan resumes from its watermark instead of restarting, so feeding a
//! `MAX_HEAD_BYTES`-sized head one byte at a time costs O(N) scanning rather
//! than O(N²). Its mechanism and its CI safety are documented on the test.

use core::time::Duration;
use std::time::Instant;

use http1_proto::{
  BodyPlan, Client, ClientTunnelOutcome, Connection, Event, General, HeadView, Item, Items,
  MAX_HEAD_BYTES, Server, StartLine, Target, Tunnel, Version,
};
use proptest::prelude::*;

/// The RFC 9112 §3.2.1 origin-form target every request in this file opens with.
const ORIGIN: Target<'static> = Target::Origin {
  path_and_query: "/",
};

/// The one field RFC 9112 §3.2 requires of a request that is not about framing.
const HOST: &[(&str, &[u8])] = &[("Host", b"h")];

/// What the driver's stock response announces. RFC 9112 §6.3 item 8 makes a
/// response carrying NO framing field close-delimited, which is not what a
/// keep-alive answer means — so a bodiless one says `Content-Length: 0`.
const LENGTH_0: &[(&str, &[u8])] = &[("Content-Length", b"0")];

/// The response bytes [`Endpoint::respond`] writes, spelled out so the corpus
/// pins the message rather than merely counting it.
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

/// RFC 9110 §7.8 wants both halves of an upgrade offer: the `upgrade`
/// connection option and an `Upgrade` field naming a protocol.
const OFFER: &[(&str, &[u8])] = &[
  ("Host", b"example.com"),
  ("Connection", b"Upgrade"),
  ("Upgrade", b"websocket"),
];

/// RFC 9110 §9.3.6's CONNECT names its destination in the request-target, so its
/// field section carries only the authority RFC 9112 §3.2 asks for.
const CONNECT_FIELDS: &[(&str, &[u8])] = &[("Host", b"example.com:443")];

/// The RFC 9112 §3.2.3 `uri-host ":" port` target of the CONNECT entry. The port
/// is not optional: RFC 9110 §9.3.6 makes sending it a client MUST.
const AUTHORITY: &str = "example.com:443";

/// Which driver shape a corpus entry needs, and which end of the connection it
/// is driven from.
#[derive(Debug, Copy, Clone)]
enum Kind {
  /// General mode, reading requests: the items pump plus the response the
  /// keep-alive gate waits on.
  Server,
  /// General mode, reading responses: the client opens its request first, since
  /// RFC 9112 §9.2 makes bytes arriving with nothing outstanding not a response
  /// at all.
  Client,
  /// Tunnel mode, RFC 9110 §7.8's protocol upgrade.
  Upgrade,
  /// Tunnel mode, RFC 9110 §9.3.6's CONNECT tunnel.
  Connect,
}

/// One valid full-connection byte stream, and how to drive it.
#[derive(Debug, Copy, Clone)]
struct Entry {
  /// What the stream is, for the assertion messages.
  name: &'static str,
  /// Which driver shape reads it.
  kind: Kind,
  /// The bytes a peer would send, in order.
  stream: &'static [u8],
}

/// The corpus: one valid stream per shape the inbound path can take.
const CORPUS: &[Entry] = &[
  // RFC 9112 §6.3 item 7: a request with no framing field has no body, so its
  // whole message is its head.
  Entry {
    name: "simple GET",
    kind: Kind::Server,
    stream: b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n",
  },
  // RFC 9112 §6.3 item 6: `Content-Length` frames the body exactly.
  Entry {
    name: "POST with Content-Length",
    kind: Kind::Server,
    stream: b"POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\nhello world",
  },
  // RFC 9112 §7.1 with §7.1.1 (`chunk-ext`) and §7.1.2 (the trailer section):
  // the framing lines are the coding's own and no item ever carries them, so a
  // split inside one must still leave the same body octets and trailers.
  Entry {
    name: "chunked with extensions and trailers",
    kind: Kind::Server,
    stream: b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n\
              3;a=b\r\nabc\r\n5;x=\"y z\"\r\nhello\r\n0\r\nX-T: v\r\nX-U: w\r\n\r\n",
  },
  // RFC 9110 §10.1.1: the expectation is stated before any body octet, because
  // the point of it is that the body has not been sent yet.
  Entry {
    name: "expect-continue then body",
    kind: Kind::Server,
    stream: b"POST /e HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\nhi",
  },
  // RFC 9112 §9.3.2: the second request waits unconsumed until the first
  // response is written, and the ids the core mints record the order.
  Entry {
    name: "pipelined request pair",
    kind: Kind::Server,
    stream: b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n",
  },
  // RFC 9112 §9.3: an HTTP/1.0 request without `keep-alive` is the last on the
  // connection, so §9.6 leaves the request pipelined behind it unread.
  Entry {
    name: "HTTP/1.0 request ends the connection",
    kind: Kind::Server,
    stream: b"GET /a HTTP/1.0\r\nHost: h\r\n\r\nGET /b HTTP/1.0\r\nHost: h\r\n\r\n",
  },
  // RFC 9110 §15.2: any number of interim responses may precede the final one,
  // on the same exchange, and a client MUST parse them.
  Entry {
    name: "interim then final response",
    kind: Kind::Client,
    stream: b"HTTP/1.1 100 \r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
  },
  // RFC 9112 §6.3 item 8: an HTTP/1.0 response with no framing field is
  // delimited by the close, so the EOF is what completes the exchange.
  Entry {
    name: "HTTP/1.0 close-delimited response",
    kind: Kind::Client,
    stream: b"HTTP/1.0 200 OK\r\n\r\nhello",
  },
  // RFC 9110 §15.2.2: the 101 ends HTTP framing, and everything behind that head
  // is the new protocol's — including whatever the server pipelined into the
  // same read.
  Entry {
    name: "upgrade tunnel with an interim",
    kind: Kind::Upgrade,
    stream: b"HTTP/1.1 100 \r\n\r\nHTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x03abc",
  },
  // RFC 9110 §9.3.6: "any 2xx (Successful) response indicates that the sender …
  // will switch to tunnel mode immediately after the response header section".
  Entry {
    name: "CONNECT tunnel",
    kind: Kind::Connect,
    stream: b"HTTP/1.1 200 Connection Established\r\n\r\n\x16\x03\x01raw",
  },
  // RFC 9110 §7.8: "Upgrade cannot be used to insist on a protocol change" — a
  // refusal is terminal for the handshake, and it consumes the head it read, so
  // the driver stops with the refusal's content in front of it.
  Entry {
    name: "refused upgrade offer",
    kind: Kind::Upgrade,
    stream: b"HTTP/1.1 426 Upgrade Required\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\
              Content-Length: 0\r\n\r\n",
  },
  // RFC 9112 §6.3 item 6 behind a refusal: the head that refuses counts its own
  // content, and the leftover is where those octets begin. Not decoded here —
  // Tunnel mode has no body machinery — which is exactly why the offset has to
  // come out of the outcome rather than out of a second scan by the caller.
  Entry {
    name: "refused CONNECT with a counted body",
    kind: Kind::Connect,
    stream: b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 12\r\n\r\nneed a token",
  },
  // RFC 9112 §6.3 item 4: the same, with the content chunked. The coding's own
  // framing lines are part of the leftover, because nothing decodes them here.
  Entry {
    name: "refused CONNECT with a chunked body",
    kind: Kind::Connect,
    stream: b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"proxy\"\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\ntoken\r\n0\r\n\r\n",
  },
  // RFC 9112 §6.3 item 8: neither framing field, so the content is however many
  // octets arrive before the close. The leftover is what arrived, which is the
  // suffix contract rather than a framed message.
  Entry {
    name: "refused upgrade with a close-delimited body",
    kind: Kind::Upgrade,
    stream: b"HTTP/1.1 403 Forbidden\r\n\r\nthis realm does not upgrade",
  },
];

/// One owned, comparable copy of a head's start line (RFC 9112 §2.1).
///
/// The facts a driver acts on, not the whole parsed line: what a server routes
/// on is the §3 method and request-target, and what a client acts on is the §4
/// status-code. A target is mirrored as the text it addresses — the four §3.2
/// forms are textually distinct (only the asterisk-form is a bare `*`, and only
/// the origin-form starts with `/`), so the form survives the flattening.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
  /// RFC 9112 §3 `request-line`.
  Request {
    /// The method, case-sensitive (RFC 9110 §9.1).
    method: String,
    /// The request-target, as text.
    target: String,
  },
  /// RFC 9112 §4 `status-line`.
  Status {
    /// The status-code.
    code: u16,
  },
}

/// Mirrors the start line a head carried, through the public `StartLine` names a
/// driver outside this crate has.
fn line_of(line: StartLine<'_>) -> Line {
  match line {
    StartLine::Request(request) => Line::Request {
      method: request.method.to_owned(),
      target: match request.target {
        Target::Origin { path_and_query } => path_and_query.to_owned(),
        Target::Absolute { uri } => uri.to_owned(),
        Target::Authority { host_port } => host_port.to_owned(),
        Target::Asterisk => "*".to_owned(),
      },
    },
    StartLine::Status(status) => Line::Status { code: status.code },
    // `StartLine` is `#[non_exhaustive]`, so a consumer outside the crate owes
    // this arm. It panics rather than mirroring nothing: a start line this
    // mirror dropped would make two different heads compare equal, which is the
    // one thing an equality property must not do.
    other => panic!("a start line this corpus does not model: {other:?}"),
  }
}

/// One owned, comparable copy of something the driver observed.
///
/// Owned because the real thing is borrowed from the buffer that is about to
/// grow, and comparable because the whole property is an equality between two
/// runs. `Item` itself is deliberately neither (a head is matched on, not
/// compared — see `Item`'s own doc), so the mirror states which parts of a head
/// this suite holds the core to: its exchange, whether it was interim, the start
/// line above its fields, the field count the scan recorded, and every field line
/// the lazy view walks back.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mirror {
  /// `Item::Head`.
  Head {
    /// The exchange the head belongs to.
    exchange: u64,
    /// Whether it was a 1xx that does not end the exchange (RFC 9110 §15.2).
    interim: bool,
    /// The start line above the fields, owned.
    line: Line,
    /// What the SCAN counted, which is a different code path from the walk
    /// below.
    field_count: usize,
    /// Every field line, in arrival order, OWS-trimmed.
    fields: Vec<(String, Vec<u8>)>,
  },
  /// A run of `Item::BodyChunk`s for one exchange, coalesced — see the module
  /// doc for why the split is not part of the property.
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
  /// A message THIS end wrote, verbatim: the request a client opens with, and
  /// the response that discharges RFC 9112 §9.3.2's re-arm gate. In the item
  /// order because it is a boundary in it — the bytes after it are only readable
  /// once it has gone out.
  Sent(Vec<u8>),
  /// `handle_eof` and the re-offer that follows it: the completion that offer
  /// hands over, if any (§6.3 item 8's close-delimited message is the one entry
  /// that produces one).
  Eof {
    /// The exchange the close completed, if any.
    completed: Option<u64>,
  },
  /// `ClientTunnelOutcome::Interim`: a head consumed with the handshake still
  /// open.
  TunnelInterim {
    /// The interim head's field lines.
    fields: Vec<(String, Vec<u8>)>,
  },
  /// `ClientTunnelOutcome::Switched` (RFC 9110 §15.2.2) or `Tunneled` (§9.3.6).
  TunnelSwitched {
    /// Whether the switch was CONNECT's tunnel rather than an upgrade.
    connect: bool,
    /// The switching head's field lines.
    fields: Vec<(String, Vec<u8>)>,
  },
  /// `ClientTunnelOutcome::Refused`: terminal for the handshake, and it reports
  /// where the head ended like every other consuming outcome.
  TunnelRefused {
    /// The status that refused (RFC 9112 §4).
    code: u16,
    /// The refusing head's field lines.
    fields: Vec<(String, Vec<u8>)>,
  },
  /// Everything the tunnel driver hands to the next protocol: the leftover the
  /// outcome reported, plus every byte the driver had not fed yet. Which of the
  /// two a byte came from is exactly what the feed shape decides, so the tail is
  /// mirrored whole.
  TunnelTail(Vec<u8>),
}

impl Mirror {
  /// Whether this entry is evidence that the connection UNDERSTOOD something the
  /// peer sent.
  ///
  /// The vacuity guard's whole question, and the three `false` arms are what
  /// make it worth asking. `Sent` is this end's own message; `Eof` and
  /// `TunnelTail` are the driver's stopping-point bookkeeping, pushed
  /// unconditionally at the end of every run — none of the three would be
  /// missing from the log of a driver that had recorded no item at all, and a
  /// guard they satisfied would pass such a driver. The equality checks would
  /// pass it too, since a recording bug is shape-independent and degrades all
  /// three feed shapes identically. So the guard demands one of the variants
  /// only a parsed byte can produce.
  fn is_from_the_peer(&self) -> bool {
    match self {
      Self::Head { .. }
      | Self::Body { .. }
      | Self::Trailer { .. }
      | Self::Complete { .. }
      | Self::ExpectContinue { .. }
      | Self::TunnelInterim { .. }
      | Self::TunnelSwitched { .. }
      | Self::TunnelRefused { .. } => true,
      Self::Sent(_) | Self::Eof { .. } | Self::TunnelTail(_) => false,
    }
  }
}

/// Everything one run of a driver observed.
///
/// Compared whole: the item/outcome sequence, the event sequence, and the total
/// bytes consumed. Equality of all three across feed shapes IS the property.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Drive {
  /// The items, outcomes and send boundaries, in order.
  log: Vec<Mirror>,
  /// The connection-scoped notices, in order (see the module doc).
  events: Vec<Event>,
  /// Bytes of the stream the connection took ownership of, summed over feeds.
  consumed: usize,
}

/// A General-mode connection at either end, so the reference driver below is ONE
/// loop rather than one per role.
///
/// An enum rather than a trait: `Items` is not generic over the role, so both
/// arms hand back the same iterator type and the loop never learns which end it
/// is driving.
enum Endpoint {
  /// Reads requests, writes responses.
  Server(Connection<Server, General>),
  /// Writes one request, reads its response.
  Client(Connection<Client, General>),
}

impl Endpoint {
  /// The request a client owes before anything it reads can be a response (RFC
  /// 9112 §9.2). A server opens nothing.
  fn open(&mut self) -> Option<Vec<u8>> {
    match self {
      Self::Server(_) => None,
      Self::Client(client) => {
        let mut out = [0u8; 64];
        let written = client
          .open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut out)
          .expect("a bodiless GET is openable on a fresh client");
        Some(out[..written].to_vec())
      }
    }
  }

  /// Offers the driver's buffer from its unconsumed start.
  fn handle<'a>(&mut self, input: &'a [u8]) -> Items<'a, '_> {
    match self {
      Self::Server(server) => server.handle(input),
      Self::Client(client) => client.handle(input),
    }
  }

  /// Whether more transport bytes would help — step 5's read half.
  fn wants_read(&self) -> bool {
    match self {
      Self::Server(server) => server.wants_read(),
      Self::Client(client) => client.wants_read(),
    }
  }

  /// Whether the LOCAL send side is what is missing — step 5's write half.
  fn is_awaiting_send(&self) -> bool {
    match self {
      Self::Server(server) => server.is_awaiting_send(),
      Self::Client(client) => client.is_awaiting_send(),
    }
  }

  /// The next queued connection-scoped notice.
  fn poll_event(&mut self) -> Option<Event> {
    match self {
      Self::Server(server) => server.poll_event(),
      Self::Client(client) => client.poll_event(),
    }
  }

  /// Writes the stock response, which is what discharges RFC 9112 §9.3.2's
  /// re-arm gate and makes a pipelined request readable.
  ///
  /// One policy for every server entry: the corpus is about what the INBOUND
  /// path does with split bytes, so the answer is the same bodiless 200 each
  /// time. A client is never in this state — its send side completed with the
  /// bodiless request it opened.
  fn respond(&mut self) -> Vec<u8> {
    match self {
      Self::Server(server) => {
        let mut out = [0u8; 64];
        let written = server
          .send_response(200, b"OK", LENGTH_0, BodyPlan::None, &mut out)
          .expect("a bodiless 200 answers every request in the corpus");
        assert_eq!(&out[..written], RESPONSE);
        out[..written].to_vec()
      }
      Self::Client(_) => unreachable!("a client owes no response in this corpus"),
    }
  }

  /// Reports the end of the transport, once.
  ///
  /// It yields nothing: `handle_eof` observes the transport and no more, so
  /// every conclusion that depends on the absence of further bytes — a
  /// truncation, the drain, and §6.3 item 8's close-delimited completion — is
  /// drawn on the re-offer that follows, where the driver's buffer is visible.
  fn handle_eof(&mut self) {
    let ended = match self {
      Self::Server(server) => server.handle_eof(),
      Self::Client(client) => client.handle_eof(),
    };
    match ended.expect("the corpus ends every message it starts") {
      None => {}
      Some(other) => unreachable!("handle_eof yields no item, not {other:?}"),
    }
  }
}

/// Splits `stream` at `cuts`, which are normalized first: out-of-range and
/// repeated points name no split, and the order they were generated in does not
/// change the segments they describe.
fn segments<'a>(stream: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
  let mut points: Vec<usize> = cuts
    .iter()
    .copied()
    .filter(|&at| at > 0 && at < stream.len())
    .collect();
  points.sort_unstable();
  points.dedup();

  let mut out = Vec::with_capacity(points.len().saturating_add(1));
  let mut at = 0;
  for point in points {
    out.push(&stream[at..point]);
    at = point;
  }
  out.push(&stream[at..]);
  out
}

/// The field lines of a head, owned.
fn fields_of(view: &HeadView<'_>) -> Vec<(String, Vec<u8>)> {
  view
    .headers()
    .map(|(name, value)| (name.to_owned(), value.to_vec()))
    .collect()
}

/// Mirrors one item, coalescing a body run into the entry before it.
fn record(log: &mut Vec<Mirror>, item: Item<'_>) {
  match item {
    Item::Head {
      exchange,
      view,
      line,
      interim,
    } => log.push(Mirror::Head {
      exchange: exchange.get(),
      interim,
      line: line_of(line),
      field_count: view.field_count(),
      fields: fields_of(&view),
    }),
    Item::BodyChunk { exchange, data } => {
      if let Some(Mirror::Body {
        exchange: at,
        data: run,
      }) = log.last_mut()
        && *at == exchange.get()
      {
        run.extend_from_slice(data);
      } else {
        log.push(Mirror::Body {
          exchange: exchange.get(),
          data: data.to_vec(),
        });
      }
    }
    Item::Trailer {
      exchange,
      name,
      value,
    } => log.push(Mirror::Trailer {
      exchange: exchange.get(),
      name: name.to_owned(),
      value: value.to_vec(),
    }),
    Item::ExchangeComplete { exchange } => log.push(Mirror::Complete {
      exchange: exchange.get(),
    }),
    Item::ExpectContinue { exchange } => log.push(Mirror::ExpectContinue {
      exchange: exchange.get(),
    }),
    // `Item` is `#[non_exhaustive]`, so a consumer outside the crate owes this
    // arm. It PANICS rather than being dropped: an unmirrored item would make a
    // feed shape that produced it compare equal to one that did not, and this
    // whole suite is that equality.
    other => panic!("an item this corpus does not model: {other:?}"),
  }
}

/// The reference driver over a General-mode connection: the loop the module doc
/// describes, run over `stream` delivered in the pieces `cuts` names.
fn drive(mut endpoint: Endpoint, stream: &[u8], cuts: &[usize]) -> Drive {
  let mut drive = Drive::default();
  if let Some(request) = endpoint.open() {
    drive.log.push(Mirror::Sent(request));
  }

  // APPEND-ONLY, and never compacted: `handle` is offered `buffer[start..]`, so
  // what was not consumed is re-presented with the next read behind it. That is
  // the whole assembly mechanism — the core keeps no buffer of its own.
  let mut buffer: Vec<u8> = Vec::new();
  let mut start = 0usize;

  'feed: for segment in segments(stream, cuts) {
    buffer.extend_from_slice(segment);
    loop {
      let consumed = {
        let mut items = endpoint.handle(&buffer[start..]);
        while let Some(item) = items.next().expect("every corpus stream is valid HTTP/1.1") {
          record(&mut drive.log, item);
        }
        items.consumed()
      };
      start = start.saturating_add(consumed);
      drive.consumed = drive.consumed.saturating_add(consumed);
      // The consumption contract, checked rather than assumed: a count past the
      // offer would have the driver skipping bytes the peer sent.
      assert!(
        start <= buffer.len(),
        "the connection consumed bytes it was never offered"
      );
      while let Some(event) = endpoint.poll_event() {
        drive.events.push(event);
      }

      // The two halves of the readiness split answer different questions and
      // are never both true — reading cannot clear a stall on the send side,
      // and a connection waiting for its own writer wants no bytes.
      assert!(
        !(endpoint.wants_read() && endpoint.is_awaiting_send()),
        "wants_read and is_awaiting_send both reported progress"
      );
      if endpoint.is_awaiting_send() {
        // RFC 9112 §9.3.2: the bytes already buffered become the next exchange
        // once this goes out, so the loop re-offers them without another read.
        let response = endpoint.respond();
        drive.log.push(Mirror::Sent(response));
        continue;
      }
      if endpoint.wants_read() {
        continue 'feed;
      }
      // Neither: RFC 9112 §9.6's drained connection, where no further inbound
      // byte is processed however many are left in the stream.
      break 'feed;
    }
  }

  // The documented EOF step: report it, then keep offering the buffer until the
  // connection stops producing. An empty offer is sufficient and is what
  // resolves an EOF taken at a message boundary.
  endpoint.handle_eof();
  let mut completed = None;
  {
    let offer = buffer.get(start..).unwrap_or_default();
    let mut items = endpoint.handle(offer);
    while let Some(item) = items
      .next()
      .expect("the corpus ends every message it starts")
    {
      if let Item::ExchangeComplete { exchange } = item {
        completed = Some(exchange.get());
      } else {
        record(&mut drive.log, item);
      }
    }
    drive.consumed = drive.consumed.saturating_add(items.consumed());
  }
  drive.log.push(Mirror::Eof { completed });
  drive
}

/// The tunnel driver: the same accumulation contract over the one handshake a
/// `Connection<Client, Tunnel>` carries.
///
/// The leftover contract replaces `Items::consumed` here — every outcome that
/// consumed a head reports where the bytes behind it begin — and [`taken_of`]
/// checks it rather than trusting it.
fn drive_tunnel(connect: bool, stream: &[u8], cuts: &[usize]) -> Drive {
  let mut drive = Drive::default();
  let mut connection = Connection::<Client, Tunnel>::new();
  let mut out = [0u8; 256];
  let written = if connect {
    connection
      .open_connect(AUTHORITY, CONNECT_FIELDS, &mut out)
      .expect("a CONNECT with a port opens the handshake")
  } else {
    connection
      .open_upgrade(&ORIGIN, OFFER, &mut out)
      .expect("an offer stating both halves opens the handshake")
  };
  drive.log.push(Mirror::Sent(out[..written].to_vec()));

  let mut buffer: Vec<u8> = Vec::new();
  let mut start = 0usize;
  'feed: for segment in segments(stream, cuts) {
    buffer.extend_from_slice(segment);
    loop {
      let offer = &buffer[start..];
      let taken = match connection
        .handle_response(offer)
        .expect("every corpus stream is a valid handshake")
      {
        // Consumes nothing: the same bytes are offered again with more behind
        // them, and the scan resumes rather than restarting.
        ClientTunnelOutcome::NeedMore => continue 'feed,
        ClientTunnelOutcome::Interim {
          head,
          status: _,
          leftover,
        } => {
          drive.log.push(Mirror::TunnelInterim {
            fields: fields_of(&head),
          });
          taken_of(offer, leftover)
        }
        ClientTunnelOutcome::Switched { head, leftover }
        | ClientTunnelOutcome::Tunneled {
          head,
          status: _,
          leftover,
        } => {
          drive.log.push(Mirror::TunnelSwitched {
            connect,
            fields: fields_of(&head),
          });
          let taken = taken_of(offer, leftover);
          drive.consumed = drive.consumed.saturating_add(taken);
          // Everything else is the next protocol's: the leftover of this offer,
          // then every byte the driver never fed.
          drive
            .log
            .push(Mirror::TunnelTail(stream[drive.consumed..].to_vec()));
          break 'feed;
        }
        // Terminal for the handshake, and it CONSUMES its head: the leftover is
        // where the refusal's content begins. This core does not frame that
        // content — how far it runs is the caller's reading of the head — so the
        // tail here is the same "everything the driver still holds" the switch
        // arm records, measured from past the head rather than from in front of
        // it.
        ClientTunnelOutcome::Refused {
          head,
          status,
          leftover,
        } => {
          drive.log.push(Mirror::TunnelRefused {
            code: status.code,
            fields: fields_of(&head),
          });
          let taken = taken_of(offer, leftover);
          drive.consumed = drive.consumed.saturating_add(taken);
          drive
            .log
            .push(Mirror::TunnelTail(stream[drive.consumed..].to_vec()));
          break 'feed;
        }
        // `ClientTunnelOutcome` is `#[non_exhaustive]`, so a consumer outside
        // the crate owes this arm. Panicking is the honest answer: an outcome
        // this driver cannot advance its buffer by is one it cannot mirror
        // either, and continuing would compare two feed shapes over a stream
        // neither of them actually read.
        other => panic!("an outcome this corpus does not model: {other:?}"),
      };
      start = start.saturating_add(taken);
      drive.consumed = drive.consumed.saturating_add(taken);
    }
  }
  drive
}

/// How much of `offer` an outcome took, out of the leftover it reported.
///
/// The leftover contract, checked rather than assumed: what comes back has to be
/// a SUFFIX of what went in, since a driver advances its buffer by the
/// difference between the two and would misattribute every byte after this
/// handshake otherwise.
fn taken_of(offer: &[u8], leftover: &[u8]) -> usize {
  assert!(
    offer.ends_with(leftover),
    "the leftover is not the tail of the offer it came from"
  );
  offer.len().saturating_sub(leftover.len())
}

/// Runs `stream` through the driver `kind` names, split at `cuts`.
fn drive_stream(kind: Kind, stream: &[u8], cuts: &[usize]) -> Drive {
  match kind {
    Kind::Server => drive(Endpoint::Server(Connection::new()), stream, cuts),
    Kind::Client => drive(Endpoint::Client(Connection::new()), stream, cuts),
    Kind::Upgrade => drive_tunnel(false, stream, cuts),
    Kind::Connect => drive_tunnel(true, stream, cuts),
  }
}

/// Runs one corpus entry through the driver its shape needs.
fn drive_entry(entry: &Entry, cuts: &[usize]) -> Drive {
  drive_stream(entry.kind, entry.stream, cuts)
}

/// Every cut point there is: the byte-at-a-time feed shape.
fn every_cut(len: usize) -> Vec<usize> {
  (1..len).collect()
}

/// The deterministic half of the property: one shot, one byte at a time, and
/// every single-cut split in between, all against the same baseline.
fn assert_split_invariant(entry: &Entry) {
  let whole = drive_entry(entry, &[]);
  // Non-vacuity: a driver that recorded nothing would satisfy every equality
  // below, because a recording fault is shape-independent and would degrade all
  // three feed shapes into the same empty answer. So the baseline has to contain
  // something only a PARSED byte produces — see `Mirror::is_from_the_peer`, and
  // note what is not asked for: a positive `consumed`, since RFC 9110 §7.8's
  // refusal is terminal and reports no leftover, so the one entry that ends in
  // one legitimately consumes nothing.
  assert!(
    whole.log.iter().any(Mirror::is_from_the_peer),
    "{}: the drive parsed nothing out of the stream",
    entry.name
  );

  let per_byte = drive_entry(entry, &every_cut(entry.stream.len()));
  assert_eq!(
    per_byte, whole,
    "{}: byte-at-a-time diverged from one shot",
    entry.name
  );

  for cut in 1..entry.stream.len() {
    assert_eq!(
      drive_entry(entry, &[cut]),
      whole,
      "{}: a split at byte {cut} diverged from one shot",
      entry.name
    );
  }
}

/// Looks a corpus entry up by name, so each test below names the stream it is
/// about instead of an index.
fn entry(name: &str) -> &'static Entry {
  CORPUS
    .iter()
    .find(|entry| entry.name == name)
    .expect("the corpus carries every entry the tests name")
}

// RFC 9112 §2.1: a message is defined over the byte stream, not over the reads
// that carried it — so the one head this stream is ends up identical however it
// was split.
#[test]
fn simple_get_is_split_invariant() {
  assert_split_invariant(entry("simple GET"));
}

// RFC 9112 §6.3 item 6: the body is exactly as long as the head said, whichever
// reads its octets arrived in.
#[test]
fn counted_body_is_split_invariant() {
  assert_split_invariant(entry("POST with Content-Length"));
}

// RFC 9112 §7.1 with §7.1.1 and §7.1.2: a split inside a chunk-size line, a
// chunk extension, a chunk's data, or the trailer section leaves the same body
// and the same trailer fields.
#[test]
fn chunked_with_trailers_is_split_invariant() {
  assert_split_invariant(entry("chunked with extensions and trailers"));
}

// RFC 9110 §10.1.1: the ask is surfaced after the head and before any body
// octet, whether or not the read that carried the head also carried the body.
#[test]
fn expect_continue_is_split_invariant() {
  assert_split_invariant(entry("expect-continue then body"));
}

// RFC 9112 §9.3.2: the second request is processed only after the first response
// is written, and the ids stay in request order — including when the two
// requests arrived in one read.
#[test]
fn pipelined_pair_is_split_invariant() {
  assert_split_invariant(entry("pipelined request pair"));
}

// RFC 9112 §9.3 with §9.6: an HTTP/1.0 request without `keep-alive` is the last
// on the connection, so the driver stops at the same byte in every feed shape.
#[test]
fn http_10_request_is_split_invariant() {
  assert_split_invariant(entry("HTTP/1.0 request ends the connection"));
}

// RFC 9110 §15.2: an interim response does not end the exchange and mints no
// new id, and a split anywhere in either head does not change that.
#[test]
fn interim_then_final_is_split_invariant() {
  assert_split_invariant(entry("interim then final response"));
}

// RFC 9112 §6.3 item 8: the close is the delimiter, so the completion comes
// from the EOF's re-offer however the body's octets were split.
#[test]
fn close_delimited_response_is_split_invariant() {
  assert_split_invariant(entry("HTTP/1.0 close-delimited response"));
}

// RFC 9110 §15.2.2 with §7.8: the head that switches ends HTTP framing, and the
// bytes handed to the next protocol are the same set whether they arrived with
// that head or after it.
#[test]
fn upgrade_tunnel_is_split_invariant() {
  assert_split_invariant(entry("upgrade tunnel with an interim"));
}

// RFC 9110 §9.3.6: the connection becomes a tunnel immediately after the header
// section, and what follows is opaque octets in every feed shape.
#[test]
fn connect_tunnel_is_split_invariant() {
  assert_split_invariant(entry("CONNECT tunnel"));
}

// RFC 9110 §7.8: a refusal is terminal for the handshake, and it consumes the
// head it read — so where the driver stops does not move with the split either.
#[test]
fn refused_upgrade_is_split_invariant() {
  assert_split_invariant(entry("refused upgrade offer"));
}

// The three shapes a refusal's content can take (RFC 9112 §6.3 items 6, 4 and
// 8), split every way. The leftover a refusal reports is where that content
// begins, and a split that moved it would move the first byte a caller reads —
// which is the whole reason the offset comes out of the outcome rather than out
// of a re-scan.
#[test]
fn counted_refusal_body_is_split_invariant() {
  assert_split_invariant(entry("refused CONNECT with a counted body"));
}

#[test]
fn chunked_refusal_body_is_split_invariant() {
  assert_split_invariant(entry("refused CONNECT with a chunked body"));
}

#[test]
fn close_delimited_refusal_body_is_split_invariant() {
  assert_split_invariant(entry("refused upgrade with a close-delimited body"));
}

// The anti-vacuity pin, and the harness's own regression test: the mirror is
// checked against what the corpus STATES, so an equality that passed because the
// driver recorded nothing could not pass here. RFC 9112 §6.3 item 7 (a request
// with no framing field has no body) and §9.3.2 (the response is what re-arms).
#[test]
fn the_mirror_records_what_the_simple_get_states() {
  let observed = drive_entry(entry("simple GET"), &[]);
  assert_eq!(
    observed,
    Drive {
      log: vec![
        Mirror::Head {
          exchange: 1,
          interim: false,
          line: Line::Request {
            method: "GET".to_owned(),
            target: "/a".to_owned(),
          },
          field_count: 1,
          fields: vec![("Host".to_owned(), b"h".to_vec())],
        },
        Mirror::Complete { exchange: 1 },
        Mirror::Sent(RESPONSE.to_vec()),
        Mirror::Eof { completed: None },
      ],
      events: vec![],
      consumed: entry("simple GET").stream.len(),
    }
  );
}

// The same pin over the richest inbound shape: RFC 9112 §7.1's framing lines
// carry no item, §7.1.2's trailer fields carry one each, and the chunk
// extensions of §7.1.1 are parsed and dropped.
#[test]
fn the_mirror_records_what_the_chunked_stream_states() {
  let subject = entry("chunked with extensions and trailers");
  let observed = drive_entry(subject, &[]);
  assert_eq!(
    observed,
    Drive {
      log: vec![
        Mirror::Head {
          exchange: 1,
          interim: false,
          line: Line::Request {
            method: "POST".to_owned(),
            target: "/c".to_owned(),
          },
          field_count: 2,
          fields: vec![
            ("Host".to_owned(), b"h".to_vec()),
            ("Transfer-Encoding".to_owned(), b"chunked".to_vec()),
          ],
        },
        Mirror::Body {
          exchange: 1,
          data: b"abchello".to_vec(),
        },
        Mirror::Trailer {
          exchange: 1,
          name: "X-T".to_owned(),
          value: b"v".to_vec(),
        },
        Mirror::Trailer {
          exchange: 1,
          name: "X-U".to_owned(),
          value: b"w".to_vec(),
        },
        Mirror::Complete { exchange: 1 },
        Mirror::Sent(RESPONSE.to_vec()),
        Mirror::Eof { completed: None },
      ],
      events: vec![],
      consumed: subject.stream.len(),
    }
  );
}

// The same pin over the keep-alive shape, which is the one with a boundary in
// the middle: RFC 9112 §9.3.2 makes the first response the thing that lets the
// second request be processed, and the ids the core mints record the order.
#[test]
fn the_mirror_records_what_the_pipelined_pair_states() {
  let subject = entry("pipelined request pair");
  let head = |exchange, target: &str| Mirror::Head {
    exchange,
    interim: false,
    line: Line::Request {
      method: "GET".to_owned(),
      target: target.to_owned(),
    },
    field_count: 1,
    fields: vec![("Host".to_owned(), b"h".to_vec())],
  };
  assert_eq!(
    drive_entry(subject, &[]),
    Drive {
      log: vec![
        head(1, "/a"),
        Mirror::Complete { exchange: 1 },
        Mirror::Sent(RESPONSE.to_vec()),
        // The targets are what say the SECOND request was read, not the first
        // one twice (RFC 9112 §9.3.2 gives the pair its order).
        head(2, "/b"),
        Mirror::Complete { exchange: 2 },
        Mirror::Sent(RESPONSE.to_vec()),
        Mirror::Eof { completed: None },
      ],
      events: vec![],
      consumed: subject.stream.len(),
    }
  );
}

/// What the tunnel corpus entry's server pipelined behind its 101 — the first
/// bytes of the protocol the connection just switched to (RFC 9110 §15.2.2).
const SWITCHED_TAIL: &[u8] = b"\x81\x03abc";

// The same pin over the tunnel driver, whose outcomes are a different vocabulary
// from the items: RFC 9110 §7.8's offer goes out, §15.2's interim is consumed
// without ending the handshake, §15.2.2's 101 switches, and everything behind
// that head is handed over verbatim.
#[test]
fn the_mirror_records_what_the_upgrade_tunnel_states() {
  let subject = entry("upgrade tunnel with an interim");
  assert_eq!(
    drive_entry(subject, &[]),
    Drive {
      log: vec![
        Mirror::Sent(
          b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            .to_vec()
        ),
        Mirror::TunnelInterim { fields: vec![] },
        Mirror::TunnelSwitched {
          connect: false,
          fields: vec![
            ("Upgrade".to_owned(), b"websocket".to_vec()),
            ("Connection".to_owned(), b"Upgrade".to_vec()),
          ],
        },
        Mirror::TunnelTail(SWITCHED_TAIL.to_vec()),
      ],
      events: vec![],
      // Both heads, and nothing of what follows them: after the switch the bytes
      // are not this core's to consume.
      consumed: subject.stream.len() - SWITCHED_TAIL.len(),
    }
  );
}

// ── the remaining golden pins ─────────────────────────────────────────────────
//
// EVERY corpus entry now has one. The split property is an EQUALITY between feed
// shapes, so on its own it says only that the shapes agree — an entry the driver
// mis-read identically in all of them would satisfy it. These absolute pins are
// what make each entry state its own content, and the five that already existed
// left six entries carrying an equality and nothing else.

// RFC 9112 §6.3 item 6: `Content-Length` frames the body exactly, and the octets
// arrive as one coalesced run whatever the transport did to them.
#[test]
fn the_mirror_records_what_the_counted_post_states() {
  let subject = entry("POST with Content-Length");
  assert_eq!(
    drive_entry(subject, &[]),
    Drive {
      log: vec![
        Mirror::Head {
          exchange: 1,
          interim: false,
          line: Line::Request {
            method: "POST".to_owned(),
            target: "/up".to_owned(),
          },
          field_count: 2,
          fields: vec![
            ("Host".to_owned(), b"h".to_vec()),
            ("Content-Length".to_owned(), b"11".to_vec()),
          ],
        },
        Mirror::Body {
          exchange: 1,
          data: b"hello world".to_vec(),
        },
        Mirror::Complete { exchange: 1 },
        Mirror::Sent(RESPONSE.to_vec()),
        Mirror::Eof { completed: None },
      ],
      events: vec![],
      consumed: subject.stream.len(),
    }
  );
}

// RFC 9110 §10.1.1: the ask is surfaced AFTER the head and BEFORE any body
// octet, because the point of the expectation is that the body has not been sent
// yet. The position in the log is the whole assertion.
#[test]
fn the_mirror_records_what_the_expect_continue_stream_states() {
  let subject = entry("expect-continue then body");
  assert_eq!(
    drive_entry(subject, &[]),
    Drive {
      log: vec![
        Mirror::Head {
          exchange: 1,
          interim: false,
          line: Line::Request {
            method: "POST".to_owned(),
            target: "/e".to_owned(),
          },
          field_count: 3,
          fields: vec![
            ("Host".to_owned(), b"h".to_vec()),
            ("Content-Length".to_owned(), b"2".to_vec()),
            ("Expect".to_owned(), b"100-continue".to_vec()),
          ],
        },
        Mirror::ExpectContinue { exchange: 1 },
        Mirror::Body {
          exchange: 1,
          data: b"hi".to_vec(),
        },
        Mirror::Complete { exchange: 1 },
        Mirror::Sent(RESPONSE.to_vec()),
        Mirror::Eof { completed: None },
      ],
      events: vec![],
      consumed: subject.stream.len(),
    }
  );
}

// RFC 9112 §9.3 with §9.6: an HTTP/1.0 request without `keep-alive` is the last
// message on the connection, so the close is signalled at its head and the
// request PIPELINED BEHIND IT is never read — `consumed` stops at the first
// request's last byte, leaving the second one in the driver's buffer rather than
// silently dropped.
#[test]
fn the_mirror_records_what_the_http_10_request_states() {
  let subject = entry("HTTP/1.0 request ends the connection");
  let first = b"GET /a HTTP/1.0\r\nHost: h\r\n\r\n".len();
  assert_eq!(
    drive_entry(subject, &[]),
    Drive {
      log: vec![
        Mirror::Head {
          exchange: 1,
          interim: false,
          line: Line::Request {
            method: "GET".to_owned(),
            target: "/a".to_owned(),
          },
          field_count: 1,
          fields: vec![("Host".to_owned(), b"h".to_vec())],
        },
        Mirror::Complete { exchange: 1 },
        Mirror::Sent(RESPONSE.to_vec()),
        Mirror::Eof { completed: None },
      ],
      events: vec![Event::CloseSignaled],
      consumed: first,
    }
  );
  assert!(
    first < subject.stream.len(),
    "the entry has to carry a second request for the stop to mean anything"
  );
}

// RFC 9112 §6.3 item 8: the CLOSE is the delimiter, so the completion comes
// from the EOF's re-offer rather than from the feed loop — and §9.3 makes the
// connection non-persistent, which is the `CloseSignaled` beside it.
#[test]
fn the_mirror_records_what_the_close_delimited_response_states() {
  let subject = entry("HTTP/1.0 close-delimited response");
  assert_eq!(
    drive_entry(subject, &[]),
    Drive {
      log: vec![
        Mirror::Sent(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n".to_vec()),
        Mirror::Head {
          exchange: 1,
          interim: false,
          line: Line::Status { code: 200 },
          field_count: 0,
          fields: vec![],
        },
        Mirror::Body {
          exchange: 1,
          data: b"hello".to_vec(),
        },
        // The item no other entry produces: §6.3 item 8's intact head plus a
        // close IS a complete message. The completion is drawn on the re-offer
        // that follows the EOF, because "these are all the octets" is a
        // conclusion about the absence of further bytes like any other.
        Mirror::Eof { completed: Some(1) },
      ],
      events: vec![Event::CloseSignaled],
      consumed: subject.stream.len(),
    }
  );
}

// RFC 9110 §9.3.6: "any 2xx (Successful) response indicates that the sender …
// will switch to tunnel mode immediately after the response header section", so
// the head is consumed and everything behind it is handed over verbatim — raw
// TLS bytes here, which are not HTTP and are not this core's to touch.
#[test]
fn the_mirror_records_what_the_connect_tunnel_states() {
  let subject = entry("CONNECT tunnel");
  const TAIL: &[u8] = b"\x16\x03\x01raw";
  assert_eq!(
    drive_entry(subject, &[]),
    Drive {
      log: vec![
        Mirror::Sent(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec()),
        Mirror::TunnelSwitched {
          connect: true,
          fields: vec![],
        },
        Mirror::TunnelTail(TAIL.to_vec()),
      ],
      events: vec![],
      consumed: subject.stream.len() - TAIL.len(),
    }
  );
}

// RFC 9110 §7.8: "Upgrade cannot be used to insist on a protocol change" — the
// refusal is TERMINAL for the handshake, and it CONSUMES the head it read. With
// `Content-Length: 0` the head is the whole message, so the tail behind it is
// empty and `consumed` is the stream.
#[test]
fn the_mirror_records_what_the_refused_upgrade_states() {
  let subject = entry("refused upgrade offer");
  assert_eq!(
    drive_entry(subject, &[]),
    Drive {
      log: vec![
        Mirror::Sent(
          b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            .to_vec()
        ),
        Mirror::TunnelRefused {
          code: 426,
          fields: vec![
            ("Upgrade".to_owned(), b"h2c".to_vec()),
            ("Connection".to_owned(), b"Upgrade".to_vec()),
            ("Content-Length".to_owned(), b"0".to_vec()),
          ],
        },
        Mirror::TunnelTail(vec![]),
      ],
      events: vec![],
      consumed: subject.stream.len(),
    }
  );
}

/// The head-end offset of a refusal corpus entry: everything up to and including
/// the empty line that closes its field section.
///
/// Computed from the stream rather than written down, so a pin states "the
/// content begins where the head ends" instead of restating a byte count that
/// would have to be recounted by hand whenever a fixture changes.
fn content_at(stream: &[u8]) -> usize {
  stream
    .windows(4)
    .position(|w| w == b"\r\n\r\n")
    .map(|at| at + 4)
    .expect("every refusal fixture carries a complete head")
}

/// The absolute pin every refusal-with-content entry shares: the head is
/// consumed, its fields are mirrored, and the tail the driver hands on begins at
/// the first octet of the content.
///
/// RFC 9110 §11.7 is why this matters for the 407s — "the server … MUST send a
/// Proxy-Authenticate header field … containing at least one challenge", and a
/// client that means to retry reads the challenge and the content beside it —
/// and RFC 9112 §6.3 is why the tail is handed over UNFRAMED: which of items 4,
/// 6 and 8 delimits it is decided from the head, by the caller.
#[track_caller]
fn assert_refusal_hands_over_its_content(
  name: &str,
  connect: bool,
  code: u16,
  fields: Vec<(String, Vec<u8>)>,
) {
  let subject = entry(name);
  let at = content_at(subject.stream);
  let sent = if connect {
    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec()
  } else {
    b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
      .to_vec()
  };
  assert_eq!(
    drive_entry(subject, &[]),
    Drive {
      log: vec![
        Mirror::Sent(sent),
        Mirror::TunnelRefused { code, fields },
        Mirror::TunnelTail(subject.stream[at..].to_vec()),
      ],
      events: vec![],
      consumed: at,
    },
    "{name}"
  );
  // The content is really there, so the pin is not passing on an empty tail.
  assert!(at < subject.stream.len(), "{name}: no content to hand over");
}

// RFC 9112 §6.3 item 6 behind a refusal.
#[test]
fn the_mirror_records_what_the_counted_refusal_states() {
  assert_refusal_hands_over_its_content(
    "refused CONNECT with a counted body",
    true,
    407,
    vec![
      (
        "Proxy-Authenticate".to_owned(),
        b"Basic realm=\"proxy\"".to_vec(),
      ),
      ("Content-Length".to_owned(), b"12".to_vec()),
    ],
  );
}

// RFC 9112 §6.3 item 4: the chunked coding's own framing lines are handed over
// verbatim, because Tunnel mode decodes nothing.
#[test]
fn the_mirror_records_what_the_chunked_refusal_states() {
  assert_refusal_hands_over_its_content(
    "refused CONNECT with a chunked body",
    true,
    407,
    vec![
      (
        "Proxy-Authenticate".to_owned(),
        b"Basic realm=\"proxy\"".to_vec(),
      ),
      ("Transfer-Encoding".to_owned(), b"chunked".to_vec()),
    ],
  );
}

// RFC 9112 §6.3 item 8: with neither framing field the content ends at the
// close, so what a driver is handed is the octets that arrived — a suffix of the
// offer, which is all the contract ever promised.
#[test]
fn the_mirror_records_what_the_close_delimited_refusal_states() {
  assert_refusal_hands_over_its_content(
    "refused upgrade with a close-delimited body",
    false,
    403,
    vec![],
  );
}

// The corpus floor: every entry carries an absolute pin, and this is what says
// so. A new entry with only the equality property behind it is the gap the six
// pins above closed, so adding one without its pin fails here.
#[test]
fn every_corpus_entry_carries_an_absolute_pin() {
  const SOURCE: &str = include_str!("split_robustness.rs");
  assert!(
    CORPUS.len() >= 14,
    "the corpus lost entries: {} left",
    CORPUS.len()
  );
  let pins = SOURCE.matches("fn the_mirror_records_what_").count();
  assert!(
    pins >= CORPUS.len(),
    "{} corpus entries but only {pins} absolute pins",
    CORPUS.len()
  );
}

// The client-side pin, and the one where the start line carries the whole
// classification: RFC 9110 §15.2 makes a 1xx interim on the SAME exchange, and
// §6.3 item 6 frames the final response's body — so the two heads differ by their
// status-code and by nothing else the driver can see.
#[test]
fn the_mirror_records_what_the_interim_final_pair_states() {
  let subject = entry("interim then final response");
  assert_eq!(
    drive_entry(subject, &[]),
    Drive {
      log: vec![
        Mirror::Sent(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n".to_vec()),
        Mirror::Head {
          exchange: 1,
          interim: true,
          line: Line::Status { code: 100 },
          field_count: 0,
          fields: vec![],
        },
        Mirror::Head {
          exchange: 1,
          interim: false,
          line: Line::Status { code: 200 },
          field_count: 1,
          fields: vec![("Content-Length".to_owned(), b"2".to_vec())],
        },
        Mirror::Body {
          exchange: 1,
          data: b"ok".to_vec(),
        },
        Mirror::Complete { exchange: 1 },
        Mirror::Eof { completed: None },
      ],
      events: vec![],
      consumed: subject.stream.len(),
    }
  );
}

// Deliberately not a split property: a driver OUTSIDE this crate reads the
// start line of the head it was handed, through public names only, and gets
// what RFC 9112 §3 and §4 put on the wire. This is the shape a router or a
// WebSocket handshake consumes — the method and target it dispatches on, the
// status it acts on — and it compiles only while every name in it is exported.
#[test]
fn a_driver_reads_the_start_line_through_public_names() {
  // Server: the §3 request-line.
  let mut server = Connection::<Server, General>::new();
  let mut items =
    server.handle(b"POST /submit?x=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n");
  let Some(Item::Head { line, view, .. }) = items.next().expect("a well-formed request") else {
    panic!("the first item of a request is its head")
  };
  match line {
    StartLine::Request(request) => {
      assert_eq!(request.method, "POST");
      assert_eq!(
        request.target,
        Target::Origin {
          path_and_query: "/submit?x=1"
        }
      );
      assert_eq!(request.version, Version::Http11);
    }
    // The `_` arm a `#[non_exhaustive]` enum owes, which on a SERVER connection
    // is the same statement the named arm makes: a request-line is the only
    // start line this role ever reads.
    other => panic!("a server reads request-lines, not {other:?}"),
  }
  // The line and the fields are two views of one head, readable together.
  assert_eq!(view.header("host"), Some(b"h".as_slice()));

  // Client: the §4 status-line, on the exchange the request opened.
  let mut client = Connection::<Client, General>::new();
  let mut request = [0u8; 128];
  client
    .open_request("GET", &ORIGIN, HOST, BodyPlan::None, &mut request)
    .expect("the request opens");
  let mut items = client.handle(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
  let Some(Item::Head { line, .. }) = items.next().expect("a well-formed response") else {
    panic!("the first item of a response is its head")
  };
  match line {
    StartLine::Status(status) => {
      assert_eq!(status.code, 404);
      assert_eq!(status.reason, b"Not Found");
      assert_eq!(status.version, Version::Http11);
    }
    other => panic!("a client reads status-lines, not {other:?}"),
  }
}

// The pipelined entry has to RE-ARM for the property to mean anything: both ids
// are visible, in order, with the response boundary between them (RFC 9112
// §9.3.2 — the second request is not processed before the first response is
// finished).
#[test]
fn the_pipelined_entry_really_re_arms() {
  let observed = drive_entry(entry("pipelined request pair"), &[]);
  let ids: Vec<u64> = observed
    .log
    .iter()
    .filter_map(|mirror| match mirror {
      Mirror::Head { exchange, .. } => Some(*exchange),
      _ => None,
    })
    .collect();
  assert_eq!(ids, [1, 2]);
  let sends = observed
    .log
    .iter()
    .filter(|mirror| matches!(mirror, Mirror::Sent(_)))
    .count();
  assert_eq!(sends, 2, "each exchange is answered exactly once");
  // The second head cannot precede the first answer.
  let first_send = observed
    .log
    .iter()
    .position(|mirror| matches!(mirror, Mirror::Sent(_)))
    .expect("the first response was written");
  let second_head = observed
    .log
    .iter()
    .position(|mirror| matches!(mirror, Mirror::Head { exchange: 2, .. }))
    .expect("the pipelined request became an exchange");
  assert!(first_send < second_head);
}

// The harness self-test, kept rather than run once by hand: every field the
// equality is built on has to be able to FAIL, or a green suite would prove
// nothing. One mutation per field of the comparison.
#[test]
fn the_harness_catches_a_lie() {
  let truth = drive_entry(entry("POST with Content-Length"), &[]);

  // A changed item.
  let mut altered = truth.clone();
  match altered.log.first_mut() {
    Some(Mirror::Head { interim, .. }) => *interim = true,
    other => unreachable!("the first mirror is the request head, not {other:?}"),
  }
  assert_ne!(altered, truth, "a changed item passed as equal");

  // A changed START LINE: a mirror that dropped it would compare equal here and
  // the whole line would go unchecked.
  let mut retargeted = truth.clone();
  match retargeted.log.first_mut() {
    Some(Mirror::Head {
      line: Line::Request { target, .. },
      ..
    }) => target.push('x'),
    other => unreachable!("the first mirror is the request head, not {other:?}"),
  }
  assert_ne!(
    retargeted, truth,
    "a changed request-target passed as equal"
  );

  // A missing item.
  let mut dropped = truth.clone();
  dropped.log.remove(1);
  assert_ne!(dropped, truth, "a missing item passed as equal");

  // A re-ordered sequence.
  let mut swapped = truth.clone();
  swapped.log.swap(0, 1);
  assert_ne!(swapped, truth, "a re-ordered sequence passed as equal");

  // A consumed total that is off by one byte.
  let mut short = truth.clone();
  short.consumed = short.consumed.saturating_sub(1);
  assert_ne!(short, truth, "a wrong consumed total passed as equal");

  // An event that was never queued.
  let mut noisy = truth.clone();
  noisy.events.push(Event::CloseSignaled);
  assert_ne!(noisy, truth, "a spurious event passed as equal");

  // A body whose octets differ but whose length does not — the coalescing must
  // compare the octet sequence, not merely count it.
  let mut rewritten = truth.clone();
  match rewritten.log.get_mut(1) {
    Some(Mirror::Body { data, .. }) => data.reverse(),
    other => unreachable!("the second mirror is the body, not {other:?}"),
  }
  assert_ne!(rewritten, truth, "a rewritten body passed as equal");
}

/// Corpus entry and a cut vector inside its stream, for the random half of the
/// property.
fn corpus_and_cuts() -> impl Strategy<Value = (usize, Vec<usize>)> {
  (0..CORPUS.len()).prop_flat_map(|index| {
    let len = CORPUS[index].stream.len();
    (Just(index), prop::collection::vec(1..len, 0..12))
  })
}

proptest! {
  // 256 cases: each one drives a whole connection twice, and the deterministic
  // tests above already sweep one-shot, byte-at-a-time and every single cut of
  // every entry — what is left for random search is the MULTI-cut space, which
  // 256 draws of up to 11 points over 11 corpus entries sample well inside a
  // second.
  //
  // No failure persistence: a counterexample is a cut vector printed in full by
  // the failure message and reproducible by pasting it into a deterministic
  // test, so the `.proptest-regressions` file would be a committed artifact with
  // nothing in it that the message does not already carry.
  #![proptest_config(ProptestConfig {
    cases: 256,
    failure_persistence: None,
    ..ProptestConfig::default()
  })]

  // RFC 9112 §2.1 again, over arbitrary segmentation: the reads a driver happens
  // to get are not part of the message, so no set of split points changes the
  // item sequence, the events, or the byte count.
  #[test]
  fn random_split_points_change_nothing((index, cuts) in corpus_and_cuts()) {
    let subject = &CORPUS[index];
    let whole = drive_entry(subject, &[]);
    let split = drive_entry(subject, &cuts);
    prop_assert_eq!(
      split,
      whole,
      "{} diverged when split at {:?}",
      subject.name,
      cuts
    );
  }
}

/// How many field lines the linearity probe's head carries. Under
/// `MAX_HEADERS`, so the head is refused for its size by nothing.
const PROBE_FIELDS: usize = 60;

/// The padding each of those lines carries, chosen so the whole head lands just
/// under `MAX_HEAD_BYTES`.
const PROBE_PADDING: usize = 250;

/// How many times each half of the linearity probe re-parses that head, one byte
/// at a time. Enough for both measurements to be milliseconds rather than
/// microseconds, so the timer's own resolution is not part of the answer, and no
/// more than that: the restarting half is the slow one, and it is the whole cost
/// of this test.
const PROBE_REPEATS: usize = 2;

/// How much cheaper the resumed parse has to be than the restarting control.
///
/// The gap the probe is built to see is Θ(N) against Θ(N²) — on a 15_750-byte
/// head that is a factor in the thousands of byte visits and, measured on a
/// debug build, roughly 200x in wall clock. Asserting a factor of 8 leaves the
/// whole rest of that margin to noise.
const PROBE_MARGIN: u32 = 8;

/// The same assertion on a shared CI runner, where the two halves are not
/// guaranteed comparable machines-worth of CPU.
///
/// LOOSER, not absent. A regression to the quadratic scan makes the two halves
/// EQUAL — a ratio of about 1 — so any margin above 1 still catches it, while a
/// co-tenant would have to steal enough CPU to halve one half's throughput
/// during the other half's 2 s to produce a false red. That is a far smaller
/// exposure than the total escape this replaces, which asserted nothing at all
/// on the three runners the `test` job uses and would have let the whole
/// linearity property regress in CI unnoticed.
const CI_PROBE_MARGIN: u32 = 2;

/// A head just under `MAX_HEAD_BYTES`, built from valid field lines.
fn probe_head() -> Vec<u8> {
  let mut head = Vec::from(&b"GET /big HTTP/1.1\r\nHost: h\r\n"[..]);
  for line in 0..PROBE_FIELDS {
    head.extend_from_slice(format!("X-Pad-{line:02}: ").as_bytes());
    head.extend(core::iter::repeat_n(b'p', PROBE_PADDING));
    head.extend_from_slice(b"\r\n");
  }
  head.extend_from_slice(b"\r\n");
  assert!(head.len() < MAX_HEAD_BYTES);
  head
}

/// Feeds `head` one byte at a time, offering the accumulated prefix each time —
/// which for a head that has not terminated is the whole of it, since nothing is
/// consumed until the block is complete.
///
/// `fresh` decides which connection meets each offer: ONE connection carrying
/// its watermark forward (the subject), or a new one per offer (the control,
/// whose scan therefore starts at byte 0 every time). Nothing else differs
/// between the two, which is what makes the pair a measurement of the watermark
/// and of nothing else.
fn feed_head_by_byte(head: &[u8], fresh: bool) {
  let mut connection = Connection::<Server, General>::new();
  for end in 1..=head.len() {
    if fresh {
      connection = Connection::new();
    }
    let mut items = connection.handle(&head[..end]);
    while items
      .next()
      .expect("the probe head is a valid request head")
      .is_some()
    {}
  }
}

/// Times `PROBE_REPEATS` byte-at-a-time parses of `head`.
fn time_probe(head: &[u8], fresh: bool) -> Duration {
  let started = Instant::now();
  for _ in 0..PROBE_REPEATS {
    feed_head_by_byte(head, fresh);
  }
  started.elapsed()
}

// The head scan RESUMES from its watermark instead of restarting, so a head
// that arrives one byte at a time is scanned once in total rather than once per
// byte.
//
// Mechanism. The probe parses a head of N = 15_750 bytes (just under
// `MAX_HEAD_BYTES`) fed one byte at a time, twice over: once by ONE connection,
// which carries the watermark, and once by a FRESH connection per offer, which
// cannot. The second is not a model of quadratic behaviour, it IS quadratic
// behaviour, produced by this crate's own scanner over the same bytes — a
// restart at byte 0 on every offer, Σ(1..N) ≈ 124 MILLION byte visits per head
// against the resumable path's 15_750. The subject must come out at least
// `PROBE_MARGIN` times cheaper.
//
// Why a ratio rather than a ceiling. Both halves run back to back, in the same
// process, on the same machine, in the same build profile, over the same input,
// through the same code — so machine speed and `--release` against debug divide
// out of the comparison instead of moving a fixed ceiling. Measured here the
// subject is ~200x cheaper (≈10 ms against ≈2 s); the assertion asks for 8x, so
// noise would have to hit one half twenty-five times harder than the other to
// matter. A scanner that had lost its watermark would make the two halves EQUAL,
// which no amount of headroom hides.
//
// A ratio still assumes the two halves got comparable machines-worth of CPU, and
// on a shared hosted runner that is an assumption about somebody else's
// workload. See the `CI` escape in the body: the ratio is asserted everywhere it
// can be trusted and skipped where it cannot, while both halves keep running.
//
// What the probe cannot see is a constant factor: it distinguishes N from N²,
// which is the property under test, and nothing finer.
//
// Not run under miri, and the exemption is this test's own construction rather
// than a tolerance: its CONTROL half is deliberately quadratic — Σ(1..15_750)
// ≈ 124 million byte visits per pass, four passes — which native code does in
// about two seconds and an interpreter does not do in a CI budget at all
// (measured: still running after ten minutes, on the one test). Nothing is lost
// by skipping it there, because what miri looks for is undefined behaviour and
// this is a wall-clock RATIO: the interpreter's uniform slowdown divides out of
// the comparison, so the assertion cannot fail under miri for a reason it would
// not also fail for natively. The same scanner code IS interpreted by every
// other test in this file.
#[cfg_attr(miri, ignore = "quadratic control half; a ratio miri cannot inform")]
#[test]
fn byte_at_a_time_head_parse_stays_linear() {
  let head = probe_head();

  // The reference driver reaches the same head, so what is being timed below is
  // a parse that actually happened rather than one refused for its size.
  let observed = drive_stream(Kind::Server, &head, &every_cut(head.len()));
  assert_eq!(observed.consumed, head.len());
  assert!(matches!(
    observed.log.first(),
    Some(Mirror::Head { field_count, .. }) if *field_count == PROBE_FIELDS + 1
  ));

  // Both halves run everywhere: they are this crate's own scanner over the same
  // input, so a fault in either shows up as a panic or a wrong answer wherever
  // the suite runs, CI included.
  let resumed = time_probe(&head, false);
  let restarted = time_probe(&head, true);

  // The RATIO is the only part that is a wall-clock claim, and on CI it is a
  // claim about a machine this suite does not own: the `test` job runs on three
  // shared hosted runners in debug, where a co-tenant stealing the CPU for the
  // 2 s the control half takes could move the measurement.
  //
  // So the margin is LOOSENED there rather than dropped. The assertion still
  // runs, and it still catches the regression it exists for: a scan that lost
  // its watermark makes the two halves EQUAL — the control IS this crate's own
  // scanner restarting at byte 0, so both would be doing the same Θ(N²) work —
  // and no ratio above 1 tolerates that. `CI_PROBE_MARGIN` sits at 2, which a
  // co-tenant would have to halve one half's throughput (and only that half's,
  // and only during the other's) to trip. Skipping the assertion outright, which
  // is what this replaces, would have let the whole linearity property regress
  // on every runner CI has.
  //
  // GitHub Actions sets `CI=true`; so does essentially every other CI system,
  // which is the point of testing the variable rather than a vendor-specific one.
  let margin = if std::env::var_os("CI").is_some() {
    CI_PROBE_MARGIN
  } else {
    PROBE_MARGIN
  };
  assert!(
    resumed.saturating_mul(margin) < restarted,
    "a {}-byte head fed one byte at a time took {resumed:?} with the watermark and {restarted:?} \
     without it — under {margin}x apart, so the scan is restarting rather than resuming",
    head.len(),
  );
}
