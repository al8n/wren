<div align="center">
<h1>http1-proto</h1>
</div>
<div align="center">

Sans-I/O HTTP/1.1 connection state machine — the RFC 9110 / 9112 subset needed
to drive request/response exchanges and hand an upgraded byte stream (e.g.
WebSocket) to the caller.

`no_std` + no-alloc capable, panic-free codec leaves.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/websockit-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/websockit/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-http1--proto-66c2a5?style=for-the-badge&labelColor=555555&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMiA0MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMiAzOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMiA0MS40di0uNmwxMDIgMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/http1-proto?style=for-the-badge&logo=rust" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge" height="22">

</div>

## What it is

`http1-proto` is the Sans-I/O core for HTTP/1.1 (RFC 9110 / RFC 9112). It owns
no sockets, no threads, no async runtime, and no buffer of its own. Callers feed
inbound transport bytes in and shuttle the produced bytes out to whatever moves
them (TCP, TLS, a test harness).

The scope is a complete HTTP/1.1 **message and connection** layer:

- **Grammar** (RFC 9110 §5.6): `token` / `field-value` over raw bytes —
  `field-vchar = VCHAR / obs-text` with interior SP/HTAB, OWS-trimmed, CTLs
  rejected — plus the RFC 3986 request-target validators.
- **Start lines**: the RFC 9112 §3 `request-line` with all four §3.2 target
  forms, and the §4 `status-line`. Single-SP separators only; no lenient
  whitespace-boundary parse.
- **Head scanner** (RFC 9112 §2.1, §5): a resumable, bounded scan over the field
  block that yields a lazy zero-copy [`HeadView`] — fields are walked out of the
  borrowed bytes on demand, never copied into a table.
- **Semantics** (RFC 9112 §3.2, §6.1, §6.3): the `Host` rule, `Content-Length`
  and `Transfer-Encoding` validation, and the §6.3 body-length decision list
  applied branch-for-branch **in its stated order**.
- **Media** (RFC 9110 §8.3.1, §12.5.1): a `Content-Type` value's `type/subtype`
  and parameters, and an `Accept` field's ranges, walked over the same §5.6.6
  parameter grammar; a candidate is matched against those ranges by composing
  §12.5.1's precedence with the §12.4.2 `qvalue` weight.
- **Bodies**: counted, chunked (RFC 9112 §7.1, with bounded `chunk-ext` and a
  trailer section), read-to-close, and none.
- **Encoders**: validated request/status heads and chunk framing, written into a
  caller-supplied slice with exact sizing and no partial writes.
- **Connection**: a compile-time role/mode type-state —
  `Connection<Client | Server, General | Tunnel>` — carrying the General-mode
  exchange FSM (keep-alive, pipelining tolerance, 1xx, `Expect: 100-continue`,
  HTTP/1.0 fallback, close-delimited responses, and a permitted client's
  opportunistic RFC 9110 §7.8 upgrade) and the Tunnel-mode handshake that builds
  such a switch from scratch. Either mode hands the leftover byte stream over.

### What belongs in this crate, and what does not

The scope is a rule rather than a list, so that a capability nobody has asked
for yet has an answer before it is argued about. The first clause is why this
crate exists; the other three are what that position obligates.

1. **Grammar, framing and the connection lifecycle are ours — both directions.**
   Every field this core reads, it reads once, and hands the result over; what
   this core reads, this core writes. A consumer that re-parses the wire becomes
   a second reader, and two readers that disagree about a message's framing is
   what RFC 9112 §11.2 calls request smuggling — "a technique that exploits
   differences in protocol parsing among various recipients". The disagreement
   *is* the vulnerability, not a symptom of one.
2. **Resource bounds are ours to enforce, yours to size.** A bound enforced
   above this layer either re-reads the framing fields — clause 1's second
   reader — or counts octets it is never shown: the chunk-framing budget bounds
   size-line bytes this core consumes and no consumer ever sees. So the
   enforcement position is not negotiable. The numbers split in two. What a
   message may *spend* — body octets, chunk framing — belongs to the deployment
   and is configurable, through `Limits`. What keeps the *parse itself* finite —
   `MAX_HEAD_BYTES`, `MAX_HEADERS` — is a constant of this parser, published
   rather than configurable.
3. **Derivations RFC 9110 / 9112 settle are ours, computed as pure functions.**
   The status a fault is answered with, the precedence of media ranges, whether
   two entity-tags match (§8.8.3.2), the order preconditions are evaluated in
   (§13.2.2): where those two RFCs give the answer, a consumer computing it
   differently is not making a different choice, it is wrong — so it is computed
   here, once, holding no clock, no store and no socket; what only you hold, a
   validator or a representation's length, arrives as an argument. An algorithm
   another specification settles — a cache's freshness (RFC 9111 §4.2), a
   reference resolved against a base URI (RFC 3986 §5), a content coding's
   decode — is your layer's, however pure it is. Where RFC 9110 / 9112 settle
   nothing and this core still answers — no status names over-large chunk
   framing, so that refusal suggests a plain 400 — the answer is advice that
   says so: a `SuggestedStatus` never binds you, and no advisory surface beyond
   it will be added.
4. **Choices the RFCs leave open are not ours.** Which representation to serve,
   which challenge to answer, whether to follow a redirect. The inputs to those
   decisions that RFC 9110 / 9112 themselves define — `Accept`'s media ranges, a
   challenge's parameters — are parsed here, to the last parameter; the decision
   is not. Fields whose grammar another specification owns — `Cookie` is the
   canonical case — ride through as raw values for their own crate to read.
   Content negotiation is the clearest case: nothing in §12 requires a server to
   negotiate, and §12.1 says a user agent "cannot rely on proactive negotiation
   preferences being consistently honored", so the ranking §12.5.1 settles is
   ours and the pick is yours.

Where a clause names work this crate does not yet do — today, §11.3's challenge
walk, §8.8.3.2's entity-tag comparison, and §13.2.2's precondition order — that
is a missing feature here, to be filed as one. It is not licence to read the
wire downstream.

So: not a router, not a URI resolver, not a cache, not a content codec. Each of
those follows from the clauses above rather than standing beside them. This core
reports what the message says, and refuses what the RFCs make unframable or what
your limits forbid; deciding *what to do* with a well-framed message is yours.

## Feature flags

| Feature | Default | Enables |
|---------|:-------:|---------|
| `std` | ✅ | `thiserror/std`, `http-semantics/std` |
| `alloc` | | heap tier without `std` (a storage-tier marker for now) |
| `no-atomic` | | heap tier without `std` and without native atomic CAS |

Every current path encodes into a caller-supplied slice, so `alloc` and
`no-atomic` carry the tier *semantics* without pulling a dependency; a
heap-backed body/transmit backend attaches to them when one lands. `no-atomic`
names the heap tier for cores with **no native atomic CAS** (Cortex-M0+ /
`thumbv6m`, e.g. the RP2040) — it stands in for `alloc` on such a core rather
than accompanying it.

The bare `no_std`, no-`alloc` tier compiles with `--no-default-features`. The
only external dependencies on that tier are `http-semantics`, `thiserror` (with
`std` off on both) and `derive_more`.

## The driver loop

The core keeps **no buffer**. Reassembly is the driver's append-only accumulation
buffer, offered to `handle` from its unconsumed start; whatever `handle` did not
consume is re-offered next time with the new bytes behind it. That is the whole
mechanism by which a message split across reads gets assembled.

Seven steps. The first six are the happy path and all of them are in the first
example below; the seventh is the error path, and it is the second example.

1. Append what the transport returned to an **append-only** buffer — never
   compacted, never copied back.
2. Offer `buffer[start..]` to `handle`, and pull `Items::next` until `Ok(None)`.
3. Advance `start` by `Items::consumed()`.
4. Drain `poll_event()`.
5. Ask **why** the items ran out: `Ok(None)` alone cannot say whether to read the
   socket or to write to it. `wants_read()` and `is_awaiting_send()` are the two
   disjoint answers, and the loop branches on them.
6. At end of input, call `handle_eof()`, then **keep offering the buffer** (step
   2) until the connection drains or reports a fault. `handle_eof` observes the
   transport and nothing else — it cannot see your buffer, so it never concludes
   that a message was truncated. An **empty slice** is a sufficient offer, and is
   what resolves the EOF when your buffer is already empty.
7. `Err` from `Items::next` (or from `handle_eof`) is not one outcome but two.
   `Error::Protocol` **latches** the connection: the violation is handed back
   exactly once, nothing more will parse, and `transport()` now reads `Failed`.
   `Error::Refused` does **not** latch — this end's own policy closed the
   exchange, not a wire fault — so `transport()` reads `Ending` instead.
   `transport()` is the authority on what to do with the transport; ask it
   rather than inferring from which error came back. A *server* whose response
   has not started going out is left owing
   exactly one answer — `is_awaiting_send()` reports it — so read
   `Error::suggested_status()`, write it with `send_error_response()`, and close
   the transport. Everything else (a client, or a server whose response is
   already partly on the wire) closes without answering: a second final response
   would be read as part of the first.

   `Item::Switched` is the exception a driver must not get wrong. After it,
   every later `Items::next` answers `Error::InvalidState` and nothing has
   latched: that transport is to be **handed over**, not closed. Having taken
   the item is what tells the two apart, since the reason string is not public.
   See **Tunnel mode** below.

```rust
use http1_proto::{BodyPlan, Connection, General, Item, Server, StartLine, Target};

fn main() -> Result<(), http1_proto::Error> {
  // The transport, split mid-field-name on purpose: a Sans-I/O core is handed
  // whatever the socket happened to return, and RFC 9112 §2.1 defines a message
  // over the byte stream rather than over the reads that carried it.
  let reads: [&[u8]; 2] = [
    b"POST /echo HTTP/1.1\r\nHost: example.com\r\nCont",
    b"ent-Length: 5\r\n\r\nhello",
  ];
  // A bodiless keep-alive answer: RFC 9112 §6.3 item 8 makes a response with NO
  // framing field close-delimited, so one that means "nothing follows" says so.
  let answer: &[(&str, &[u8])] = &[("Content-Length", b"0")];

  let mut conn = Connection::<Server, General>::new();
  let mut buffer: Vec<u8> = Vec::new();
  let mut start = 0usize; // how much of `buffer` the connection has taken
  let mut body: Vec<u8> = Vec::new();
  let mut written: Vec<u8> = Vec::new();

  'reads: for read in reads {
    buffer.extend_from_slice(read);
    loop {
      let consumed = {
        let mut items = conn.handle(&buffer[start..]);
        while let Some(item) = items.next()? {
          match item {
            Item::Head { exchange, view, line, interim } => {
              // The start line says WHAT the message is; the view says what
              // fields it carried. A server always reads a request-line.
              let StartLine::Request(request) = line else {
                unreachable!("a server connection reads request-lines")
              };
              assert_eq!(request.method, "POST");
              assert_eq!(request.target, Target::Origin { path_and_query: "/echo" });
              assert_eq!(view.header("host"), Some(b"example.com".as_slice()));
              // Ids are minted by the core, in the order exchanges start; an
              // interim (1xx) head never opens a new one (RFC 9110 §15.2).
              assert_eq!(exchange.get(), 1);
              assert!(!interim);
            }
            // Body octets point straight into `buffer` — nothing is copied.
            Item::BodyChunk { data, .. } => body.extend_from_slice(data),
            Item::Trailer { .. } => {}        // RFC 9112 §7.1.2
            Item::ExpectContinue { .. } => {} // RFC 9110 §10.1.1
            Item::ExchangeComplete { .. } => {}
            // `Item` is `#[non_exhaustive]`: what this core surfaces out of a
            // message can grow, so a driver forwards what it does not know
            // rather than failing to compile against a later minor release.
            _ => {}
          }
        }
        items.consumed()
      };
      start += consumed;
      while let Some(_event) = conn.poll_event() { /* lifecycle notices */ }

      // The two questions are disjoint answers: reading cannot clear a stall on
      // the send side, and a connection waiting for its own writer wants no
      // bytes.
      assert!(!(conn.wants_read() && conn.is_awaiting_send()));
      if conn.is_awaiting_send() {
        // RFC 9112 §9.3.2: keep-alive re-arms on the response, so anything
        // already buffered behind this request is readable only once it is out.
        let mut out = [0u8; 64];
        let n = conn.send_response(200, b"OK", answer, BodyPlan::None, &mut out)?;
        written.extend_from_slice(&out[..n]);
        continue;
      }
      if conn.wants_read() {
        continue 'reads; // back to the socket
      }
      // Neither. On this SERVER connection that is RFC 9112 §9.6's drained
      // state — no further inbound byte is processed. A client reaches the same
      // branch when it is merely idle between exchanges; see below the loop.
      break 'reads;
    }
  }

  assert_eq!(body, b"hello");
  assert_eq!(written, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  // The transport ended. Reported once, and it can still owe the item that
  // completes a close-delimited message — here it owes nothing.
  assert!(conn.handle_eof()?.is_none());
  Ok(())
}
```

### Step 7: the error path

A protocol violation is terminal, and a server owes exactly **one** answer for
it. This is the whole of that path (RFC 9112 §6.3 item 3 makes the message
below unframable, and §6.1 requires a server to "respond with a 400 (Bad
Request) status code and then close the connection"):

```rust
use http1_proto::{Connection, Error, General, Server, Transport};

fn main() {
  // Both framing fields: two recipients would delimit this message differently,
  // which is the RFC 9112 §11.2 primitive itself.
  let unframable: &[u8] =
    b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
  let no_fields: &[(&str, &[u8])] = &[]; // `send_error_response` states its own
  let mut conn = Connection::<Server, General>::new();

  // 1. The violation comes back from `next`, exactly once. Nothing was yielded
  //    before it: the fault is in the head, so no request was ever delivered.
  let failure = {
    let mut items = conn.handle(unframable);
    let error = items.next().expect_err("the framing is unresolvable");
    assert_eq!(items.consumed(), 0);
    error
  };
  assert!(matches!(failure, Error::Protocol(_)));

  // 2. The connection has latched: reading cannot help, and the ONE answer is
  //    what it is waiting to write.
  assert!(!conn.wants_read());
  assert!(conn.is_awaiting_send());

  // 3. What to answer with. Advisory — the driver may answer differently or
  //    close without answering — and `None` for a caller-side error.
  let status = failure.suggested_status().expect("a wire fault suggests one");
  assert_eq!(status.code(), 400);

  // 4. Bodiless, and `Connection: close` is INJECTED (a caller that states the
  //    field itself is refused rather than having a second one appended).
  let mut out = [0u8; 64];
  let n = conn
    .send_error_response(status.code(), b"Bad Request", no_fields, &mut out)
    .expect("the one answer is owed");
  assert_eq!(&out[..n], b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");

  // 5. Draining: nothing further is owed either way, and `transport()` is what
  //    says to close it — read, not delivered.
  assert_eq!(conn.transport(), Transport::Ending);
  assert!(!conn.wants_read() && !conn.is_awaiting_send());
  assert!(conn.send_error_response(400, b"", no_fields, &mut out).is_err());
}
```

### The client half

A client is the mirror image: `open_request(method, target, fields, plan, out)`
writes the request head into the caller's slice, and `handle` then yields the
response's `Item::Head` carrying a `StartLine::Status` on the same
`ExchangeId` — through any number of 1xx interim heads (`interim: true`) before
the final one.

Reading it back is the same pump, and it is the half a client cannot skip: a
driver that writes a request and never runs the loop has no answer, and one
that stops at the first head takes an interim response for it.

```rust
use http1_proto::{BodyPlan, Client, Connection, General, Item, StartLine, Target};

fn main() -> Result<(), http1_proto::Error> {
  // RFC 9112 §3.2 makes `Host` a MUST on every HTTP/1.1 request, and every
  // request this crate writes is one — so `open_request` refuses a section
  // without exactly one valid line, and writes nothing.
  let fields: &[(&str, &[u8])] = &[("Host", b"example.com")];
  let first = Target::Origin { path_and_query: "/status" };

  let mut conn = Connection::<Client, General>::new();
  let mut out = [0u8; 64];
  let n = conn.open_request("GET", &first, fields, BodyPlan::None, &mut out)?;
  assert_eq!(&out[..n], b"GET /status HTTP/1.1\r\nHost: example.com\r\n\r\n");
  // ... write out[..n] to the socket, then read the answer back ...

  // This read carried an interim response and the final one behind it. A driver
  // accumulates exactly as the server example does — offer `buffer[start..]`,
  // advance by `consumed()` — and here the whole answer arrived at once.
  let response: &[u8] =
    b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n\
      HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
  let mut body: Vec<u8> = Vec::new();
  let mut interims = 0usize;

  let consumed = {
    let mut items = conn.handle(response);
    while let Some(item) = items.next()? {
      match item {
        Item::Head { exchange, view, line, interim } => {
          let StartLine::Status(status) = line else {
            unreachable!("a client connection reads status-lines")
          };
          // RFC 9110 §15.2 makes a 1xx informational and explicitly not the
          // answer, so it opens no exchange of its own: both heads carry the id
          // `open_request` minted.
          assert_eq!(exchange.get(), 1);
          if interim {
            assert_eq!(status.code, 103);
            assert_eq!(view.header("link"), Some(b"</style.css>; rel=preload".as_slice()));
            interims += 1;
          } else {
            assert_eq!(status.code, 200);
            // The reason-phrase is opaque bytes (RFC 9112 §4): never trimmed,
            // possibly empty, and not necessarily UTF-8.
            assert_eq!(status.reason, b"OK");
          }
        }
        Item::BodyChunk { data, .. } => body.extend_from_slice(data),
        Item::ExchangeComplete { .. } => {}
        // `Item` is `#[non_exhaustive]`: forward what you do not know.
        _ => {}
      }
    }
    items.consumed()
  };

  assert_eq!(consumed, response.len());
  assert_eq!(interims, 1);
  assert_eq!(body, b"hi");

  // Neither question is true, and on a CLIENT that is RFC 9112 §9.2's idle
  // connection rather than a drained one: with nothing outstanding, arriving
  // data would not be a response at all. The next move is the next request —
  // which a driver that read this state as "drained" would never send.
  assert!(!conn.wants_read() && !conn.is_awaiting_send());
  let next = Target::Origin { path_and_query: "/next" };
  let n = conn.open_request("GET", &next, fields, BodyPlan::None, &mut out)?;
  assert_eq!(&out[..n], b"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n");
  Ok(())
}
```

`fields` must satisfy RFC 9112 §3.2's three `Host` MUSTs — **exactly one** field
line, whose value is a **valid authority or empty**. §3.2 makes the field a
client MUST on every HTTP/1.1 request and every request this crate writes is
one, so `open_request` — and Tunnel's `open_upgrade` / `open_connect` — refuse a
section that breaks any of the three and write nothing. An empty value is the
field §3.2 asks for when the target authority is undefined; the value is read
OWS-trimmed, because that is what the recipient reads; and naming the *right*
authority stays the caller's, since only it holds the target URI.

More generally: **what this core reads, this core writes.** `open_request` also
enforces §3.2.3/§3.2.4's target-method pairing (`GET *` is refused), out of the
same predicates the receive path uses — so a request this crate emits is one
this crate's own server half accepts.

### Reading the two questions

| | `wants_read()` | `is_awaiting_send()` |
|---|:---:|:---:|
| A head or body is still arriving | ✅ | |
| A parsed message's reply is owed (RFC 9112 §9.3.2) | | ✅ |
| A violation's single error response is owed (`send_error_response`) | | ✅ |
| **Server: the peer half-closed and the reply is still owed** | | ✅ |
| Keep-alive is over, or the connection failed | | |
| Client with no request outstanding (RFC 9112 §9.2) | | |
| …with an **undecided CR** at its cursor (RFC 9112 §2.2) | ✅ | |
| **Client: the connection switched protocols (RFC 9110 §7.8)** | | |

The half-close row is what a server's `handle_eof` produces for any EOF that is
not a truncation. RFC 9112 §9.6 is explicit that "a TCP connection that is
half-closed by the client does not delimit a request message, nor does it imply
that the client is no longer interested in a response" — so an owed response
survives the EOF: every send call still works, and it goes out.

**So does every response to whatever the peer pipelined behind it.** §9.3.2 had
left those bytes unconsumed in your buffer until the current response went out;
a FIN says the peer will send no *more*, not that it withdrew what it already
sent. After each response the connection re-arms, and **re-offering your buffer**
is what reads the next request out of it — `wants_read()` stays false, because
the socket has nothing left to give. The reference driver above already does
this: it loops back to `handle` after every send rather than only after a read.
The connection drains once that buffer is exhausted.

The read side closing is latched as a fact about the **transport**, in a field of
its own, and nothing ever clears it. It is deliberately *not* a connection
lifecycle state: "can more bytes arrive?" and "will this end accept another
exchange?" are independent questions — a peer can half-close without ever saying
`close`, and say `close` without closing anything — so **when** you report the
EOF cannot change what it means (before the response, after the re-arm, or
repeatedly across both; `handle_eof` is idempotent), and no later `close` can
undo it.

One consequence worth knowing: once the read side is closed, a re-offered buffer
that runs out **mid-message** is a truncation *now* (`Err`), not a wait —
`wants_read()` never goes back to true for bytes that cannot arrive.

What *does* stop it is §9.6's `close` **connection option**, which is the rule
that really says the server "MUST NOT process any further requests received on
that connection". A `close` from the peer's request, from a response you write,
or from a local `close()` drains the connection and suppresses whatever was
buffered behind it — while the read-side fact stays set beside it, so
`wants_read()` remains false and a truncation is still diagnosed. `transport()`
reads `Transport::Ending` from that point, so a driver knows before it writes
that no *new* exchange will follow.

Never both: reading cannot clear a stall on the send side, and a connection
waiting for its own writer wants no bytes.

**Neither true does not mean "drained".** It means nothing is owed to the
transport *right now*, and the table's three blank rows are three different
reasons for that — with three different next moves:

- **Keep-alive is over** (either role), or the connection failed — the
  connection has drained. RFC 9112 §9.6 makes any further pipelined bytes
  unprocessable, and the core leaves them unconsumed rather than silently
  dropping them: stop reading and close the transport.
- **A client with no request outstanding** — the exchange completed and the
  connection is idle and healthy. RFC 9112 §9.2 is why it wants no bytes: with
  nothing outstanding, arriving data is not a response at all. The next move is
  `open_request` (or a close, if the driver is done). A client driver that reads
  this state as "drained" and leaves its read loop never sends its second
  request.

  **One exception, and it is the last row of the table.** If a lone `\r` is
  sitting at that idle cursor, `wants_read()` is **true** even with nothing
  outstanding: RFC 9112 §2.2 makes a CR a terminator only once its LF has
  arrived, so the byte behind it is what decides whether it was one more stray
  empty line to discard (§9.2) or the start of something that is not a response
  at all. `open_request` is **refused** (`Error::InvalidState`) while that CR is
  undecided — it sits in front of whatever the peer sends next, so opening over
  it would put a bare CR at the head of the response parse. Read the deciding
  byte first; `wants_read()` is already asking for it.

- **A client that switched protocols** (RFC 9110 §7.8) — and this is the one
  where the first bullet's advice is exactly wrong. Both halves go quiet from
  the PHASE rather than from the message state: `wants_read()` is false because
  the bytes on that transport are the next protocol's, and `is_awaiting_send()`
  is false because this end has no write left to make. The connection is still
  `Open` and its request is still outstanding — §7.8 leaves it so, since "the
  server still has an outstanding request to satisfy after the protocol has been
  changed" — so neither reading above fits. The transport is to be **handed
  over**, not closed, and it is not idle either: `open_request` is refused. See
  step 7 above.

A driver never has to guess which of the three it is in — it asks
`transport()`, which answers `HandedOver` for the third and `Ending` for the
first, and an idle client is what is left when neither happened. That answer is
DERIVED on the ask rather than delivered once, so it cannot be missed by a
driver that was not listening, and asking twice is two reads rather than two
instructions.

## Tunnel mode

`Connection<_, Tunnel>` exists to complete exactly one protocol switch — RFC 9110
§7.8's `Upgrade` or §9.3.6's `CONNECT` — and then get out of the way. It is a
separate *mode* of the same type-state rather than a runtime flag, so a Tunnel
connection cannot be asked to stream exchanges; that is a compile error.

BUILDING a handshake is this mode's; CARRYING one that arrived on an ordinary
exchange is not. A `Connection<Client, General>` constructed with
`Limits::allow_opportunistic_upgrade(true)` may make a §7.8 offer on an ordinary
`open_request` — the `Upgrade` field §7.8 makes the *indication*, plus the
`upgrade` connection option §7.8's sender MUST requires beside it — and takes the
answering 101 as `Item::Switched { head, leftover }`, after which the connection
is spent: the transport belongs to the protocol the 101 named and every later
call refuses. The offering request must be **bodiless**, and that is this
crate's restriction rather than the RFC's: §7.8 would let a 101 answer a request
whose body is still going out, the client finishing it in the old protocol
before beginning the new one, but a core that parks at the 101 and hands the
transport over has no send side left to finish it through. Every other 101 a
General connection can receive stays a protocol error, since §7.8 forbids a
server to switch to a protocol "not indicated by the client in the corresponding
request's Upgrade header field". The permission is OFF by default — §7.8 obliges a client to nothing, so a driver that wants the
capability asks for it, and a proxy-shaped driver forwarding a downstream
client's `Upgrade` field never chose to send one.

Every outcome that **consumed a head** reports the **leftover**: the suffix of
the offered bytes that head did not cover. There is no exception to remember —
a driver advances its buffer by the same arithmetic whatever the answer was.

| Outcome | Consumes | What `leftover` is |
|---|---|---|
| `Switched` (RFC 9110 §15.2.2) | the 101 head | the new protocol's first byte, verbatim — including whatever the peer pipelined into the same read |
| `Tunneled` (RFC 9110 §9.3.6) | the 2xx head | the tunnel's first byte, verbatim |
| `Interim` (RFC 9110 §15.2) | the 1xx head | where the next head begins; the handshake stays open |
| `Refused` | the refusing head | the first byte of whatever **content** the refusal carries — **unframed**, see below |
| `NeedMore` | nothing | — offer the same bytes again with more behind them |

`Refused` is terminal for the *handshake*: the phase is spent, and no further
call on the connection succeeds. Its content is still reachable, and usually
needs to be — RFC 9110 §15.5.22's `426` describes the protocol it wants, and
§11.7's `407` carries the `Proxy-Authenticate` challenge a client must read
before it can retry.

What this core does **not** do is delimit that content. Tunnel mode has no body
machinery, and adding one for a message the connection closes behind would be a
second implementation of RFC 9112 §6.3 living where no second message can
follow it. So where the body *ends* is your reading of the head you were just
handed — item 6's `Content-Length`, item 4's `Transfer-Encoding: chunked`, or
item 8's remainder-until-close — and a caller that wants it framed asks over a
`General` connection instead.

```rust
use http1_proto::{ClientTunnelOutcome, Client, Connection, Target, Tunnel};

fn main() -> Result<(), http1_proto::Error> {
  // RFC 9110 §7.8 wants both halves of the offer: the `upgrade` connection
  // option, and an `Upgrade` field naming a protocol.
  let offer: &[(&str, &[u8])] = &[
    ("Host", b"example.com"),
    ("Connection", b"Upgrade"),
    ("Upgrade", b"websocket"),
  ];
  let mut conn = Connection::<Client, Tunnel>::new();
  let mut out = [0u8; 256];
  let n = conn.open_upgrade(&Target::Origin { path_and_query: "/" }, offer, &mut out)?;
  assert_eq!(
    &out[..n],
    b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
  );

  // The server switched, and pipelined the first frame of the new protocol into
  // the same read (RFC 9110 §15.2.2).
  let response = b"HTTP/1.1 101 Switching Protocols\r\n\
                   Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x03abc";
  match conn.handle_response(response)? {
    ClientTunnelOutcome::Switched { head, leftover } => {
      assert_eq!(head.header("upgrade"), Some(b"websocket".as_slice()));
      assert_eq!(leftover, b"\x81\x03abc"); // the new protocol's, not ours
    }
    other => unreachable!("the server switched: {other:?}"),
  }
  Ok(())
}
```

The core validates that a 101 names a protocol and that the exchange was
offerable; matching the response's `Upgrade` token against what the caller
*offered* is delegated upward (RFC 9110 §7.8) — the offer is the caller's
knowledge, and `websocket-proto` performs that match.

## Tiers

| Cargo features | Heap | Target example |
|---|---|---|
| `default` (`std`) | yes | any std platform |
| `alloc` | yes (no `std`) | WASM, embedded with allocator |
| `no-atomic` | yes (no `std`, no atomic CAS) | `thumbv6m-none-eabi` (Cortex-M0+, RP2040) |
| _(none)_ | **no** | `thumbv6m-none-eabi`, `thumbv7em-none-eabihf` |

`Connection<Role, Mode>` is `const _: () = assert!(…)`-bounded to 256 bytes and
`HeadView` to 128, unconditionally — so the bound is const-evaluated on every
target the crate is checked against, including the 32-bit `usize` ones.

## Conformance

The strictness posture, in one line: **reject what an RFC leaves us free to
reject**, because every accepted ambiguity is a request-smuggling vector between
two recipients that resolve it differently.

- Strict CRLF everywhere — head lines, chunk lines, trailers. Bare CR, bare LF,
  obs-fold, whitespace before a field colon, and whitespace before the first
  field line are all refused (RFC 9112 §2.2, §5.1, §5.2).
- Every framing ambiguity RFC 9112 §6.3 names is a hard error rather than a
  guess: `Transfer-Encoding` beside `Content-Length`, differing `Content-Length`
  values, `chunked` that is not the final coding in a request.
- Every protocol-violation error carries a byte offset (`MalformedDetail`) and,
  where a server would answer, a `SuggestedStatus` (400 / 414 / 431 / 501 / 505).
- A [`no-panic`] link-time test (`tests/no_panic.rs`) proves eleven leaf
  primitives compile to panic-free code in release: the head-end scanner, the
  status-line and chunk-size parsers, the §5.6.6 parameterised-list walk, the
  §12.4.2 `qvalue` reader, the §12.5.1 weight selection, the FNV-1a head digest,
  and the inbound body budget's four leaves. Every argument at every call site
  goes through `core::hint::black_box`, which is load-bearing rather than
  decorative: a shim called with compile-time constants is folded away before
  the guard can act, so the symbol that would fail the link is never emitted and
  the shim "passes" with an empty proof. A **lie-check** keeps that honest — the
  internal `test-no-panic-lie` feature adds one shim with a deliberately
  reachable panic, and CI asserts that building it **fails**. The rest of the
  crate is held by the crate-wide clippy panic-freedom lint wall
  (`unwrap_used` / `indexing_slicing` / `arithmetic_side_effects` / …) and by
  `forbid(unsafe_code)`.
- The parser is checked against `httparse` as a **differential oracle**
  (`tests/differential.rs`): we are never more permissive, and every stricter
  refusal is justified in the file with its RFC citation. The same corpus is
  compared a second time for where each parser says a head *ends* — two
  recipients that accept the same head but cut it in different places have
  already disagreed about where the body begins.
- A **request-smuggling** corpus in both directions. `tests/smuggling.rs` pins
  each named inbound vector, accept side and reject side, with the exact refusal
  it earns; `tests/smuggling_outbound.rs` is the mirror over the send API — the
  head/plan combinations this core refuses to *write*, since §11.1 and §11.2 do
  not require the disagreement to be the peer's fault.
- A **split-robustness** property (`tests/split_robustness.rs`) asserts that where
  the transport cut the byte stream cannot change what the connection says about
  it — one shot, byte-at-a-time, every single cut, and proptest-generated
  multi-cut vectors, over a corpus covering every inbound shape.

The full MUST / MUST NOT / SHOULD / MAY matrix, mapping each rule to its
implementing module and test, is the conformance appendix of the design spec.

## MSRV

Rust 1.91.0. The MSRV may be raised in a minor release.

## License

`http1-proto` is under the terms of both the MIT license and the Apache
License (Version 2.0).

See [LICENSE-APACHE](../LICENSE-APACHE), [LICENSE-MIT](../LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.

[`no-panic`]: https://docs.rs/no-panic
[`HeadView`]: https://docs.rs/http1-proto/latest/http1_proto/head/struct.HeadView.html
[Github-url]: https://github.com/al8n/websockit/
[CI-url]: https://github.com/al8n/websockit/actions/workflows/ci.yml
[doc-url]: https://docs.rs/http1-proto
[crates-url]: https://crates.io/crates/http1-proto
