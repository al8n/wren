use super::*;
use crate::duplex::{Pipe, duplex};
use agnostic_lite::tokio::TokioRuntime;

// The driver layer is covered here, over the in-memory duplex, including the
// `accept_pending` accept and reject round-trips; tests/loopback.rs drives the
// same entry points over real TCP.

/// `Duplex` is a `Send` bound, and a server that authorizes before answering
/// holds the pending accept across an await — usually on a spawned task. What
/// the pending accept now carries — an advanced `ServerHandshake` holding its
/// own validated answer — must not take that away.
const _: fn() = || {
  fn is_send<T: Send>() {}
  is_send::<crate::PendingAccept<TokioRuntime, Pipe>>();
};

#[tokio::test]
async fn client_and_server_handshake_over_duplex() {
  let (client_stream, server_stream) = duplex();
  let opts = ClientOptions::default().with_subprotocols(["chat"]);
  let client = tokio::spawn(async move {
    let (_stream, outcome) = drive_client(client_stream, "example.com", "/chat", &opts)
      .await
      .unwrap();
    outcome
  });
  let acc = AcceptOptions::default().with_supported_subprotocols(["chat"]);
  let mut stream = server_stream;
  let pending = drive_server_request(&mut stream, &acc).await.unwrap();
  assert_eq!(pending.summary.path(), "/chat");
  assert_eq!(pending.summary.host(), "example.com");
  let (_stream, server) = finish_accept(
    stream,
    pending.handshake,
    pending.summary,
    pending.buffered,
    &acc,
  )
  .await
  .unwrap();
  let client = client.await.unwrap();
  assert_eq!(client.negotiated.subprotocol(), Some("chat"));
  assert_eq!(server.negotiated.subprotocol(), Some("chat"));
  assert_eq!(server.summary.path(), "/chat");
  assert!(client.leftover.is_empty());
  assert!(server.leftover.is_empty());
}

/// The other half of what the pending accept carries: RFC 6455 §4.2.2 step 5
/// lets the server answer an otherwise valid request with a non-101, and that
/// answer is written through the SAME connection that classified the request —
/// a tunnel that never read one has nothing to refuse. So the handshake has to
/// travel to the rejection exactly as it travels to the 101.
#[tokio::test]
async fn pending_accept_can_reject_before_the_upgrade() {
  let (client_stream, server_stream) = duplex();
  let client = tokio::spawn(async move {
    crate::client::<TokioRuntime, _>(
      client_stream,
      "intruder.example",
      "/admin",
      ClientOptions::default(),
    )
    .await
    .map(|_| ())
  });
  let pending = crate::accept_pending::<TokioRuntime, _>(server_stream, AcceptOptions::default())
    .await
    .unwrap();
  // The caller inspects the request BEFORE anything is written…
  assert_eq!(pending.request().path(), "/admin");
  assert_eq!(pending.request().host(), "intruder.example");
  // …and turns it away without establishing the connection. `finish_reject`
  // drops the transport when it returns, so a rejection that never reached the
  // wire ends the client's read rather than parking it.
  pending.reject(403, "Forbidden").await.unwrap();
  let err = client.await.unwrap().unwrap_err();
  assert!(
    matches!(err, ConnectError::Rejected { status: 403 }),
    "{err:?}"
  );
}

/// A request that broke a WebSocket rule, in the one shape RFC 6455 §4.2.2
/// answers with something other than a 400: "If the server doesn't support the
/// requested version, it MUST respond with a `Sec-WebSocket-Version` header
/// field ... containing the version(s) the server is capable of". A driver that
/// dropped the transport would leave the client unable to tell an unsupported
/// version from a dead server, and with nothing to retry with.
#[tokio::test]
async fn an_unsupported_version_is_answered_with_426_rather_than_a_close() {
  const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 8\r\n\r\n";

  let (mut client, mut server) = duplex();
  client.write_all(REQUEST).await.unwrap();
  client.flush().await.unwrap();

  let err = drive_server_request(&mut server, &AcceptOptions::default())
    .await
    .unwrap_err();
  // The caller is told why the HANDSHAKE failed. Writing the refusal is
  // best-effort and never becomes the reported fault.
  assert!(
    matches!(
      err,
      AcceptError::Handshake(ServerHandshakeError::UnsupportedVersion)
    ),
    "{err:?}"
  );
  drop(server);

  let mut answer = Vec::new();
  client.read_to_end(&mut answer).await.unwrap();
  let answer = String::from_utf8(answer).unwrap();
  assert!(
    answer.starts_with("HTTP/1.1 426 Upgrade Required\r\n"),
    "{answer}"
  );
  assert!(
    answer.contains("\r\nSec-WebSocket-Version: 13\r\n"),
    "{answer}"
  );
}

/// RFC 6455 §4.2.1: a server that stops processing a handshake "MUST stop
/// processing the client's handshake and return an HTTP response with an
/// appropriate error code (such as 400 Bad Request)" — and the fault here is
/// HTTP's (whitespace before the field colon, RFC 9112 §5.1), read by
/// http1-proto rather than by this layer. The connection is left reject-only
/// precisely so the answer is still writable.
#[tokio::test]
async fn a_malformed_request_is_answered_with_400_rather_than_a_close() {
  let (mut client, mut server) = duplex();
  client
    .write_all(b"GET /chat HTTP/1.1\r\nHost : example.com\r\n\r\n")
    .await
    .unwrap();
  client.flush().await.unwrap();

  let err = drive_server_request(&mut server, &AcceptOptions::default())
    .await
    .unwrap_err();
  assert!(
    matches!(err, AcceptError::Handshake(ServerHandshakeError::Http(_))),
    "{err:?}"
  );
  drop(server);

  let mut answer = Vec::new();
  client.read_to_end(&mut answer).await.unwrap();
  let answer = String::from_utf8(answer).unwrap();
  assert!(
    answer.starts_with("HTTP/1.1 400 Bad Request\r\n"),
    "{answer}"
  );
  assert!(answer.contains("\r\nConnection: close\r\n"), "{answer}");
}

/// The property the pipelined leftover exists for: RFC 6455 §4.1 lets a client
/// send frames the moment its request is out, so the first frame can share a
/// segment with the handshake. Those bytes are read by the handshake driver and
/// have to reach the connection machine, not be dropped with the read buffer.
#[tokio::test]
async fn a_frame_sent_with_the_request_survives_the_accept() {
  const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\r\n";
  // A masked text frame carrying "abc" (RFC 6455 §5.3: a client MUST mask).
  const FRAME: &[u8] = &[0x81, 0x83, 0x37, 0xfa, 0x21, 0x3d, 0x56, 0x98, 0x42];

  let (mut client, server_stream) = duplex();
  let mut segment = REQUEST.to_vec();
  segment.extend_from_slice(FRAME);
  // ONE write: the request and the frame reach the server together, so the
  // handshake's read buffer necessarily holds both.
  client.write_all(&segment).await.unwrap();
  client.flush().await.unwrap();

  let pending = crate::accept_pending::<TokioRuntime, _>(server_stream, AcceptOptions::default())
    .await
    .unwrap();
  assert_eq!(pending.request().path(), "/chat");
  let (mut ws, _summary) = pending.accept().await.unwrap();
  // The client end goes away once it has been answered. The frame is already
  // in the connection's hands if the leftover survived, so a driver that
  // dropped it reports the close here instead of blocking for a frame that
  // was sent long ago.
  drop(client);
  let msg = ws.next().await.unwrap().unwrap();
  assert_eq!(msg, crate::Message::Text("abc".into()));
}

/// RFC 9110 §15.2 lets any number of 1xx responses precede the final one, and
/// `ClientProgress::Interim` reports how far the buffer advanced past each.
/// Advancing is the whole point: a driver that lost the offset would re-offer
/// the same head and read it forever — a HANG rather than a failed assertion,
/// which is the worst thing to leave uncovered in CI.
///
/// Two interims, of different lengths, glued to the 101 in ONE segment: the
/// offset has to ACCUMULATE (`start += consumed`), and everything after the
/// first is served out of the buffer the driver already holds rather than out
/// of a fresh read.
#[tokio::test]
async fn interim_responses_before_the_switch_are_consumed_not_re_read() {
  let (client_stream, mut server) = duplex();
  let opts = ClientOptions::default();
  let client = tokio::spawn(async move {
    drive_client(client_stream, "example.com", "/", &opts)
      .await
      .map(|(_stream, outcome)| outcome)
  });

  // A real server side, so the 101 carries the accept value for the key this
  // client actually generated.
  let mut hs = ServerHandshake::new();
  let mut acc: Vec<u8> = Vec::new();
  let mut chunk = vec![0u8; 4096];
  loop {
    let got = server.read(&mut chunk).await.unwrap();
    assert!(got > 0, "the request reached the server");
    acc.extend_from_slice(chunk.get(..got).unwrap_or(&[]));
    match hs.handle(&acc).unwrap() {
      ServerProgress::NeedMore => continue,
      ServerProgress::Upgrade(mut pending) => {
        pending.validate_accept(&Accept::new()).unwrap();
        break;
      }
      other => panic!("expected an upgrade request, got {other:?}"),
    }
  }
  let mut response = vec![0u8; 4096];
  let (n, _) = hs
    .encode_response(&ExtraHeaders::new(), &mut response)
    .unwrap();

  let mut segment = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\n".to_vec();
  segment.extend_from_slice(response.get(..n).unwrap_or(&[]));
  server.write_all(&segment).await.unwrap();
  server.flush().await.unwrap();

  let outcome = client.await.unwrap().unwrap();
  // Both interims were consumed where they sat: the frame stream starts after
  // the 101, so anything mis-counted would surface as leftover bytes here.
  assert!(outcome.leftover.is_empty(), "{:?}", outcome.leftover);
}

/// Regression: consuming an interim response used to advance a cursor and
/// nothing else, so the bytes behind it stayed in `acc` while later reads kept
/// appending — and RFC 9110 §15.2 puts no limit on how many interim responses
/// may precede the answer, so a hostile server grew the buffer until the client
/// ran out of memory. The cursor was chosen over a drain to avoid a memmove;
/// that trade bought unbounded growth.
///
/// This is the client loop's own buffer arithmetic, run for far more rounds
/// than the interim bound allows: the retained capacity is the assertion, and
/// without the drop it would be the whole 4 MiB this feeds through.
#[test]
fn consumed_interim_bytes_leave_the_accumulator() {
  let mut acc: Vec<u8> = Vec::with_capacity(READ_CHUNK);
  let mut start = 0usize;
  let head = vec![b'x'; READ_CHUNK];
  for _ in 0..1024 {
    acc.extend_from_slice(&head); // one read
    start = start.saturating_add(head.len()); // …classified as one interim
    drop_consumed(&mut acc, &mut start);
  }
  assert_eq!(start, 0);
  assert!(acc.is_empty());
  assert!(
    acc.capacity() <= READ_CHUNK.saturating_mul(2),
    "the accumulator retained {} bytes across 1024 interim responses",
    acc.capacity()
  );

  // A read that carried an interim AND the head behind it keeps the suffix:
  // dropping the consumed prefix must not drop the answer glued to it.
  let mut acc = b"interim-headHTTP/1.1 101 ...".to_vec();
  let mut start = "interim-head".len();
  drop_consumed(&mut acc, &mut start);
  assert_eq!(acc, b"HTTP/1.1 101 ...");
  assert_eq!(start, 0);

  // Panic-free at the edges: nothing consumed, and everything consumed.
  let mut acc = b"abc".to_vec();
  let mut start = 0usize;
  drop_consumed(&mut acc, &mut start);
  assert_eq!(acc, b"abc");
  let mut start = acc.len();
  drop_consumed(&mut acc, &mut start);
  assert!(acc.is_empty());
}

/// Compacting bounds the MEMORY an endless 1xx stream costs, not the WORK: RFC
/// 9110 §15.2 lets a server send interim responses forever, and a client that
/// obeys that literally never returns — a connect that hangs with nothing to
/// report. The driver stops at `MAX_INTERIM_RESPONSES` and says so.
#[tokio::test]
async fn a_server_that_streams_interim_responses_is_refused_rather_than_read_forever() {
  let (client_stream, mut server) = duplex();
  let opts = ClientOptions::default();
  let client = tokio::spawn(async move {
    drive_client(client_stream, "example.com", "/", &opts)
      .await
      .map(|_| ())
  });
  let mut sink = vec![0u8; 4096];
  assert!(
    server.read(&mut sink).await.unwrap() > 0,
    "the request reached the server"
  );

  // One head per write, so they reach the client across separate reads. Past
  // the bound the client is gone and its end of the pipe is closed, which is
  // the refusal arriving rather than a fault of the test.
  for _ in 0..=MAX_INTERIM_RESPONSES {
    if server
      .write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n")
      .await
      .is_err()
    {
      break;
    }
    let _ = server.flush().await;
  }

  // Then the transport ends. The bound has already fired by now, so this
  // changes nothing about the outcome — it is here so that losing the bound
  // FAILS this test with an EOF instead of hanging CI forever, which is the
  // shape of the defect being pinned.
  drop(server);

  let err = client.await.unwrap().unwrap_err();
  assert!(
    matches!(
      err,
      ConnectError::TooManyInterimResponses {
        limit: MAX_INTERIM_RESPONSES
      }
    ),
    "{err:?}"
  );
}

/// A refusal is an ANSWER, not a fault. A driver that mistook it for "read
/// more" would loop until the peer closed and report the close instead — so
/// the server here closes right after refusing, and the assertion is that the
/// status survived rather than an `UnexpectedEof` taking its place.
#[tokio::test]
async fn a_refusal_reaches_the_caller_as_rejected_not_as_an_eof() {
  let (client_stream, server_stream) = duplex();
  let opts = ClientOptions::default();
  let client = tokio::spawn(async move {
    drive_client(client_stream, "example.com", "/", &opts)
      .await
      .map(|_| ())
  });
  use futures_util::{AsyncReadExt as _, AsyncWriteExt as _};
  let mut server_stream = server_stream;
  let mut sink = vec![0u8; 4096];
  assert!(
    server_stream.read(&mut sink).await.unwrap() > 0,
    "the request reached the server"
  );
  server_stream
    .write_all(
      b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"wren\"\r\n\
Content-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
  server_stream.flush().await.unwrap();
  drop(server_stream);
  let err = client.await.unwrap().unwrap_err();
  assert!(
    matches!(err, ConnectError::Rejected { status: 401 }),
    "{err:?}"
  );
}

#[tokio::test]
async fn rejected_status_surfaces_as_rejected() {
  let (client_stream, server_stream) = duplex();
  let opts = ClientOptions::default();
  let client = tokio::spawn(async move {
    drive_client(client_stream, "example.com", "/", &opts)
      .await
      .map(|_| ())
  });
  // Swallow the request (any prefix will do), answer with a 403.
  use futures_util::{AsyncReadExt as _, AsyncWriteExt as _};
  let mut server_stream = server_stream;
  let mut sink = vec![0u8; 4096];
  let swallowed = server_stream.read(&mut sink).await.unwrap();
  assert!(swallowed > 0, "the request reached the server");
  server_stream
    .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
    .await
    .unwrap();
  server_stream.flush().await.unwrap();
  let err = client.await.unwrap().unwrap_err();
  assert!(matches!(err, ConnectError::Rejected { status: 403 }));
}

/// Sixty subprotocol offers survive the driver.
///
/// Regression: websocket-proto emitted one `Sec-WebSocket-Protocol` field LINE
/// per offer, so sixty of them made a sixty-five-line head — one past the
/// `MAX_HEADERS = 64` that http1-proto's scanner, which is what this driver's
/// server side reads with, refuses. The client wrote the request happily and
/// the failure landed on the peer.
#[tokio::test]
async fn sixty_subprotocol_offers_survive_the_driver() {
  let names: Vec<String> = (0..60).map(|i| format!("p{i}")).collect();
  let (client_stream, server_stream) = duplex();
  let opts = ClientOptions::default().with_subprotocols(names.clone());
  let client = tokio::spawn(async move {
    let (_stream, outcome) = drive_client(client_stream, "example.com", "/chat", &opts)
      .await
      .unwrap();
    outcome
  });
  // The LAST offer, so a server that saw only the head's first element would
  // not have it to select.
  let acc = AcceptOptions::default().with_supported_subprotocols(["p59"]);
  let mut stream = server_stream;
  let pending = drive_server_request(&mut stream, &acc).await.unwrap();
  let (_stream, server) = finish_accept(
    stream,
    pending.handshake,
    pending.summary,
    pending.buffered,
    &acc,
  )
  .await
  .unwrap();
  let client = client.await.unwrap();
  assert_eq!(client.negotiated.subprotocol(), Some("p59"));
  assert_eq!(server.negotiated.subprotocol(), Some("p59"));
}
