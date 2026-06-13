use super::*;
use crate::duplex::{Pipe, duplex, duplex_with_capacity};
use agnostic_lite::tokio::TokioRuntime;

type Client = WebSocket<TokioRuntime, ClientRole, Pipe>;
type Server = WebSocket<TokioRuntime, ServerRole, Pipe>;

fn pair() -> (Client, Server) {
  pair_with(Default::default(), Default::default())
}

fn pair_cap(cap: usize) -> (Client, Server) {
  let (c, s) = duplex_with_capacity(cap);
  let n = Negotiated::none();
  (
    WebSocket::client(c, &n, &Default::default(), Vec::new()),
    WebSocket::server(s, &n, &Default::default(), Vec::new()),
  )
}

fn pair_with(co: crate::options::ClientOptions, so: crate::options::AcceptOptions) -> (Client, Server) {
  let (c, s) = duplex();
  let n = Negotiated::none();
  (
    WebSocket::client(c, &n, &co, Vec::new()),
    WebSocket::server(s, &n, &so, Vec::new()),
  )
}

#[tokio::test]
async fn echo_text_round_trip() {
  let (mut client, mut server) = pair();
  client.send_text("hello").await.unwrap();
  let task = tokio::spawn(async move {
    let m = server.next().await.unwrap().unwrap();
    server.send(m).await.unwrap();
    server
  });
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("hello".into()));
  drop(task.await);
}

#[tokio::test]
async fn large_binary_round_trip() {
  let (mut client, mut server) = pair();
  let payload = vec![0xAB_u8; 1 << 20];
  let expect = payload.clone();
  let task = tokio::spawn(async move {
    let m = server.next().await.unwrap().unwrap();
    assert_eq!(m, Message::Binary(expect.into()));
  });
  client.send_binary(&payload).await.unwrap();
  task.await.unwrap();
}

#[tokio::test]
async fn inbound_arrives_while_outbound_is_backpressured() {
  // The property wren-compio's single pump could not satisfy: a large
  // outbound write to a slow-reading peer must NOT delay inbound delivery.
  // 4 KiB pipes in both directions; the client pushes a 1 MiB outbound the
  // server does not drain yet, while the server's small messages must reach
  // the client's reader promptly.
  let (client, server) = pair_cap(4 * 1024);
  let (mut cread, mut cwrite) = client.split();
  let (mut sread, mut swrite) = server.split();

  let big = vec![0xCD_u8; 1 << 20];
  let expect = big.clone();
  // Client writer: stuck pushing 1 MiB (server reads it only later).
  let client_writer = tokio::spawn(async move {
    cwrite.send_binary(&big).await.unwrap();
    cwrite
  });
  // Server: send 5 small messages first, THEN drain the big inbound.
  let server_task = tokio::spawn(async move {
    for i in 0..5u32 {
      swrite.send_text(&format!("s{i}")).await.unwrap();
    }
    let m = sread.next().await.unwrap().unwrap();
    assert_eq!(m, Message::Binary(expect.into()));
    (sread, swrite)
  });

  // The client receives all 5 promptly while its writer is backpressured.
  for i in 0..5u32 {
    let m = tokio::time::timeout(std::time::Duration::from_secs(5), cread.next())
      .await
      .expect("inbound delivered while outbound is backpressured")
      .unwrap()
      .unwrap();
    assert_eq!(m, Message::Text(format!("s{i}").into()));
  }
  client_writer.await.unwrap();
  drop(server_task.await.unwrap());
}

use std::time::Duration;

#[tokio::test]
async fn close_handshake_completes() {
  let (client, mut server) = pair();
  let server_task = tokio::spawn(async move {
    assert!(server.next().await.is_none());
    let c = server.closed().unwrap();
    assert_eq!(c.code(), CloseCode::Normal);
    assert!(c.clean());
  });
  let closed = client.close(CloseCode::Normal, "bye").await.unwrap();
  assert!(closed.clean());
  server_task.await.unwrap();
}

#[tokio::test]
async fn keepalive_pings_flow_while_idle() {
  let co = crate::options::ClientOptions::default().with_keepalive(Some(Duration::from_millis(50)));
  let (mut client, mut server) = pair_with(co, Default::default());
  // Both pumps idle: the client keepalive emits pings, the server auto-pongs,
  // and no data message surfaces — so the experiment times out.
  let outcome = tokio::time::timeout(Duration::from_millis(400), async {
    tokio::select! {
      m = client.next() => m,
      m = server.next() => m,
    }
  })
  .await;
  assert!(outcome.is_err(), "no data message may surface");
  assert!(server.pings_seen() >= 1, "server saw the keepalive ping(s)");
}

#[tokio::test]
async fn close_deadline_fires_without_peer_echo() {
  let (c, _held_open) = duplex(); // the peer never answers
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_close_timeout(Duration::from_millis(80));
  let client = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &co, Vec::new());
  let closed = client.close(CloseCode::Normal, "").await.unwrap();
  assert!(!closed.clean(), "deadline close is unclean");
}

#[tokio::test]
async fn write_half_close_drives_through_reader() {
  let (mut client, server) = pair();
  let (mut sread, mut swrite) = server.split();
  let reader = tokio::spawn(async move {
    while sread.next().await.is_some() {}
    sread
  });
  swrite.close(CloseCode::Normal, "done").await.unwrap();
  assert!(client.next().await.is_none());
  assert_eq!(client.closed().unwrap().code(), CloseCode::Normal);
  let sread = reader.await.unwrap();
  assert!(sread.closed().unwrap().clean());
}

#[tokio::test]
async fn pong_flushes_before_buffered_data_delivery() {
  let (mut client, mut server) = pair();
  // Ping + Text land in the server's pipe before it polls once.
  client.ping(b"are-you-there").await.unwrap();
  client.send_text("data").await.unwrap();
  let m = server.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("data".into()));
  // The Pong is already on the wire: the client sees it with no more server
  // polls (RFC 6455 §5.5.3 "as soon as practical").
  let outcome = tokio::time::timeout(Duration::from_millis(100), client.next()).await;
  assert!(outcome.is_err(), "no data message surfaces on the client");
  assert_eq!(client.pongs_seen(), 1, "the pong reached the client");
}

#[tokio::test]
async fn write_error_poisons_the_connection() {
  // The transport accepts 4 KiB, fails one write, then recovers.
  let (c, s) = crate::duplex::duplex_with_write_fault(4 * 1024);
  let n = Negotiated::none();
  let mut client = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &Default::default(), Vec::new());
  let _server = WebSocket::<TokioRuntime, ServerRole, Pipe>::server(s, &n, &Default::default(), Vec::new());

  let payload = vec![0xAA_u8; 64 * 1024];
  let err = client.send_binary(&payload).await.unwrap_err();
  let Error::Io(first) = err else {
    panic!("write fault surfaces as Io, got {err:?}");
  };
  // A partial frame is on the wire; nothing may be spliced after it.
  let err = client.send_text("tail").await.unwrap_err();
  assert!(matches!(&err, Error::Io(e) if e.kind() == first.kind()));
  let err = client.next().await.unwrap().unwrap_err();
  assert!(matches!(&err, Error::Io(e) if e.kind() == first.kind()));
}

#[tokio::test]
async fn sends_survive_read_half_drop() {
  let (mut client, server) = pair();
  let (sread, mut swrite) = server.split();
  drop(sread);
  // The writer keeps working — it owns proto + the write transport.
  swrite.send_text("after drop").await.unwrap();
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("after drop".into()));
  // Dropping the writer too closes the transport: the peer sees EOF.
  drop(swrite);
  match client.next().await {
    None => {}
    Some(Err(Error::Io(_))) => {}
    other => panic!("expected EOF after both halves drop, got {other:?}"),
  }
}

#[tokio::test]
async fn reads_survive_write_half_drop() {
  let (client, server) = pair();
  let (mut sread, swrite) = server.split();
  drop(swrite);
  // The reader still pumps — it can write control frames via the shared
  // transport and complete a peer-initiated clean close.
  let reader = tokio::spawn(async move {
    while sread.next().await.is_some() {}
    sread
  });
  let closed = client.close(CloseCode::Normal, "bye").await.unwrap();
  assert!(closed.clean());
  let sread = reader.await.unwrap();
  assert!(sread.closed().unwrap().clean());
}

#[tokio::test]
async fn cancelled_next_preserves_the_connection() {
  let (mut client, mut server) = pair();
  // Poll server.next() once (it parks on the read) then drop it — the
  // readiness model consumed nothing.
  {
    use std::future::Future;
    let mut fut = Box::pin(server.next());
    std::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  client.send_text("after cancel").await.unwrap();
  let m = server.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("after cancel".into()));
  // Reverse direction too.
  server.send_text("echo").await.unwrap();
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("echo".into()));
}
