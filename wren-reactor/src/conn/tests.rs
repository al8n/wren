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
