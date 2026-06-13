use super::*;
use crate::duplex::{Pipe, duplex};
use agnostic_lite::tokio::TokioRuntime;

type Client = WebSocket<TokioRuntime, ClientRole, Pipe>;
type Server = WebSocket<TokioRuntime, ServerRole, Pipe>;

fn pair() -> (Client, Server) {
  pair_with(Default::default(), Default::default())
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
