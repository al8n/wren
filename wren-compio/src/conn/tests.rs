use super::*;
use crate::duplex::{Pipe, duplex};

fn pair() -> (WebSocket<ClientRole, Pipe>, WebSocket<ServerRole, Pipe>) {
  pair_with(
    crate::options::ClientOptions::default(),
    crate::options::AcceptOptions::default(),
  )
}

fn pair_with(
  copts: crate::options::ClientOptions,
  sopts: crate::options::AcceptOptions,
) -> (WebSocket<ClientRole, Pipe>, WebSocket<ServerRole, Pipe>) {
  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  (
    WebSocket::client(c, &negotiated, &copts, Vec::new()),
    WebSocket::server(s, &negotiated, &sopts, Vec::new()),
  )
}

#[compio::test]
async fn echo_text_round_trip() {
  let (mut client, mut server) = pair();
  client.send_text("hello").await.unwrap();
  let echo = compio_runtime::spawn(async move {
    let msg = server.next().await.unwrap().unwrap();
    server.send(msg).await.unwrap();
    server
  });
  let msg = client.next().await.unwrap().unwrap();
  assert_eq!(msg, Message::Text("hello".into()));
  drop(echo.await);
}

#[compio::test]
async fn large_binary_round_trip() {
  let (mut client, mut server) = pair();
  let payload = vec![0xAB_u8; 1 << 20];
  let expect = payload.clone();
  let server_task = compio_runtime::spawn(async move {
    let msg = server.next().await.unwrap().unwrap();
    assert_eq!(msg, Message::Binary(expect.into()));
  });
  client.send_binary(&payload).await.unwrap();
  server_task.await.unwrap();
}

#[compio::test]
async fn close_handshake_completes() {
  let (client, mut server) = pair();
  let server_task = compio_runtime::spawn(async move {
    assert!(server.next().await.is_none());
    let closed = server.closed().unwrap();
    assert_eq!(closed.code(), CloseCode::Normal);
    assert!(closed.clean());
  });
  let closed = client.close(CloseCode::Normal, "bye").await.unwrap();
  assert!(closed.clean());
  server_task.await.unwrap();
}

#[compio::test]
async fn keepalive_pings_flow_while_idle() {
  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let copts = crate::options::ClientOptions::default()
    .with_keepalive(Some(std::time::Duration::from_millis(50)));
  let mut client = WebSocket::client(c, &negotiated, &copts, Vec::new());
  let mut server = WebSocket::server(
    s,
    &negotiated,
    &crate::options::AcceptOptions::default(),
    Vec::new(),
  );
  // Both pumps idle: the client keepalive must emit pings, the server
  // auto-pongs, and no data message surfaces — so the experiment times out.
  let outcome = compio::time::timeout(std::time::Duration::from_millis(400), async {
    futures_util::select_biased! {
      m = client.next().fuse() => m,
      m = server.next().fuse() => m,
    }
  })
  .await;
  assert!(outcome.is_err(), "no data message may surface");
  assert!(server.pings_seen() >= 1, "server saw the keepalive ping(s)");
}

#[compio::test]
async fn close_deadline_fires_without_peer_echo() {
  let (c, _held_open) = duplex(); // the peer never answers
  let negotiated = Negotiated::none();
  let copts = crate::options::ClientOptions::default()
    .with_close_timeout(std::time::Duration::from_millis(80));
  let client = WebSocket::client(c, &negotiated, &copts, Vec::new());
  let closed = client.close(CloseCode::Normal, "").await.unwrap();
  assert!(!closed.clean(), "deadline close is unclean");
}

#[compio::test]
async fn split_writer_sends_while_reader_pumps() {
  let (mut client, server) = pair();
  let (mut sread, mut swrite) = server.split();
  let writer = compio_runtime::spawn(async move {
    for i in 0..10u32 {
      swrite.send_text(&format!("msg-{i}")).await.unwrap();
    }
    swrite
  });
  let reader = compio_runtime::spawn(async move {
    while let Some(result) = sread.next().await {
      result.unwrap();
    }
  });
  for i in 0..10u32 {
    let m = client.next().await.unwrap().unwrap();
    assert_eq!(m, Message::Text(format!("msg-{i}").into()));
  }
  drop(writer.await);
  drop(client); // EOF wakes the reader task's parked read
  let _ = reader.await;
}

#[compio::test]
async fn dropping_read_half_wakes_writers() {
  let (_client, server) = pair();
  let (sread, mut swrite) = server.split();
  drop(sread);
  let err = swrite.send_text("nope").await.unwrap_err();
  assert!(matches!(err, Error::ReadHalfGone));
}

#[compio::test]
async fn write_half_close_drives_through_reader() {
  let (mut client, server) = pair();
  let (mut sread, mut swrite) = server.split();
  let reader = compio_runtime::spawn(async move {
    while sread.next().await.is_some() {}
    sread
  });
  swrite.close(CloseCode::Normal, "done").await.unwrap();
  // The client observes the close handshake cleanly.
  assert!(client.next().await.is_none());
  let closed = client.closed().unwrap();
  assert_eq!(closed.code(), CloseCode::Normal);
  let sread = reader.await.unwrap();
  assert!(sread.closed().unwrap().clean());
}
