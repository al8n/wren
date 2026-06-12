use super::*;
use crate::{
  IntoDuplex,
  duplex::{Pipe, duplex, duplex_with_capacity},
};

type PipeDuplex = <Pipe as IntoDuplex>::Duplex;

fn pair() -> (
  WebSocket<ClientRole, PipeDuplex>,
  WebSocket<ServerRole, PipeDuplex>,
) {
  pair_with(
    crate::options::ClientOptions::default(),
    crate::options::AcceptOptions::default(),
  )
}

fn pair_with(
  copts: crate::options::ClientOptions,
  sopts: crate::options::AcceptOptions,
) -> (
  WebSocket<ClientRole, PipeDuplex>,
  WebSocket<ServerRole, PipeDuplex>,
) {
  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  (
    WebSocket::client(c.into_duplex(), &negotiated, &copts, Vec::new()),
    WebSocket::server(s.into_duplex(), &negotiated, &sopts, Vec::new()),
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
  let mut client = WebSocket::client(c.into_duplex(), &negotiated, &copts, Vec::new());
  let mut server = WebSocket::server(
    s.into_duplex(),
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
  let client = WebSocket::client(c.into_duplex(), &negotiated, &copts, Vec::new());
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
    sread
  });
  for i in 0..10u32 {
    let m = client.next().await.unwrap().unwrap();
    assert_eq!(m, Message::Text(format!("msg-{i}").into()));
  }
  drop(writer.await);
  // A clean close lets the reader loop run to `None` without errors; the
  // join surfaces any panic the loop hit on the way.
  let closed = client.close(CloseCode::Normal, "done").await.unwrap();
  assert!(closed.clean());
  let sread = reader.await.unwrap();
  assert!(sread.closed().unwrap().clean());
}

#[compio::test]
async fn cancelled_send_flushes_before_close() {
  use std::future::Future;

  let (mut client, server) = pair();
  let (mut sread, mut swrite) = server.split();
  let reader = compio_runtime::spawn(async move {
    while let Some(result) = sread.next().await {
      result.unwrap();
    }
    sread
  });
  // Cancel a send after its first poll: the frame is already enqueued but
  // no task awaits it any more.
  {
    let mut fut = Box::pin(swrite.send_text("zombie"));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  swrite.close(CloseCode::Normal, "done").await.unwrap();
  // The orphaned frame still precedes the Close on the wire (RFC 6455
  // §5.5.1: no data frames after the Close).
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("zombie".into()));
  assert!(client.next().await.is_none());
  assert!(client.closed().unwrap().clean());
  let sread = reader.await.unwrap();
  assert!(sread.closed().unwrap().clean());
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
async fn cancelled_next_preserves_the_connection() {
  use std::future::Future;

  let (mut client, mut server) = pair();
  // Park the server pump on its read, then cancel it mid-await.
  {
    let mut fut = Box::pin(server.next());
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  // The connection must still work: the stream went back into the
  // connection when the future dropped, and nothing was lost.
  client.send_text("after cancel").await.unwrap();
  let m = server.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("after cancel".into()));
  // And the reverse direction too.
  server.send_text("echo").await.unwrap();
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("echo".into()));
}

#[compio::test]
async fn cancelled_send_resumes_without_corruption() {
  use std::future::Future;

  // A 4 KiB pipe + a 64 KiB frame: the send must park on backpressure
  // with the frame partially on the wire.
  let (c, s) = duplex_with_capacity(4 * 1024);
  let negotiated = Negotiated::none();
  let mut client = WebSocket::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default(),
    Vec::new(),
  );
  let mut server = WebSocket::server(
    s.into_duplex(),
    &negotiated,
    &crate::options::AcceptOptions::default(),
    Vec::new(),
  );

  let payload = vec![0xCD_u8; 64 * 1024];
  {
    // Poll the send until it parks (adapter buffer + pipe both full),
    // then cancel it. The write cursor must survive in the connection.
    let mut fut = Box::pin(client.send_binary(&payload));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  // A fresh send resumes the cancelled frame first, then sends its own:
  // the peer must see BOTH messages intact, in order — no spliced bytes,
  // no duplicated chunk from a cursor reset.
  let expect = payload.clone();
  let server_task = compio_runtime::spawn(async move {
    let first = server.next().await.unwrap().unwrap();
    assert_eq!(first, Message::Binary(expect.into()));
    let second = server.next().await.unwrap().unwrap();
    assert_eq!(second, Message::Text("tail".into()));
    server
  });
  client.send_text("tail").await.unwrap();
  // Propagates any assertion panic from the server task.
  drop(server_task.await.unwrap());
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
