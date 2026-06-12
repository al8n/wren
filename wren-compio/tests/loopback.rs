//! ws:// integration over a real compio TCP loopback.

use wren_compio::{AcceptOptions, ClientOptions, CloseCode, Message, accept, connect};

#[compio::test]
async fn ws_loopback_echo() {
  let listener = compio_net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let server = compio_runtime::spawn(async move {
    let (stream, _peer) = listener.accept().await.unwrap();
    let (mut ws, summary) = accept(
      stream,
      AcceptOptions::new().with_supported_subprotocols(["echo.v1"]),
    )
    .await
    .unwrap();
    assert_eq!(summary.path(), "/echo");
    assert_eq!(summary.query(), Some("room=1"));
    while let Some(msg) = ws.next().await {
      let msg = msg.unwrap();
      ws.send(msg).await.unwrap();
    }
    assert!(ws.closed().unwrap().clean());
  });

  let url = format!("ws://{addr}/echo?room=1");
  let (mut ws, resp) = connect(
    &url,
    ClientOptions::new().with_subprotocols(["echo.v1", "echo.v0"]),
  )
  .await
  .unwrap();
  assert_eq!(resp.subprotocol(), Some("echo.v1"));

  ws.send_text("ping").await.unwrap();
  let m = ws.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("ping".into()));

  ws.send_binary(&[1, 2, 3]).await.unwrap();
  let m = ws.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Binary(vec![1, 2, 3].into()));

  let closed = ws.close(CloseCode::Normal, "done").await.unwrap();
  assert!(closed.clean());
  server.await.unwrap();
}

#[cfg(feature = "deflate")]
#[compio::test]
async fn deflate_negotiates_and_round_trips() {
  use websocket_proto::negotiation::{DeflateOffer, ServerDeflateConfig};

  let listener = compio_net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let server = compio_runtime::spawn(async move {
    let (stream, _peer) = listener.accept().await.unwrap();
    let (mut ws, _summary) = accept(
      stream,
      AcceptOptions::new().with_deflate(ServerDeflateConfig::new()),
    )
    .await
    .unwrap();
    while let Some(msg) = ws.next().await {
      let msg = msg.unwrap();
      ws.send(msg).await.unwrap();
    }
  });

  let url = format!("ws://{addr}/");
  let (mut ws, resp) = connect(&url, ClientOptions::new().with_deflate(DeflateOffer::new()))
    .await
    .unwrap();
  assert!(resp.deflate().is_some(), "deflate negotiated");

  // Compressible payload, sent compressed; the echo comes back through the
  // pump's transparent inflate.
  let text = "wren ".repeat(13_000); // ~65 KiB
  ws.send_text_compressed(&text).await.unwrap();
  let m = ws.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text(text.into()));

  let closed = ws.close(CloseCode::Normal, "").await.unwrap();
  assert!(closed.clean());
  server.await.unwrap();
}
