//! ws:// integration over real TCP loopbacks, exercised on both runtimes.

use agnostic_net::{Net, TcpListener as _};
use wren_reactor::{AcceptOptions, ClientOptions, CloseCode, Message, accept, connect};

async fn echo_suite<N: Net>() {
  let listener = <N as Net>::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = listener.local_addr().unwrap().port();

  let server = async {
    let (tcp, _peer) = listener.accept().await.unwrap();
    let opts = AcceptOptions::new().with_supported_subprotocols(["echo.v1"]);
    let (mut ws, summary) = accept::<N::Runtime, _>(tcp, opts).await.unwrap();
    assert_eq!(summary.path(), "/chat");
    assert_eq!(summary.query(), Some("room=1"));
    while let Some(msg) = ws.next().await {
      let m = msg.unwrap();
      ws.send(m).await.unwrap();
    }
    assert!(ws.closed().unwrap().clean());
  };

  let client = async {
    let url = format!("ws://127.0.0.1:{port}/chat?room=1");
    let opts = ClientOptions::new().with_subprotocols(["echo.v1"]);
    let (mut ws, resp) = connect::<N>(&url, opts).await.unwrap();
    assert_eq!(resp.subprotocol(), Some("echo.v1"));
    ws.send_text("hello").await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::Text("hello".into()));
    ws.send_binary(&[1, 2, 3]).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::Binary(vec![1, 2, 3].into()));
    let closed = ws.close(CloseCode::Normal, "bye").await.unwrap();
    assert!(closed.clean());
  };

  futures_util::join!(server, client);
}

#[tokio::test]
async fn ws_loopback_tokio() {
  echo_suite::<agnostic_net::tokio::Net>().await;
}

#[test]
fn ws_loopback_smol() {
  smol::block_on(echo_suite::<agnostic_net::smol::Net>());
}

#[cfg(feature = "deflate")]
#[tokio::test]
async fn deflate_round_trip() {
  use wren_reactor::proto::negotiation::{DeflateOffer, ServerDeflateConfig};
  type N = agnostic_net::tokio::Net;

  let listener = <N as Net>::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = listener.local_addr().unwrap().port();
  let text = "wren ".repeat(13_000); // ~65 KiB, compressible
  let expect = text.clone();

  let server = async {
    let (tcp, _) = listener.accept().await.unwrap();
    let opts = AcceptOptions::new().with_deflate(ServerDeflateConfig::new());
    let (mut ws, _) = accept::<<N as Net>::Runtime, _>(tcp, opts).await.unwrap();
    while let Some(msg) = ws.next().await {
      let m = msg.unwrap();
      ws.send(m).await.unwrap();
    }
  };
  let client = async {
    let url = format!("ws://127.0.0.1:{port}/");
    let (mut ws, resp) = connect::<N>(&url, ClientOptions::new().with_deflate(DeflateOffer::new()))
      .await
      .unwrap();
    assert!(resp.deflate().is_some(), "deflate negotiated");
    ws.send_text_compressed(&text).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::Text(expect.into()));
    assert!(ws.close(CloseCode::Normal, "").await.unwrap().clean());
  };
  futures_util::join!(server, client);
}
