use super::*;
use crate::{IntoDuplex, duplex::duplex};

#[compio::test]
async fn client_and_server_handshake_over_duplex() {
  let (client_stream, server_stream) = duplex();
  let opts = ClientOptions::default().with_subprotocols(["chat"]);
  let client = compio_runtime::spawn(async move {
    let (_stream, outcome) =
      drive_client(client_stream.into_duplex(), "example.com", "/chat", &opts)
        .await
        .unwrap();
    outcome
  });
  let acc = AcceptOptions::default().with_supported_subprotocols(["chat"]);
  let mut stream = server_stream.into_duplex();
  let (head, summary) = drive_server_request(&mut stream).await.unwrap();
  assert_eq!(summary.path(), "/chat");
  assert_eq!(summary.host(), "example.com");
  let (_stream, server) = finish_accept(stream, head, summary, &acc).await.unwrap();
  let client = client.await.unwrap();
  assert_eq!(client.negotiated.subprotocol(), Some("chat"));
  assert_eq!(server.negotiated.subprotocol(), Some("chat"));
  assert_eq!(server.summary.path(), "/chat");
  assert!(client.leftover.is_empty());
  assert!(server.leftover.is_empty());
}

#[compio::test]
async fn pending_accept_can_reject_before_the_upgrade() {
  let (client_stream, server_stream) = duplex();
  let client = compio_runtime::spawn(async move {
    crate::client(
      client_stream,
      "intruder.example",
      "/admin",
      ClientOptions::default(),
    )
    .await
    .map(|_| ())
  });
  let pending = crate::accept_pending(server_stream, AcceptOptions::default())
    .await
    .unwrap();
  // The caller inspects the request BEFORE anything is written…
  assert_eq!(pending.request().path(), "/admin");
  assert_eq!(pending.request().host(), "intruder.example");
  // …and turns it away without establishing the connection.
  pending.reject(403, "Forbidden").await.unwrap();
  let err = client.await.unwrap().unwrap_err();
  assert!(matches!(err, ConnectError::Rejected { status: 403 }));
}

#[compio::test]
async fn pending_accept_accepts_after_inspection() {
  let (client_stream, server_stream) = duplex();
  let client = compio_runtime::spawn(async move {
    crate::client(
      client_stream,
      "example.com",
      "/ok",
      ClientOptions::default(),
    )
    .await
    .unwrap()
  });
  let pending = crate::accept_pending(server_stream, AcceptOptions::default())
    .await
    .unwrap();
  assert_eq!(pending.request().path(), "/ok");
  let (mut ws, summary) = pending.accept().await.unwrap();
  assert_eq!(summary.path(), "/ok");
  let (mut cws, _resp) = client.await.unwrap();
  cws.send_text("hi").await.unwrap();
  let m = ws.next().await.unwrap().unwrap();
  assert_eq!(m, crate::Message::Text("hi".into()));
}

#[compio::test]
async fn rejected_status_surfaces_as_rejected() {
  let (client_stream, server_stream) = duplex();
  let opts = ClientOptions::default();
  let client = compio_runtime::spawn(async move {
    drive_client(client_stream.into_duplex(), "example.com", "/", &opts)
      .await
      .map(|_| ())
  });
  // Swallow the request (any prefix will do), answer with a 403.
  use futures_util::{AsyncReadExt as _, AsyncWriteExt as _};
  let mut server_stream = server_stream.into_duplex();
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
