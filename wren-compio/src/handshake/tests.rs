use super::*;
use crate::duplex::duplex;

#[compio::test]
async fn client_and_server_handshake_over_duplex() {
  let (client_stream, server_stream) = duplex();
  let opts = ClientOptions::default().with_subprotocols(["chat"]);
  let client = compio_runtime::spawn(async move {
    let (_stream, outcome) = drive_client(client_stream, "example.com", "/chat", &opts)
      .await
      .unwrap();
    outcome
  });
  let acc = AcceptOptions::default().with_supported_subprotocols(["chat"]);
  let (_stream, server) = drive_server(server_stream, &acc).await.unwrap();
  let client = client.await.unwrap();
  assert_eq!(client.negotiated.subprotocol(), Some("chat"));
  assert_eq!(server.negotiated.subprotocol(), Some("chat"));
  assert_eq!(server.summary.path(), "/chat");
  assert_eq!(server.summary.host(), "example.com");
  assert!(client.leftover.is_empty());
  assert!(server.leftover.is_empty());
}

#[compio::test]
async fn rejected_status_surfaces_as_rejected() {
  let (client_stream, mut server_stream) = duplex();
  let opts = ClientOptions::default();
  let client = compio_runtime::spawn(async move {
    drive_client(client_stream, "example.com", "/", &opts)
      .await
      .map(|_| ())
  });
  // Swallow the request, answer with a 403.
  use compio_io::AsyncWriteExt as _;
  let BufResult(res, _buf) = server_stream.read(Vec::with_capacity(4096)).await;
  res.unwrap();
  server_stream
    .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n".to_vec())
    .await
    .0
    .unwrap();
  let err = client.await.unwrap().unwrap_err();
  assert!(matches!(err, ConnectError::Rejected { status: 403 }));
}
