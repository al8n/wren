use super::*;
use crate::duplex::duplex;

// The high-level `pending_accept` reject/accept round-trips live in
// tests/loopback.rs once `client`/`accept_pending` exist (the driver layer
// itself is covered here).

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
