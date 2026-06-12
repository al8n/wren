//! wss:// integration over a real compio TCP loopback with rcgen certs.

#![cfg(feature = "tls")]

use std::sync::Arc;

use wren_compio::{AcceptOptions, ClientOptions, CloseCode, Message, accept, connect};

#[compio::test]
async fn wss_loopback_echo() {
  // Self-signed cert for localhost; the client trusts exactly this cert.
  let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
  let cert_der = certified.cert.der().clone();
  let key_der =
    rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();

  let server_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der.clone()], key_der)
    .unwrap();
  let acceptor = compio_tls::TlsAcceptor::from(Arc::new(server_config));

  let mut roots = rustls::RootCertStore::empty();
  roots.add(cert_der).unwrap();
  let client_config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  let connector = compio_tls::TlsConnector::from(Arc::new(client_config));

  let listener = compio_net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = listener.local_addr().unwrap().port();

  let server = compio_runtime::spawn(async move {
    let (tcp, _peer) = listener.accept().await.unwrap();
    let tls = acceptor.accept(tcp).await.unwrap();
    let (mut ws, summary) = accept(tls, AcceptOptions::new()).await.unwrap();
    assert_eq!(summary.path(), "/secure");
    while let Some(msg) = ws.next().await {
      let msg = msg.unwrap();
      ws.send(msg).await.unwrap();
    }
    assert!(ws.closed().unwrap().clean());
  });

  let url = format!("wss://localhost:{port}/secure");
  let (mut ws, _resp) = compio::time::timeout(
    std::time::Duration::from_secs(10),
    connect(&url, ClientOptions::new().with_tls_connector(connector)),
  )
  .await
  .expect("connect timed out")
  .unwrap();

  ws.send_text("over tls").await.unwrap();
  let m = ws.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("over tls".into()));

  let closed = ws.close(CloseCode::Normal, "bye").await.unwrap();
  assert!(closed.clean());
  server.await.unwrap();
}
