//! wss:// integration over real TCP loopbacks with rcgen certs, both runtimes.

#![cfg(feature = "tls")]

use std::sync::Arc;

use agnostic_net::{Net, TcpListener as _};
use futures_rustls::TlsAcceptor;
use wren_reactor::{AcceptOptions, ClientOptions, CloseCode, Message, accept, connect};

async fn wss_suite<N: Net>() {
  // Self-signed cert for localhost; the client trusts exactly this cert.
  let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
  let cert_der = certified.cert.der().clone();
  let key_der = rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();

  let server_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der.clone()], key_der)
    .unwrap();
  let acceptor = TlsAcceptor::from(Arc::new(server_config));

  let mut roots = rustls::RootCertStore::empty();
  roots.add(cert_der).unwrap();
  let client_config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  let connector = futures_rustls::TlsConnector::from(Arc::new(client_config));

  let listener = <N as Net>::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = listener.local_addr().unwrap().port();

  let server = async {
    let (tcp, _peer) = listener.accept().await.unwrap();
    let tls = acceptor.accept(tcp).await.unwrap();
    let (mut ws, summary) = accept::<<N as Net>::Runtime, _>(tls, AcceptOptions::new()).await.unwrap();
    assert_eq!(summary.path(), "/secure");
    while let Some(msg) = ws.next().await {
      let m = msg.unwrap();
      ws.send(m).await.unwrap();
    }
    assert!(ws.closed().unwrap().clean());
  };

  let client = async {
    let url = format!("wss://localhost:{port}/secure");
    let (mut ws, _resp) = connect::<N>(&url, ClientOptions::new().with_tls_connector(connector))
      .await
      .unwrap();
    ws.send_text("over tls").await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::Text("over tls".into()));
    assert!(ws.close(CloseCode::Normal, "bye").await.unwrap().clean());
  };

  futures_util::join!(server, client);
}

#[tokio::test]
async fn wss_loopback_tokio() {
  tokio::time::timeout(
    std::time::Duration::from_secs(20),
    wss_suite::<agnostic_net::tokio::Net>(),
  )
  .await
  .expect("wss loopback timed out");
}

#[test]
fn wss_loopback_smol() {
  smol::block_on(wss_suite::<agnostic_net::smol::Net>());
}
