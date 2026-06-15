//! A minimal echo server: `cargo run -p wren-reactor --example echo-server`.

use agnostic_net::{Net, TcpListener as _};
use wren_reactor::{AcceptOptions, tokio::accept};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  type N = agnostic_net::tokio::Net;
  let listener = <N as Net>::TcpListener::bind("127.0.0.1:9001").await?;
  println!("listening on ws://127.0.0.1:9001");
  loop {
    let (stream, peer) = listener.accept().await?;
    tokio::spawn(async move {
      let (mut ws, summary) = match accept(stream, AcceptOptions::new()).await {
        Ok(v) => v,
        Err(e) => {
          eprintln!("{peer} handshake failed: {e}");
          return;
        }
      };
      println!("{peer} connected on {}", summary.path());
      while let Some(result) = ws.next().await {
        let message = match result {
          Ok(message) => message,
          Err(e) => {
            eprintln!("{peer} errored: {e}");
            return;
          }
        };
        if ws.send(message).await.is_err() {
          break;
        }
      }
      println!("{peer} closed: {:?}", ws.closed());
    });
  }
}
