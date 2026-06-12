//! A minimal echo server: `cargo run -p wren-compio --example echo-server`.

use wren_compio::{AcceptOptions, accept};

#[compio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let listener = compio_net::TcpListener::bind("127.0.0.1:9001").await?;
  println!("listening on ws://127.0.0.1:9001");
  loop {
    let (stream, peer) = listener.accept().await?;
    compio_runtime::spawn(async move {
      let Ok((mut ws, summary)) = accept(stream, AcceptOptions::new()).await else {
        return;
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
    })
    .detach();
  }
}
