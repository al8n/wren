//! A minimal echo client: `cargo run -p wren-compio --example echo-client`.

use wren_compio::{ClientOptions, CloseCode, connect};

#[compio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let (mut ws, _response) = connect("ws://127.0.0.1:9001/echo", ClientOptions::new()).await?;
  ws.send_text("hello from wren-compio").await?;
  if let Some(message) = ws.next().await {
    println!("echoed: {:?}", message?);
  }
  let closed = ws.close(CloseCode::Normal, "done").await?;
  println!("closed cleanly: {}", closed.clean());
  Ok(())
}
