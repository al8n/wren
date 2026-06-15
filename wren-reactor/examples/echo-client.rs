//! A minimal echo client: `cargo run -p wren-reactor --example echo-client`.

use wren_reactor::{ClientOptions, CloseCode, Message, tokio::connect};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let (mut ws, _resp) = connect("ws://127.0.0.1:9001/", ClientOptions::new()).await?;
  ws.send_text("hello from wren-reactor").await?;
  if let Some(Ok(Message::Text(text))) = ws.next().await {
    println!("echo: {text}");
  }
  ws.close(CloseCode::Normal, "done").await?;
  Ok(())
}
