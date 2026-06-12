//! Autobahn TestSuite **server** harness for `websocket-proto`.
//!
//! A minimal blocking, single-threaded `echo` server built directly on the
//! Sans-I/O core: it performs the RFC 6455 opening handshake (granting
//! permessage-deflate when offered), drives a [`Connection`] per accepted
//! socket, and echoes every data message back — text as text, binary as
//! binary, and compressed when the inbound message arrived compressed (so the
//! suite's §12/§13 compression cases exercise the deflate-on-send path too).
//!
//! This binary is a conformance fixture, not production code: it is
//! single-threaded, reads with blocking I/O, and `unwrap`s I/O and protocol
//! results (examples are exempt from the crate's panic-freedom wall).
//!
//! # Running the suite locally
//!
//! Terminal 1 — start this server:
//!
//! ```sh
//! cargo run -p websocket-proto --example autobahn-server \
//!   --features std,deflate --release
//! ```
//!
//! Terminal 2 — point the dockerized fuzzing **client** at it. With a
//! `fuzzingclient.json` spec naming the server URL (Linux: `--network host`
//! and `ws://127.0.0.1:9001`):
//!
//! ```sh
//! docker run -it --rm --network host \
//!   -v "$PWD/autobahn:/config" \
//!   -v "$PWD/autobahn/reports:/reports" \
//!   crossbario/autobahn-testsuite \
//!   wstest -m fuzzingclient -s /config/fuzzingclient.json
//! ```
//!
//! Reports land in `autobahn/reports/servers/index.json`; every case must end
//! with `behavior` in `OK`/`NON-STRICT`/`INFORMATIONAL`/`UNIMPLEMENTED` (never
//! `FAILED`). The CI workflow `.github/workflows/autobahn.yml` automates this.

use std::{
  io::{Read, Write},
  net::{TcpListener, TcpStream},
  time::Instant as StdInstant,
};

use websocket_proto::{
  Message, MessageAssembler, Negotiated,
  connection::{Connection, ConnectionConfig, Event, role::Server},
  handshake::h1::{Accept, ServerHandshake, ServerProgress},
  negotiation::{ServerDeflateConfig, accept_deflate_offer},
};

/// Where Autobahn's `fuzzingclient` expects the echo server.
const ADDR: &str = "127.0.0.1:9001";

/// Generous message cap for the suite (it sends multi-MiB frames in §9.*).
const MAX_MESSAGE: usize = 256 * 1024 * 1024;

fn main() {
  let listener = TcpListener::bind(ADDR).expect("bind 127.0.0.1:9001");
  eprintln!("autobahn-server listening on ws://{ADDR}");
  for stream in listener.incoming() {
    match stream {
      // One connection at a time keeps the fixture trivial and matches the
      // suite's sequential case execution.
      Ok(stream) => {
        if let Err(e) = serve(stream) {
          eprintln!("connection ended: {e}");
        }
      }
      Err(e) => eprintln!("accept error: {e}"),
    }
  }
}

/// Drives one client: handshake, then the echo loop until the connection
/// terminates.
fn serve(mut stream: TcpStream) -> std::io::Result<()> {
  stream.set_nodelay(true).ok();

  let (negotiated, leftover) = match handshake(&mut stream)? {
    Some(parts) => parts,
    None => return Ok(()), // rejected or aborted mid-handshake
  };

  let mut conn: Connection<StdInstant, Server> = Connection::new(
    &negotiated,
    ConnectionConfig::new()
      .with_max_message_size(MAX_MESSAGE as u64)
      .with_max_frame_payload(MAX_MESSAGE as u64),
    Server::new(),
    StdInstant::now(),
  );

  echo_loop(&mut stream, &mut conn, leftover)
}

/// Performs the server handshake: reads the request, grants deflate when
/// offered, writes the 101 response. Returns `(negotiated, leftover)` where
/// `leftover` is any frame-stream bytes that arrived glued to the request, or
/// `None` if the handshake could not complete.
fn handshake(stream: &mut TcpStream) -> std::io::Result<Option<(Negotiated, Vec<u8>)>> {
  let server = ServerHandshake::new();
  let mut buf = Vec::new();
  let mut chunk = [0u8; 4096];

  loop {
    let n = stream.read(&mut chunk)?;
    if n == 0 {
      return Ok(None); // peer hung up before sending a full request
    }
    buf.extend_from_slice(&chunk[..n]);

    // Re-parse the whole accumulated buffer (the handshake is stateless).
    let mut out = vec![0u8; 1024];
    match server.handle(&buf) {
      Ok(ServerProgress::NeedMore) => continue,
      Ok(ServerProgress::Request(view)) => {
        // Grant permessage-deflate when the client offers it.
        let granted = accept_deflate_offer(view.extensions(), &ServerDeflateConfig::new());
        let accept = Accept::new().with_deflate(granted.map(|(_, resp)| resp));
        let (written, negotiated) = server
          .encode_response(&view, &accept, &mut out)
          .expect("encode 101 response");
        let consumed = view.consumed();
        stream.write_all(&out[..written])?;
        // Bytes past the request head are the start of the frame stream.
        let leftover = buf.split_off(consumed);
        return Ok(Some((negotiated, leftover)));
      }
      Err(e) => {
        eprintln!("handshake rejected: {e}");
        return Ok(None);
      }
      // `ServerProgress` is non-exhaustive; treat any future variant as
      // "need more input".
      Ok(_) => continue,
    }
  }
}

/// The blocking read → handle → assemble → echo → drain loop.
fn echo_loop(
  stream: &mut TcpStream,
  conn: &mut Connection<StdInstant, Server>,
  leftover: Vec<u8>,
) -> std::io::Result<()> {
  let mut asm = MessageAssembler::new(MAX_MESSAGE);
  let mut read_buf = [0u8; 64 * 1024];
  let mut out = vec![0u8; 1024];

  // Consume any frame bytes that arrived glued to the handshake first (rare:
  // Autobahn waits for the 101 before sending frames).
  if !leftover.is_empty() && !step(conn, &mut asm, leftover, stream, &mut out)? {
    return Ok(());
  }

  loop {
    let n = stream.read(&mut read_buf)?;
    if n == 0 {
      return Ok(()); // peer closed the socket
    }
    if !step(conn, &mut asm, read_buf[..n].to_vec(), stream, &mut out)? {
      return Ok(());
    }
  }
}

/// Feeds one chunk of inbound bytes, echoes any completed messages, and drains
/// protocol-generated frames. Returns `false` once the connection is terminal.
fn step(
  conn: &mut Connection<StdInstant, Server>,
  asm: &mut MessageAssembler,
  mut bytes: Vec<u8>,
  stream: &mut TcpStream,
  out: &mut Vec<u8>,
) -> std::io::Result<bool> {
  // Collect echoes as (message, was_compressed) so we can re-borrow the
  // connection mutably to encode after the events cursor is dropped.
  let mut echoes: Vec<(Message, bool)> = Vec::new();
  let mut compressed_in = false;

  {
    let mut events = match conn.handle(StdInstant::now(), &mut bytes) {
      Ok(ev) => ev,
      Err(_) => return Ok(false), // terminal
    };
    while let Some(ev) = events.next() {
      if let Event::MessageStart(s) = &ev {
        compressed_in = s.compressed();
      }
      if let Some(msg) = asm.push(&ev).expect("assemble") {
        echoes.push((msg, compressed_in));
      }
    }
  }

  // Drain protocol-generated frames first so a pong echo precedes the data
  // echo (Autobahn §5.6/§5.19/§5.20 expect the pong before the message). If a
  // Close arrived in this batch it drains here too (close-first priority),
  // after which the data echoes below are harmlessly dropped (`Closing`).
  drain_transmit(conn, stream, out)?;

  // Echo the completed data messages back.
  for (msg, was_compressed) in echoes {
    encode_echo(conn, &msg, was_compressed, stream, out)?;
  }

  // A close that was queued *after* the data (rare) still needs draining.
  drain_transmit(conn, stream, out)?;

  Ok(!conn.is_terminal())
}

/// Echoes one message, preferring compression when the inbound message was
/// compressed (falls back to plain when compression is unavailable). A data
/// send that races a close is silently dropped (the connection is shutting
/// down — the protocol close echo still drains).
fn encode_echo(
  conn: &mut Connection<StdInstant, Server>,
  msg: &Message,
  was_compressed: bool,
  stream: &mut TcpStream,
  out: &mut Vec<u8>,
) -> std::io::Result<()> {
  use websocket_proto::connection::EncodeError;

  // Compressed output can exceed the input on tiny/incompressible data; size
  // the scratch generously.
  let needed = msg.len().saturating_mul(2).saturating_add(64);
  if out.len() < needed {
    out.resize(needed, 0);
  }

  let result = match (msg, was_compressed) {
    (Message::Text(s), true) => conn
      .encode_text_compressed(s, out)
      .or_else(|_| conn.encode_text(s, out)),
    (Message::Text(s), false) => conn.encode_text(s, out),
    (Message::Binary(b), true) => conn
      .encode_binary_compressed(b, out)
      .or_else(|_| conn.encode_binary(b, out)),
    (Message::Binary(b), false) => conn.encode_binary(b, out),
  };
  match result {
    Ok(n) => stream.write_all(&out[..n]),
    // The connection started closing before we could echo — drop the reply.
    Err(EncodeError::Closing) => Ok(()),
    Err(e) => panic!("encode echo frame: {e}"),
  }
}

/// Drains every queued protocol frame into the socket. Protocol frames
/// (pong/close echoes, keepalive pings) are tiny, so the shared scratch buffer
/// always fits one.
fn drain_transmit(
  conn: &mut Connection<StdInstant, Server>,
  stream: &mut TcpStream,
  out: &mut [u8],
) -> std::io::Result<()> {
  loop {
    match conn
      .poll_transmit(StdInstant::now(), out)
      .expect("poll_transmit")
    {
      Some(n) => stream.write_all(&out[..n])?,
      None => return Ok(()),
    }
  }
}
