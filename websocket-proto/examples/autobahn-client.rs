//! Autobahn TestSuite **client** harness for `websocket-proto`.
//!
//! The mirror of `autobahn-server`: it connects (as a WebSocket *client*) to a
//! running Autobahn `fuzzingserver`, asks how many cases there are, runs each
//! one through the same echo loop, then asks the server to write its reports.
//!
//! The driver protocol is the suite's own convention:
//!
//! - `GET /getCaseCount` — one text message carrying the case count;
//! - `GET /runCase?case=N&agent=websocket-proto` — the server drives case `N`,
//!   we echo every message back until it closes;
//! - `GET /updateReports?agent=websocket-proto` — flush the report files.
//!
//! This binary is a conformance fixture, not production code: it is
//! single-threaded, reads with blocking I/O, and `unwrap`s I/O and protocol
//! results (examples are exempt from the crate's panic-freedom wall).
//!
//! # Running the suite locally
//!
//! Terminal 1 — start the dockerized fuzzing **server** (Linux: `--network
//! host`; otherwise publish 9001):
//!
//! ```sh
//! docker run -it --rm --network host \
//!   -v "$PWD/autobahn:/config" \
//!   -v "$PWD/autobahn/reports:/reports" \
//!   crossbario/autobahn-testsuite \
//!   wstest -m fuzzingserver -s /config/fuzzingserver.json
//! ```
//!
//! Terminal 2 — run this client against it:
//!
//! ```sh
//! cargo run -p websocket-proto --example autobahn-client \
//!   --features std,deflate --release
//! ```
//!
//! Reports land in `autobahn/reports/clients/index.json`; every case must end
//! with `behavior` in `OK`/`NON-STRICT`/`INFORMATIONAL`/`UNIMPLEMENTED` (never
//! `FAILED`). The CI workflow `.github/workflows/autobahn.yml` automates this.

use std::{
  io::{Read, Write},
  net::TcpStream,
  time::Instant as StdInstant,
};

use websocket_proto::{
  Message, MessageAssembler, Negotiated,
  connection::{Connection, ConnectionConfig, Event, role::Client},
  handshake::h1::{ClientHandshake, ClientOptions, ClientProgress},
  negotiation::DeflateOffer,
};

/// A tiny non-cryptographic RNG for masking keys, seeded from system entropy.
///
/// The `rand` crate is *not* in scope under the example's `std,deflate` feature
/// set (the crate's `rand` optional feature gates it), so this fixture supplies
/// its own `rand_core::Rng`. For a real client use a CSPRNG (RFC 6455 §10.3) —
/// for the conformance suite, unpredictability across frames is all that
/// matters and this xorshift64* seeded from `RandomState` + the clock suffices.
struct SeedRng {
  state: u64,
}

impl SeedRng {
  fn from_entropy() -> Self {
    use std::hash::{BuildHasher, Hasher};
    // `RandomState` is seeded by the OS at process start; mix in the clock so
    // successive connections within a run start from different states.
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(
      std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0),
    );
    let seed = h.finish();
    Self {
      // Avoid the all-zero state (xorshift's fixed point).
      state: seed | 1,
    }
  }

  fn next_u64(&mut self) -> u64 {
    // xorshift64*.
    let mut x = self.state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    self.state = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
  }
}

// `rand_core::Rng` has a blanket impl for any infallible `TryRng`, so we
// implement the fallible base trait and get `Rng` (which the `Client` role
// requires) for free.
impl rand_core::TryRng for SeedRng {
  type Error = core::convert::Infallible;

  fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
    Ok((self.next_u64() >> 32) as u32)
  }

  fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
    Ok(self.next_u64())
  }

  fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
    let mut chunks = dst.chunks_exact_mut(8);
    for chunk in &mut chunks {
      chunk.copy_from_slice(&self.next_u64().to_le_bytes());
    }
    let tail = chunks.into_remainder();
    if !tail.is_empty() {
      let bytes = self.next_u64().to_le_bytes();
      tail.copy_from_slice(&bytes[..tail.len()]);
    }
    Ok(())
  }
}

/// Where Autobahn's `fuzzingserver` listens.
const HOST: &str = "127.0.0.1";
const PORT: u16 = 9001;
const AGENT: &str = "websocket-proto";

/// Generous message cap for the suite (it sends multi-MiB frames in §9.*).
const MAX_MESSAGE: usize = 256 * 1024 * 1024;

fn main() {
  let count = get_case_count().expect("getCaseCount");
  eprintln!("autobahn-client: running {count} cases against ws://{HOST}:{PORT}");

  for case in 1..=count {
    let path = format!("/runCase?case={case}&agent={AGENT}");
    if let Err(e) = run_case(&path) {
      eprintln!("case {case} ended: {e}");
    }
  }

  if let Err(e) = update_reports() {
    eprintln!("updateReports failed: {e}");
  }
  eprintln!("autobahn-client: done");
}

/// Connects to `/getCaseCount` and parses the single text message it returns.
fn get_case_count() -> std::io::Result<u32> {
  let count = std::cell::Cell::new(0u32);
  run_path("/getCaseCount", |msg| {
    if let Message::Text(s) = msg {
      count.set(s.trim().parse().unwrap_or(0));
    }
    // Don't echo control/data; just observe.
    None
  })?;
  Ok(count.get())
}

/// Runs one case: echo every message the server sends until it closes.
fn run_case(path: &str) -> std::io::Result<()> {
  run_path(path, |msg| Some(msg.clone()))
}

/// Hits `/updateReports` (no messages expected; the server closes immediately).
fn update_reports() -> std::io::Result<()> {
  let path = format!("/updateReports?agent={AGENT}");
  run_path(&path, |_| None)
}

/// Opens one client connection to `path`, then runs the echo loop. `on_message`
/// decides what (if anything) to send back for each completed inbound message;
/// returning `Some(reply)` echoes it (preserving compression when the inbound
/// was compressed), `None` swallows it.
fn run_path(
  path: &str,
  mut on_message: impl FnMut(&Message) -> Option<Message>,
) -> std::io::Result<()> {
  let mut stream = TcpStream::connect((HOST, PORT))?;
  stream.set_nodelay(true).ok();

  let (negotiated, leftover) = client_handshake(&mut stream, path)?;

  let mut conn: Connection<StdInstant, Client<SeedRng>> = Connection::new(
    &negotiated,
    ConnectionConfig::new()
      .with_max_message_size(MAX_MESSAGE as u64)
      .with_max_frame_payload(MAX_MESSAGE as u64),
    Client::new(SeedRng::from_entropy()),
    StdInstant::now(),
  );

  echo_loop(&mut stream, &mut conn, leftover, &mut on_message)
}

/// Performs the client handshake against `path` and returns
/// `(negotiated, leftover)` (leftover = frame bytes glued to the 101 response).
fn client_handshake(stream: &mut TcpStream, path: &str) -> std::io::Result<(Negotiated, Vec<u8>)> {
  let host = format!("{HOST}:{PORT}");
  let options = ClientOptions::new(&host, path).with_deflate(DeflateOffer::new());
  let mut rng = SeedRng::from_entropy();
  let handshake = ClientHandshake::new(options, &mut rng).expect("valid client options");

  let mut out = vec![0u8; 1024];
  let n = handshake.encode_request(&mut out).expect("encode request");
  stream.write_all(&out[..n])?;

  let mut buf = Vec::new();
  let mut chunk = [0u8; 4096];
  loop {
    let n = stream.read(&mut chunk)?;
    if n == 0 {
      return Err(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "server closed during handshake",
      ));
    }
    buf.extend_from_slice(&chunk[..n]);
    match handshake.handle(&buf) {
      Ok(ClientProgress::NeedMore) => continue,
      Ok(ClientProgress::Complete(done)) => {
        let consumed = done.consumed();
        let leftover = buf.split_off(consumed);
        return Ok((done.into_negotiated(), leftover));
      }
      Err(e) => {
        return Err(std::io::Error::other(format!("handshake failed: {e}")));
      }
      // `ClientProgress` is non-exhaustive; treat any future variant as
      // "need more input".
      Ok(_) => continue,
    }
  }
}

/// The blocking read → handle → assemble → reply → drain loop.
fn echo_loop(
  stream: &mut TcpStream,
  conn: &mut Connection<StdInstant, Client<SeedRng>>,
  leftover: Vec<u8>,
  on_message: &mut impl FnMut(&Message) -> Option<Message>,
) -> std::io::Result<()> {
  let mut asm = MessageAssembler::new(MAX_MESSAGE);
  let mut read_buf = [0u8; 64 * 1024];
  let mut out = vec![0u8; 1024];

  if !leftover.is_empty() && !step(conn, &mut asm, leftover, stream, &mut out, on_message)? {
    return Ok(());
  }

  loop {
    let n = stream.read(&mut read_buf)?;
    if n == 0 {
      return Ok(());
    }
    if !step(
      conn,
      &mut asm,
      read_buf[..n].to_vec(),
      stream,
      &mut out,
      on_message,
    )? {
      return Ok(());
    }
  }
}

/// Feeds one chunk of inbound bytes, replies to any completed messages, and
/// drains protocol-generated frames. Returns `false` once terminal.
fn step(
  conn: &mut Connection<StdInstant, Client<SeedRng>>,
  asm: &mut MessageAssembler,
  mut bytes: Vec<u8>,
  stream: &mut TcpStream,
  out: &mut Vec<u8>,
  on_message: &mut impl FnMut(&Message) -> Option<Message>,
) -> std::io::Result<bool> {
  let mut replies: Vec<(Message, bool)> = Vec::new();
  let mut compressed_in = false;

  {
    let mut events = match conn.handle(StdInstant::now(), &mut bytes) {
      Ok(ev) => ev,
      Err(_) => return Ok(false),
    };
    while let Some(ev) = events.next() {
      if let Event::MessageStart(s) = &ev {
        compressed_in = s.compressed();
      }
      if let Some(msg) = asm.push(&ev).expect("assemble")
        && let Some(reply) = on_message(&msg)
      {
        replies.push((reply, compressed_in));
      }
    }
  }

  // Drain protocol-generated frames first so a pong precedes any data reply.
  drain_transmit(conn, stream, out)?;

  for (msg, was_compressed) in replies {
    encode_reply(conn, &msg, was_compressed, stream, out)?;
  }

  // A close queued after the reply (rare) still needs draining.
  drain_transmit(conn, stream, out)?;

  Ok(!conn.is_terminal())
}

/// Sends one reply, preferring compression when the inbound message was
/// compressed (falls back to plain when compression is unavailable). A data
/// send that races a close is silently dropped.
fn encode_reply(
  conn: &mut Connection<StdInstant, Client<SeedRng>>,
  msg: &Message,
  was_compressed: bool,
  stream: &mut TcpStream,
  out: &mut Vec<u8>,
) -> std::io::Result<()> {
  use websocket_proto::connection::EncodeError;

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
    // The connection started closing before we could reply — drop it.
    Err(EncodeError::Closing) => Ok(()),
    Err(e) => panic!("encode reply frame: {e}"),
  }
}

/// Drains every queued protocol frame into the socket. Protocol frames
/// (pong/close echoes, keepalive pings) are tiny, so the shared scratch buffer
/// always fits one.
fn drain_transmit(
  conn: &mut Connection<StdInstant, Client<SeedRng>>,
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
