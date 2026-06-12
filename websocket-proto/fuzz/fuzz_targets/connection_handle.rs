//! Fuzz: the Connection recv machine never panics on arbitrary bytes split
//! at arbitrary points, and terminal means terminal.
#![no_main]

use libfuzzer_sys::fuzz_target;
use websocket_proto::{
  Connection, ConnectionConfig,
  connection::{Event, role::Server},
  negotiation::Negotiated,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FuzzInstant(u64);

impl websocket_proto::time::Instant for FuzzInstant {
  fn checked_add_duration(self, dur: core::time::Duration) -> Option<Self> {
    u64::try_from(dur.as_micros())
      .ok()
      .and_then(|m| self.0.checked_add(m))
      .map(Self)
  }
  fn checked_duration_since(self, earlier: Self) -> Option<core::time::Duration> {
    self.0.checked_sub(earlier.0).map(core::time::Duration::from_micros)
  }
}

fn feed(
  conn: &mut Connection<FuzzInstant, Server>,
  piece: &[u8],
  terminal_seen: &mut bool,
) {
  let mut buf = piece.to_vec();
  match conn.handle(FuzzInstant(0), &mut buf) {
    Err(_) => assert!(*terminal_seen, "Terminal error before any Closed event"),
    Ok(mut events) => {
      while let Some(e) = events.next() {
        assert!(!*terminal_seen, "event after Closed");
        if let Event::Closed(_) = e {
          *terminal_seen = true;
        }
      }
    }
  }
}

fuzz_target!(|input: (Vec<u8>, Vec<u16>)| {
  let (data, cuts) = input;
  let mut points: Vec<usize> =
    cuts.iter().map(|&c| usize::from(c) % (data.len() + 1)).collect();
  points.sort_unstable();
  points.dedup();

  let mut conn: Connection<FuzzInstant, Server> = Connection::new(
    &Negotiated::none(),
    ConnectionConfig::default(),
    Server::new(),
    FuzzInstant(0),
  );

  let mut terminal_seen = false;
  let mut start = 0usize;
  for &p in &points {
    feed(&mut conn, &data[start..p], &mut terminal_seen);
    start = p;
  }
  feed(&mut conn, &data[start..], &mut terminal_seen);

  // Drain whatever the protocol queued; must never panic.
  let mut out = [0u8; 256];
  while let Ok(Some(_)) = conn.poll_transmit(FuzzInstant(0), &mut out) {}
});
