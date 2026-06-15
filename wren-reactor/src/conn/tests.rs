use super::*;
use crate::duplex::{
  Pipe, duplex, duplex_with_capacity, duplex_with_eager_wake, duplex_with_failing_close,
  duplex_with_stalling_close, duplex_with_stalling_flush, duplex_with_wake_on_flush,
  duplex_with_write_fault,
};
use agnostic_lite::tokio::TokioRuntime;
use std::time::Duration;

/// A waker that counts how many times it was woken — for poll-level wakeup tests.
struct CountWaker(std::sync::atomic::AtomicUsize);
impl std::task::Wake for CountWaker {
  fn wake(self: std::sync::Arc<Self>) {
    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
  }
  fn wake_by_ref(self: &std::sync::Arc<Self>) {
    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
  }
}

fn client_over(pipe: Pipe) -> Client {
  WebSocket::client(
    pipe,
    &Negotiated::none(),
    &ClientOptions::default(),
    Vec::new(),
  )
}
fn server_over(pipe: Pipe) -> Server {
  WebSocket::server(
    pipe,
    &Negotiated::none(),
    &AcceptOptions::default(),
    Vec::new(),
  )
}

type Client = WebSocket<TokioRuntime, ClientRole, Pipe>;
type Server = WebSocket<TokioRuntime, ServerRole, Pipe>;

fn pair() -> (Client, Server) {
  let (c, s) = duplex();
  let n = Negotiated::none();
  (
    WebSocket::client(c, &n, &ClientOptions::default(), Vec::new()),
    WebSocket::server(s, &n, &AcceptOptions::default(), Vec::new()),
  )
}

/// Runs `server` as an echo loop on a task; returns its join handle.
fn spawn_echo(mut server: Server) -> tokio::task::JoinHandle<()> {
  tokio::spawn(async move {
    while let Some(Ok(msg)) = server.next().await {
      if server.send(msg).await.is_err() {
        break;
      }
    }
  })
}

#[tokio::test]
async fn text_and_binary_roundtrip() {
  let (mut client, server) = pair();
  let echo = spawn_echo(server);
  client.send_text("hello").await.unwrap();
  assert_eq!(
    client.next().await.unwrap().unwrap(),
    Message::Text("hello".into())
  );
  client.send_binary(&[1, 2, 3]).await.unwrap();
  assert_eq!(
    client.next().await.unwrap().unwrap(),
    Message::Binary(vec![1, 2, 3].into())
  );
  let closed = client.close(CloseCode::Normal, "bye").await.unwrap();
  assert!(closed.clean());
  let _ = echo.await;
}

#[tokio::test]
async fn split_full_duplex() {
  // The whole point of the split: read and write halves driven from two tasks at
  // once. The writer sends 16, waits until the reader has the echoes, THEN closes —
  // a realistic client reads responses before closing (a bulk-send-then-close would
  // race the peer's close-echo ahead of its data echoes, by design).
  let (client, server) = pair();
  let echo = spawn_echo(server);
  let (mut cread, mut cwrite) = client.split();
  let (done_tx, done_rx) = futures_channel::oneshot::channel::<()>();
  let writer = tokio::spawn(async move {
    for i in 0..16u8 {
      cwrite.send_binary(&[i]).await.unwrap();
    }
    let _ = done_rx.await; // the reader has the echoes; now close
    cwrite.close(CloseCode::Normal, "done").await.unwrap();
  });
  let mut got = 0u8;
  while got < 16 {
    match cread.next().await {
      Some(Ok(Message::Binary(b))) => {
        assert_eq!(b.as_ref(), &[got]);
        got += 1;
      }
      other => panic!("expected binary echo {got}, got {other:?}"),
    }
  }
  let _ = done_tx.send(()); // release the writer to close
  while cread.next().await.is_some() {} // drain to the close
  assert_eq!(got, 16);
  assert!(cread.closed().is_some());
  writer.await.unwrap();
  let _ = echo.await;
}

#[tokio::test]
async fn ping_is_auto_ponged_by_the_peer() {
  // The peer's read pump must auto-pong our ping while it is being polled.
  let (mut client, server) = pair();
  let echo = spawn_echo(server);
  client.ping(b"hi").await.unwrap();
  // Round-trip a data message to prove the connection stayed live through the ping.
  client.send_text("after-ping").await.unwrap();
  assert_eq!(
    client.next().await.unwrap().unwrap(),
    Message::Text("after-ping".into())
  );
  let _ = client.close(CloseCode::Normal, "").await;
  let _ = echo.await;
}

#[tokio::test]
async fn close_handshake_is_clean() {
  let (mut client, server) = pair();
  let echo = spawn_echo(server);
  let closed = client.close(CloseCode::Normal, "bye").await.unwrap();
  assert!(closed.clean());
  let _ = echo.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_message_backpressured() {
  // A large send to a bounded transport completes via backpressure as the peer drains
  // it (no autonomous write deadline — caller-bounded, here unbounded).
  let (mut client, server) = {
    let (c, s) = duplex_with_capacity(4096);
    (client_over(c), server_over(s))
  };
  let big = vec![0xABu8; 256 * 1024];
  let want = big.clone();
  let recv = tokio::spawn(async move {
    let mut server = server;
    server.next().await
  }); // drains as the client sends
  client.send_binary(&big).await.unwrap();
  let got = recv.await.unwrap().unwrap().unwrap();
  assert_eq!(got, Message::Binary(want.into()));
}

#[tokio::test]
async fn send_surfaces_write_error() {
  let mut client = client_over(duplex_with_write_fault(0).0); // first transport write faults
  let err = client.send_text("x").await.unwrap_err();
  assert!(
    matches!(err, Error::Io(_)),
    "write fault surfaces as Io (got {err:?})"
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_write_does_not_block_reads() {
  // The no-head-of-line property: a write whose flush is stalled does not block the
  // read half — the peer's message still arrives.
  let (c, s) = duplex_with_stalling_flush(); // the client's poll_flush stalls forever
  let client = client_over(c);
  let mut server = server_over(s);
  let (mut cread, mut cwrite) = client.split();
  let stuck = tokio::spawn(async move { cwrite.send_text("stuck").await }); // hangs in flush
  tokio::task::yield_now().await;
  server.send_text("hello").await.unwrap();
  let got = tokio::time::timeout(Duration::from_secs(5), cread.next())
    .await
    .expect("a read must not be blocked by the stalled write")
    .unwrap()
    .unwrap();
  assert_eq!(got, Message::Text("hello".into()));
  stuck.abort();
}

#[tokio::test]
async fn close_teardown_is_caller_bounded() {
  // The library imposes no close deadline: a transport whose shutdown (poll_close)
  // stalls makes close() hang until the CALLER's timeout fires, not the library's.
  let (c, s) = duplex_with_stalling_close(); // the client's poll_close never completes
  let mut client = client_over(c);
  let mut server = server_over(s);
  let srv = tokio::spawn(async move { while server.next().await.is_some() {} });
  let r = tokio::time::timeout(
    Duration::from_millis(200),
    client.close(CloseCode::Normal, ""),
  )
  .await;
  assert!(
    r.is_err(),
    "close teardown must be bounded by the caller, not hang"
  );
  srv.abort();
}

#[tokio::test]
async fn post_close_send_is_rejected() {
  let (mut client, server) = pair();
  let echo = spawn_echo(server);
  client.close(CloseCode::Normal, "").await.unwrap();
  let err = client.send_text("late").await.unwrap_err();
  assert!(
    matches!(err, Error::Closed),
    "a post-close send is Closed (got {err:?})"
  );
  let _ = echo.await;
}

#[tokio::test]
async fn awaited_send_before_close_is_delivered() {
  // Parity contract: await the send (or flush) before close to guarantee delivery.
  let (client, server) = pair();
  let (mut sread, _swrite) = server.split();
  let (mut cread, mut cwrite) = client.split();
  cwrite.send_binary(b"AWAITED").await.unwrap(); // awaited → flushed before close
  let got = sread.next().await.unwrap().unwrap();
  assert_eq!(got, Message::Binary(b"AWAITED".to_vec().into()));
  cwrite.close(CloseCode::Normal, "").await.unwrap();
  // Drain both halves so the handshake completes cleanly.
  while sread.next().await.is_some() {}
  while cread.next().await.is_some() {}
}

#[test]
fn reader_drain_wakes_parked_writer() {
  // No stolen wakeup (the recurring split class): a writer parked on a backpressured
  // flush is woken when the peer drains the transport — even though the read pump polls
  // the SAME write side in between. The fan-out reactor holds the transport's waker
  // slot (not a per-task waker), so it cannot be stolen; the read pump only registers
  // the reactor's READ slot, never clobbering the writer's WRITE slot.
  use futures_util::AsyncRead;
  use std::{
    pin::Pin,
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
  };

  let (c, s) = duplex_with_capacity(64); // tiny transport: one flush can't drain it
  let mut s = s;
  let mut inner = client_over(c).inner; // drive Inner directly
  // Stage a message far larger than the transport window.
  let payload = [0u8; 4096];
  inner
    .encode_into_buf(payload.len(), |conn, o| conn.encode_binary(&payload, o))
    .unwrap();

  // Writer parks on the full transport (registers its task in the reactor's write slot).
  let writer = Arc::new(CountWaker(AtomicUsize::new(0)));
  let ww = Waker::from(writer.clone());
  assert!(
    inner
      .poll_flush_writer(&mut Context::from_waker(&ww))
      .is_pending(),
    "the staged message exceeds the transport window, so the flush parks"
  );
  assert_eq!(writer.0.load(Ordering::SeqCst), 0, "not woken yet");

  // The read pump polls the same (still-full) write side. Under the old single-slot
  // design this stole the writer's wakeup; here it only registers the reactor's READ
  // slot, so the writer's WRITE registration survives.
  let reader = Waker::from(Arc::new(CountWaker(AtomicUsize::new(0))));
  assert!(matches!(
    inner.poll_next(&mut Context::from_waker(&reader)),
    Poll::Pending
  ));

  // The peer drains the transport: its readiness fans out through the reactor and wakes
  // the parked writer.
  let noop = futures_util::task::noop_waker();
  let mut buf = [0u8; 64];
  assert!(matches!(
    Pin::new(&mut s).poll_read(&mut Context::from_waker(&noop), &mut buf),
    Poll::Ready(Ok(_))
  ));
  assert!(
    writer.0.load(Ordering::SeqCst) >= 1,
    "the peer drain must wake the parked writer via the reactor (no stolen wakeup)"
  );
}

#[tokio::test]
async fn split_close_is_retryable_after_timeout() {
  // Finding 2: a `timeout(close())` cancelled AFTER the Close was queued must be
  // resumable — a later close resumes flushing the same handshake instead of
  // rejecting it as already-closed.
  let (c, s) = duplex_with_stalling_flush(); // flush never completes → close can't finish
  let _s = s;
  let client = client_over(c);
  let (_cread, mut cwrite) = client.split();
  // First close queues the Close frame, then hangs in flush → the caller times out.
  let r1 = tokio::time::timeout(
    Duration::from_millis(100),
    cwrite.close(CloseCode::Normal, ""),
  )
  .await;
  assert!(
    r1.is_err(),
    "the stalled flush makes the first close time out"
  );
  // The retry must resume flushing (still stalled) — NOT return Error::Closed.
  let r2 = tokio::time::timeout(
    Duration::from_millis(100),
    cwrite.close(CloseCode::Normal, ""),
  )
  .await;
  match r2 {
    Err(_elapsed) => {} // resumed flushing the queued Close; still stalled — correct
    Ok(Err(Error::Closed)) => {
      panic!("retry wrongly rejected the queued close as already-closed (Finding 2)")
    }
    Ok(other) => panic!("retry resolved unexpectedly: {other:?}"),
  }
}

#[tokio::test]
async fn convenience_send_respects_backpressure_gate() {
  // Finding 3: convenience sends must wait on the soft-cap gate BEFORE encoding, so a
  // stalled transport bounds `write_buf` instead of letting each send stack another
  // frame on top of an already-over-cap buffer.
  use futures_util::sink::SinkExt;
  let (c, s) = duplex_with_stalling_flush();
  let _s = s;
  let mut client = client_over(c);
  // Preload the staged buffer past the soft cap via the Sink: `feed` runs poll_ready
  // (Ready on the empty buffer) + start_send (encodes), with NO flush.
  let big = vec![0u8; WRITE_BUF_SOFT_CAP + 1024];
  client.feed(Message::Binary(big.into())).await.unwrap();
  let before = client.inner.write_buf.len();
  assert!(
    before >= WRITE_BUF_SOFT_CAP,
    "preload must exceed the soft cap"
  );
  // A convenience send now must PARK at the gate rather than encode another frame.
  let r = tokio::time::timeout(Duration::from_millis(100), client.send_text("x")).await;
  assert!(
    r.is_err(),
    "a backpressured convenience send must park, not complete"
  );
  assert_eq!(
    before,
    client.inner.write_buf.len(),
    "the gate blocks BEFORE encoding, so write_buf does not grow (Finding 3)"
  );
}

#[test]
fn reader_gate_wakes_when_writer_drains() {
  // No lost reader wakeup: the read pump parked at the soft-cap
  // backpressure gate must be woken when a WRITER drains the shared buffer below the
  // cap — even though the writer holds (and may steal) the transport's single
  // write-waker slot. Driven at the poll level with distinct wakers.
  use futures_util::AsyncRead;
  use std::{
    pin::Pin,
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
  };

  // A transport window smaller than the staged buffer, so the flush stalls with the
  // buffer still above the soft cap (tripping the read gate).
  let cap = 40 * 1024;
  let (c, s) = duplex_with_capacity(cap);
  let mut s = s;
  let mut inner = client_over(c).inner;
  // Stage a message larger than the soft cap so the gate trips.
  let payload = vec![0u8; WRITE_BUF_SOFT_CAP + 8 * 1024];
  inner
    .encode_into_buf(payload.len(), |conn, o| conn.encode_binary(&payload, o))
    .unwrap();

  // The read pump parks at the gate: poll_flush writes `cap` bytes then stalls while
  // write_buf is still at/above the soft cap.
  let reader = Arc::new(CountWaker(AtomicUsize::new(0)));
  let rw = Waker::from(reader.clone());
  assert!(
    inner.poll_next(&mut Context::from_waker(&rw)).is_pending(),
    "the buffer is above the soft cap with a stalled flush, so the reader gates"
  );
  assert_eq!(reader.0.load(Ordering::SeqCst), 0, "not woken yet");

  // The writer polls the still-full transport FIRST: its poll_write parks too,
  // STEALING the transport's single write-waker slot from the gated reader. From here
  // the reader can be woken only via the durable read_waker, not the transport.
  let writer = Waker::from(Arc::new(CountWaker(AtomicUsize::new(0))));
  assert!(
    inner
      .poll_flush_writer(&mut Context::from_waker(&writer))
      .is_pending(),
    "the transport is full, so the writer parks too (stealing the slot)"
  );
  // Now drain the peer and flush to completion. Clearing the buffer below the cap must
  // wake the gated reader via the durable read_waker.
  let noop = futures_util::task::noop_waker();
  let mut buf = vec![0u8; cap];
  let mut cleared = false;
  for _ in 0..64 {
    let _ = Pin::new(&mut s).poll_read(&mut Context::from_waker(&noop), &mut buf);
    if inner
      .poll_flush_writer(&mut Context::from_waker(&writer))
      .is_ready()
    {
      cleared = true;
      break;
    }
  }
  assert!(
    cleared,
    "the writer should drain the buffer within the budget"
  );
  assert!(
    reader.0.load(Ordering::SeqCst) >= 1,
    "draining the buffer below the cap must wake the gated reader"
  );
}

#[tokio::test]
async fn unsplit_close_retry_after_flush_before_echo() {
  // A `timeout(close())` cancelled AFTER our Close flushed but BEFORE
  // the peer echo must be resumable — the retry resumes driving the handshake instead
  // of re-initiating it and being rejected as already-closing.
  let (c, s) = duplex();
  let _s = s; // peer endpoint stays open but never echoes → handshake stalls at the echo wait
  let mut client = client_over(c);
  // First close flushes our Close, then waits for the (absent) echo → caller times out.
  let r1 = tokio::time::timeout(
    Duration::from_millis(100),
    client.close(CloseCode::Normal, ""),
  )
  .await;
  assert!(r1.is_err(), "no peer echo, so the first close times out");
  // The retry must resume waiting for the echo — NOT resolve with an error.
  let r2 = tokio::time::timeout(
    Duration::from_millis(100),
    client.close(CloseCode::Normal, ""),
  )
  .await;
  match r2 {
    Err(_elapsed) => {} // resumed driving the handshake; still awaiting the echo — correct
    Ok(other) => panic!("retry must resume the pending handshake, not resolve: {other:?}"),
  }
}

#[tokio::test]
async fn split_close_retry_after_reader_cleared_pending() {
  // Split: once the read half flushes our Close and clears the transient
  // close-pending flag while awaiting the peer echo, a WriteHalf close retry must still
  // succeed (idempotent) rather than be rejected.
  let (c, s) = duplex();
  let _s = s; // peer endpoint stays open but never echoes
  let client = client_over(c);
  let (mut cread, mut cwrite) = client.split();
  // First close flushes our Close (returns Ok; the read half drives the echo).
  cwrite.close(CloseCode::Normal, "").await.unwrap();
  // The read half runs and clears the transient close_pending while awaiting the echo.
  let _ = tokio::time::timeout(Duration::from_millis(50), cread.next()).await;
  // The retry must resume (idempotent), not be rejected because the flag was cleared.
  cwrite.close(CloseCode::Normal, "").await.unwrap();
}

#[test]
fn closing_with_unflushed_echo_parks_reader_durably() {
  // No lost reader wakeup at close: while closing with an
  // unflushed Close/echo BELOW the soft cap, the read pump must park durably (store
  // read_waker) so a concurrent writer draining the echo wakes it to publish the close
  // — it must not fall through to poll_read relying on the steal-prone transport slot.
  use futures_util::AsyncRead;
  use std::{
    pin::Pin,
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
  };

  let cap = 8; // tiny transport so a small staged frame can't flush in one go
  let (c, s) = duplex_with_capacity(cap);
  let mut s = s;
  let mut inner = client_over(c).inner;
  // Reproduce "closing with a small unflushed Close/echo": stage a sub-cap frame, then
  // mark the connection closing (as decode_pending does when a peer Close arrives).
  let payload = [0u8; 64]; // < WRITE_BUF_SOFT_CAP but > the transport window
  inner
    .encode_into_buf(payload.len(), |conn, o| conn.encode_binary(&payload, o))
    .unwrap();
  inner.closing = true;

  // The read pump parks at the closing-unflushed gate, storing a durable read_waker.
  let reader = Arc::new(CountWaker(AtomicUsize::new(0)));
  let rw = Waker::from(reader.clone());
  assert!(
    inner.poll_next(&mut Context::from_waker(&rw)).is_pending(),
    "closing with an unflushed echo must park the reader, not read on"
  );
  assert_eq!(reader.0.load(Ordering::SeqCst), 0, "not woken yet");

  // A writer steals the transport slot, then drains the echo to completion. Clearing
  // the buffer must wake the gated reader via the durable read_waker.
  let writer = Waker::from(Arc::new(CountWaker(AtomicUsize::new(0))));
  assert!(
    inner
      .poll_flush_writer(&mut Context::from_waker(&writer))
      .is_pending(),
    "the transport is full, so the writer parks too (stealing the slot)"
  );
  let noop = futures_util::task::noop_waker();
  let mut buf = vec![0u8; cap];
  let mut cleared = false;
  for _ in 0..64 {
    let _ = Pin::new(&mut s).poll_read(&mut Context::from_waker(&noop), &mut buf);
    if inner
      .poll_flush_writer(&mut Context::from_waker(&writer))
      .is_ready()
    {
      cleared = true;
      break;
    }
  }
  assert!(
    cleared,
    "the writer should drain the buffer within the budget"
  );
  assert!(
    reader.0.load(Ordering::SeqCst) >= 1,
    "draining the unflushed echo must wake the closing reader"
  );
}

#[test]
fn read_eof_fails_and_wakes_parked_writer() {
  // Read-side terminal propagation: when the read pump sees transport
  // EOF, it must record a terminal state AND wake a parked writer — the write half
  // can't observe EOF on its own, so it would otherwise hang forever.
  use std::{
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
  };

  let (c, s) = duplex_with_capacity(8); // tiny window so the writer parks on flush
  let mut inner = client_over(c).inner;
  // Stage a small (sub-cap) frame and park a writer on the backpressured flush.
  let payload = [0u8; 64];
  inner
    .encode_into_buf(payload.len(), |conn, o| conn.encode_binary(&payload, o))
    .unwrap();
  let writer = Arc::new(CountWaker(AtomicUsize::new(0)));
  let ww = Waker::from(writer.clone());
  assert!(
    inner
      .poll_flush_writer(&mut Context::from_waker(&ww))
      .is_pending(),
    "the transport window is full, so the writer parks"
  );

  // The peer goes away → the client's read side hits EOF.
  drop(s);

  // The read pump observes EOF: it must surface an error, record terminal state, and
  // wake the parked writer.
  let reader = Waker::from(Arc::new(CountWaker(AtomicUsize::new(0))));
  match inner.poll_next(&mut Context::from_waker(&reader)) {
    std::task::Poll::Ready(Some(Err(Error::Io(_)))) => {}
    other => panic!("EOF before close must surface as an Io error, got {other:?}"),
  }
  assert!(
    writer.0.load(Ordering::SeqCst) >= 1,
    "read EOF must wake the parked writer"
  );
  // And a subsequent send sees the terminal state rather than succeeding.
  inner
    .encode_into_buf(1, |conn, o| conn.encode_text("x", o))
    .unwrap_err();
}

#[tokio::test]
async fn close_surfaces_transport_shutdown_error() {
  // A failed transport shutdown (poll_close error) must surface from
  // close(), not be swallowed and reported as a clean close.
  let (c, s) = duplex_with_failing_close();
  let mut client = client_over(c);
  let mut server = server_over(s);
  let srv = tokio::spawn(async move { while server.next().await.is_some() {} });
  let err = client.close(CloseCode::Normal, "").await.unwrap_err();
  assert!(
    matches!(err, Error::Io(_)),
    "a failed transport shutdown surfaces as Io (got {err:?})"
  );
  srv.abort();
}

#[test]
fn backpressured_send_fails_when_peer_close_arrives() {
  // A send parked at the soft-cap gate must observe a peer-initiated
  // close — waking promptly and returning Closed — not hang waiting for a buffer that
  // will never drain once no new frame can be accepted.
  use std::{
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
  };

  // Generate a real peer (server) Close frame to feed the client.
  let close_bytes = {
    let (_x, sp) = duplex();
    let mut srv = server_over(sp).inner;
    srv.start_close(CloseCode::Normal, "").unwrap();
    srv.drain_transmits().unwrap();
    srv.write_buf.clone()
  };

  let (c, _s) = duplex_with_capacity(8); // tiny window: the staged send can't drain
  let mut inner = client_over(c).inner;
  // Stage an over-cap message and park a sender at the backpressure gate.
  let payload = vec![0u8; WRITE_BUF_SOFT_CAP + 1024];
  inner
    .encode_into_buf(payload.len(), |conn, o| conn.encode_binary(&payload, o))
    .unwrap();
  let sender = Arc::new(CountWaker(AtomicUsize::new(0)));
  let sw = Waker::from(sender.clone());
  assert!(
    matches!(
      inner.poll_ready_writer(&mut Context::from_waker(&sw)),
      Poll::Pending
    ),
    "the over-cap buffer cannot drain, so the sender parks at the gate"
  );

  // A peer Close arrives and the read pump decodes it: this must wake the parked sender.
  inner.pending_input = close_bytes;
  inner.decode_pending().unwrap();
  assert!(
    sender.0.load(Ordering::SeqCst) >= 1,
    "decoding a peer Close must wake the parked sender"
  );

  // Re-polling the gate now rejects the send instead of waiting on the dead buffer.
  match inner.poll_ready_writer(&mut Context::from_waker(&sw)) {
    Poll::Ready(Err(Error::Closed)) => {}
    other => panic!("a send after a peer close must be rejected as Closed, got {other:?}"),
  }
}

#[test]
fn terminal_shutdown_parks_reader_durably() {
  // While the terminal transport shutdown (poll_close) is pending, the
  // read pump must park durably (store read_waker), so a split writer that steals the
  // transport write slot still wakes it (via wake_both on its flush) to finish teardown.
  use futures_util::AsyncWrite;
  use std::{
    pin::Pin,
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
  };

  // A real peer (server) Close frame to drive the client to a published close.
  let close_bytes = {
    let (_x, sp) = duplex();
    let mut srv = server_over(sp).inner;
    srv.start_close(CloseCode::Normal, "").unwrap();
    srv.drain_transmits().unwrap();
    srv.write_buf.clone()
  };

  let (c, s) = duplex_with_stalling_close(); // the client's poll_close never completes
  let mut s = s;
  let mut inner = client_over(c).inner;
  // Deliver the peer Close to the client's read side.
  let noop = futures_util::task::noop_waker();
  match Pin::new(&mut s).poll_write(&mut Context::from_waker(&noop), &close_bytes) {
    Poll::Ready(Ok(n)) => assert_eq!(n, close_bytes.len()),
    other => panic!("failed to deliver peer Close: {other:?}"),
  }

  // The read pump processes the Close, echoes it, publishes `closed`, then reaches the
  // terminal poll_close which stalls — it must park in the reactor's read slot.
  let reader = Arc::new(CountWaker(AtomicUsize::new(0)));
  let rw = Waker::from(reader.clone());
  assert!(
    matches!(
      inner.poll_next(&mut Context::from_waker(&rw)),
      Poll::Pending
    ),
    "the stalled terminal shutdown leaves the read pump pending"
  );

  // A split writer flushing (empty buffer) clears the buffer and wakes the reader (via
  // wake_both) to re-attempt teardown — proving the reader parked durably.
  let writer = Waker::from(Arc::new(CountWaker(AtomicUsize::new(0))));
  let _ = inner.poll_flush_writer(&mut Context::from_waker(&writer));
  assert!(
    reader.0.load(Ordering::SeqCst) >= 1,
    "a writer flush must wake the reader parked in terminal shutdown"
  );
}

#[test]
fn cancelled_writer_does_not_strand_parked_reader() {
  // Cancellation-safe wakeups: a reader parked at the soft-cap gate must
  // be woken when the transport drains EVEN IF a writer registered (then was cancelled)
  // on the same write side. The fan-out reactor wakes BOTH slots on transport
  // readiness, so a stale/cancelled writer waker cannot swallow the reader's wakeup.
  use futures_util::AsyncRead;
  use std::{
    pin::Pin,
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
  };

  let cap = 40 * 1024;
  let (c, s) = duplex_with_capacity(cap);
  let mut s = s;
  let mut inner = client_over(c).inner;
  // Stage an over-cap message so the read pump gates and a writer flush can't drain it.
  let payload = vec![0u8; WRITE_BUF_SOFT_CAP + 8 * 1024];
  inner
    .encode_into_buf(payload.len(), |conn, o| conn.encode_binary(&payload, o))
    .unwrap();

  // Reader parks at the soft-cap gate (registers the reactor's read slot).
  let reader = Arc::new(CountWaker(AtomicUsize::new(0)));
  let rw = Waker::from(reader.clone());
  assert!(matches!(
    inner.poll_next(&mut Context::from_waker(&rw)),
    Poll::Pending
  ));

  // A writer parks on the same full write side (registers the reactor's write slot),
  // then is "cancelled": we simply never poll it again. Its registration goes stale.
  {
    let cancelled = Waker::from(Arc::new(CountWaker(AtomicUsize::new(0))));
    assert!(
      inner
        .poll_flush_writer(&mut Context::from_waker(&cancelled))
        .is_pending()
    );
  }

  // The peer drains the transport: readiness fans out through the reactor and wakes the
  // reader, despite the stale (cancelled) writer registration on the same write side.
  let noop = futures_util::task::noop_waker();
  let mut buf = vec![0u8; cap];
  assert!(matches!(
    Pin::new(&mut s).poll_read(&mut Context::from_waker(&noop), &mut buf),
    Poll::Ready(Ok(_))
  ));
  assert!(
    reader.0.load(Ordering::SeqCst) >= 1,
    "the reader must wake on transport drain despite a cancelled writer"
  );
}

#[test]
fn writer_registers_before_poll_no_lost_wake() {
  // The reactor slot must be registered BEFORE the transport poll. With a
  // transport that signals readiness exactly at the poll (the race window), a
  // register-after-poll drops the wake (AtomicWaker has no memory of it); register-
  // before-poll catches it.
  use std::{
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
  };

  let (c, _s) = duplex_with_eager_wake(); // poll_write wakes the task, then blocks
  let mut inner = client_over(c).inner;
  let payload = [0u8; 64];
  inner
    .encode_into_buf(payload.len(), |conn, o| conn.encode_binary(&payload, o))
    .unwrap();

  let writer = Arc::new(CountWaker(AtomicUsize::new(0)));
  let ww = Waker::from(writer.clone());
  // The flush polls the transport, which wakes the fan-out waker mid-poll. Because the
  // write slot was registered first, that wake reaches this task.
  let _ = inner.poll_flush_writer(&mut Context::from_waker(&ww));
  assert!(
    writer.0.load(Ordering::SeqCst) >= 1,
    "register-before-poll must catch readiness that fires at the poll"
  );
}

#[test]
fn idle_poll_next_parks_without_self_wake() {
  // Poll_next on an idle connection (empty write buffer, nothing inbound)
  // must park WITHOUT waking its own read slot. Flushing an already-empty buffer must
  // not fire wake_both, or next() self-wakes and busy-loops.
  use std::{
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
  };

  let (c, _s) = duplex(); // idle: nothing to read, nothing staged to write
  let mut inner = client_over(c).inner;
  let reader = Arc::new(CountWaker(AtomicUsize::new(0)));
  let rw = Waker::from(reader.clone());
  assert!(matches!(
    inner.poll_next(&mut Context::from_waker(&rw)),
    Poll::Pending
  ));
  assert_eq!(
    reader.0.load(Ordering::SeqCst),
    0,
    "an idle poll_next must park without waking its own read slot"
  );
}

#[test]
fn idle_poll_next_skips_flush_no_self_wake() {
  // Even on a transport whose poll_flush wakes its waker on an idle
  // flush, an idle poll_next must NOT self-wake — the driver skips the transport flush
  // entirely when nothing is staged.
  use std::{
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
  };

  let (c, _s) = duplex_with_wake_on_flush(); // poll_flush would wake the task if called
  let mut inner = client_over(c).inner;
  let reader = Arc::new(CountWaker(AtomicUsize::new(0)));
  let rw = Waker::from(reader.clone());
  assert!(matches!(
    inner.poll_next(&mut Context::from_waker(&rw)),
    Poll::Pending
  ));
  assert_eq!(
    reader.0.load(Ordering::SeqCst),
    0,
    "idle poll_next must skip the transport flush, so a wake-on-flush adapter can't self-wake it"
  );
}

#[test]
fn large_send_does_not_retain_peak_capacity() {
  // After a single oversized frame drains, the write buffer must not keep
  // its peak capacity for the life of the connection.
  use std::task::Poll;

  let (c, s) = duplex(); // unbounded: the whole frame flushes in one poll
  let _s = s;
  let mut inner = client_over(c).inner;
  let big = vec![0u8; 2 * 1024 * 1024]; // 2 MiB, far above the retain cap
  inner
    .encode_into_buf(big.len(), |conn, o| conn.encode_binary(&big, o))
    .unwrap();
  assert!(
    inner.write_buf.capacity() >= big.len(),
    "staging the frame balloons the buffer"
  );
  assert!(
    matches!(inner.poll_flush(), Poll::Ready(Ok(()))),
    "the unbounded transport drains the whole frame"
  );
  assert!(
    inner.write_buf.capacity() <= 8 * WRITE_BUF_SOFT_CAP,
    "post-drain capacity must be shrunk, not retained at the multi-megabyte peak"
  );
}

#[test]
fn protocol_failure_surfaces_promptly_over_staged_data() {
  // A protocol violation must fail fast — surface an error to the reader
  // and poison (so a pending writer's send fails) — not queue the failure Close behind
  // backpressured app data and park behind it.
  use futures_util::AsyncWrite;
  use std::{
    pin::Pin,
    task::{Context, Poll},
  };

  let (c, s) = duplex_with_stalling_flush(); // the client's writes stall, so staged data sticks
  let mut s = s;
  let mut inner = client_over(c).inner;
  // Stage app data that cannot drain (the write side's flush stalls forever).
  inner
    .encode_into_buf(3, |conn, o| conn.encode_binary(b"app", o))
    .unwrap();
  // Deliver a malformed frame (reserved opcode 0x3, unmasked server frame) to the
  // client's read side.
  let noop = futures_util::task::noop_waker();
  let bad = [0x83u8, 0x00];
  assert!(matches!(
    Pin::new(&mut s).poll_write(&mut Context::from_waker(&noop), &bad),
    Poll::Ready(Ok(_))
  ));
  // The reader must surface the failure even though staged app data is stuck, and the
  // error must carry the proto close code (ProtocolError for a reserved opcode), not a
  // generic transport reset.
  match inner.poll_next(&mut Context::from_waker(&noop)) {
    Poll::Ready(Some(Err(Error::Protocol(CloseCode::ProtocolError)))) => {}
    other => panic!("a protocol failure must surface promptly with its code, got {other:?}"),
  }
  // Poisoned: a subsequent send fails rather than appearing to succeed.
  inner
    .encode_into_buf(1, |conn, o| conn.encode_text("x", o))
    .unwrap_err();
}

#[test]
fn build_config_lifts_frame_cap_to_message_cap() {
  // The per-frame cap must track the configured message cap, or an
  // unfragmented message between proto's 16 MiB frame default and the message cap is
  // wrongly rejected.
  let cap = 20 * 1024 * 1024;
  let (config, got) = build_config(Some(cap));
  assert_eq!(got, cap);
  assert_eq!(
    config.max_frame_payload(),
    cap as u64,
    "the frame cap must match the configured message cap"
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symmetric_large_sends_do_not_deadlock() {
  // Both peers sending a large message concurrently must not deadlock.
  // The read gate must not refuse to drain inbound just because OUR app data is over the
  // soft cap (only a read-pump-driven pong/echo flood may pause reads); otherwise each
  // side refuses to drain the other and both sends hang.
  let (ca, sb) = duplex_with_capacity(4096); // bounded both directions
  let client = client_over(ca);
  let server = server_over(sb);
  let (mut cread, mut cwrite) = client.split();
  let (mut sread, mut swrite) = server.split();
  let big_c = vec![0xCDu8; 256 * 1024];
  let big_s = vec![0xABu8; 256 * 1024];
  let cw = tokio::spawn(async move { cwrite.send_binary(&big_c).await });
  let sw = tokio::spawn(async move { swrite.send_binary(&big_s).await });
  let cr = tokio::spawn(async move { cread.next().await });
  let sr = tokio::spawn(async move { sread.next().await });
  tokio::time::timeout(Duration::from_secs(10), async move {
    cw.await.unwrap().unwrap();
    sw.await.unwrap().unwrap();
    assert!(matches!(cr.await.unwrap(), Some(Ok(Message::Binary(_)))));
    assert!(matches!(sr.await.unwrap(), Some(Ok(Message::Binary(_)))));
  })
  .await
  .expect("symmetric large sends must not deadlock");
}
