use super::*;
use crate::{
  IntoDuplex,
  duplex::{Pipe, duplex, duplex_with_capacities, duplex_with_capacity, duplex_with_write_fault},
};

type PipeDuplex = <Pipe as IntoDuplex>::Duplex;

fn pair() -> (
  WebSocket<ClientRole, PipeDuplex>,
  WebSocket<ServerRole, PipeDuplex>,
) {
  pair_with(
    crate::options::ClientOptions::default(),
    crate::options::AcceptOptions::default(),
  )
}

fn pair_with(
  copts: crate::options::ClientOptions,
  sopts: crate::options::AcceptOptions,
) -> (
  WebSocket<ClientRole, PipeDuplex>,
  WebSocket<ServerRole, PipeDuplex>,
) {
  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  (
    WebSocket::client(c.into_duplex(), &negotiated, &copts, Vec::new()),
    WebSocket::server(s.into_duplex(), &negotiated, &sopts, Vec::new()),
  )
}

#[compio::test]
async fn echo_text_round_trip() {
  let (mut client, mut server) = pair();
  client.send_text("hello").await.unwrap();
  let echo = compio_runtime::spawn(async move {
    let msg = server.next().await.unwrap().unwrap();
    server.send(msg).await.unwrap();
    server
  });
  let msg = client.next().await.unwrap().unwrap();
  assert_eq!(msg, Message::Text("hello".into()));
  drop(echo.await);
}

#[compio::test]
async fn large_binary_round_trip() {
  let (mut client, mut server) = pair();
  let payload = vec![0xAB_u8; 1 << 20];
  let expect = payload.clone();
  let server_task = compio_runtime::spawn(async move {
    let msg = server.next().await.unwrap().unwrap();
    assert_eq!(msg, Message::Binary(expect.into()));
  });
  client.send_binary(&payload).await.unwrap();
  server_task.await.unwrap();
}

#[compio::test]
async fn close_handshake_completes() {
  let (client, mut server) = pair();
  let server_task = compio_runtime::spawn(async move {
    assert!(server.next().await.is_none());
    let closed = server.closed().unwrap();
    assert_eq!(closed.code(), CloseCode::Normal);
    assert!(closed.clean());
  });
  let closed = client.close(CloseCode::Normal, "bye").await.unwrap();
  assert!(closed.clean());
  server_task.await.unwrap();
}

#[compio::test]
async fn keepalive_pings_flow_while_idle() {
  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let copts = crate::options::ClientOptions::default()
    .with_keepalive(Some(std::time::Duration::from_millis(50)));
  let mut client = WebSocket::client(c.into_duplex(), &negotiated, &copts, Vec::new());
  let mut server = WebSocket::server(
    s.into_duplex(),
    &negotiated,
    &crate::options::AcceptOptions::default(),
    Vec::new(),
  );
  // Both pumps idle: the client keepalive must emit pings, the server
  // auto-pongs, and no data message surfaces — so the experiment times out.
  let outcome = compio::time::timeout(std::time::Duration::from_millis(400), async {
    futures_util::select_biased! {
      m = client.next().fuse() => m,
      m = server.next().fuse() => m,
    }
  })
  .await;
  assert!(outcome.is_err(), "no data message may surface");
  assert!(server.pings_seen() >= 1, "server saw the keepalive ping(s)");
}

#[compio::test]
async fn close_deadline_fires_without_peer_echo() {
  let (c, _held_open) = duplex(); // the peer never answers
  let negotiated = Negotiated::none();
  let copts = crate::options::ClientOptions::default()
    .with_close_timeout(std::time::Duration::from_millis(80));
  let client = WebSocket::client(c.into_duplex(), &negotiated, &copts, Vec::new());
  let closed = client.close(CloseCode::Normal, "").await.unwrap();
  assert!(!closed.clean(), "deadline close is unclean");
}

#[compio::test]
async fn split_writer_sends_while_reader_pumps() {
  let (mut client, server) = pair();
  let (mut sread, mut swrite) = server.split();
  let writer = compio_runtime::spawn(async move {
    for i in 0..10u32 {
      swrite.send_text(&format!("msg-{i}")).await.unwrap();
    }
    swrite
  });
  let reader = compio_runtime::spawn(async move {
    while let Some(result) = sread.next().await {
      result.unwrap();
    }
    sread
  });
  for i in 0..10u32 {
    let m = client.next().await.unwrap().unwrap();
    assert_eq!(m, Message::Text(format!("msg-{i}").into()));
  }
  drop(writer.await);
  // A clean close lets the reader loop run to `None` without errors; the
  // join surfaces any panic the loop hit on the way.
  let closed = client.close(CloseCode::Normal, "done").await.unwrap();
  assert!(closed.clean());
  let sread = reader.await.unwrap();
  assert!(sread.closed().unwrap().clean());
}

#[compio::test]
async fn cancelled_send_flushes_before_close() {
  use std::future::Future;

  let (mut client, server) = pair();
  let (mut sread, mut swrite) = server.split();
  let reader = compio_runtime::spawn(async move {
    while let Some(result) = sread.next().await {
      result.unwrap();
    }
    sread
  });
  // Cancel a send after its first poll: the frame is already enqueued but
  // no task awaits it any more.
  {
    let mut fut = Box::pin(swrite.send_text("zombie"));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  swrite.close(CloseCode::Normal, "done").await.unwrap();
  // The orphaned frame still precedes the Close on the wire (RFC 6455
  // §5.5.1: no data frames after the Close).
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("zombie".into()));
  assert!(client.next().await.is_none());
  assert!(client.closed().unwrap().clean());
  let sread = reader.await.unwrap();
  assert!(sread.closed().unwrap().clean());
}

#[compio::test]
async fn dropping_read_half_wakes_writers() {
  let (_client, server) = pair();
  let (sread, mut swrite) = server.split();
  drop(sread);
  let err = swrite.send_text("nope").await.unwrap_err();
  assert!(matches!(err, Error::ReadHalfGone));
}

#[compio::test]
async fn cancelled_next_preserves_the_connection() {
  use std::future::Future;

  let (mut client, mut server) = pair();
  // Park the server pump on its read, then cancel it mid-await.
  {
    let mut fut = Box::pin(server.next());
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  // The connection must still work: the stream went back into the
  // connection when the future dropped, and nothing was lost.
  client.send_text("after cancel").await.unwrap();
  let m = server.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("after cancel".into()));
  // And the reverse direction too.
  server.send_text("echo").await.unwrap();
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("echo".into()));
}

#[compio::test]
async fn cancelled_send_resumes_without_corruption() {
  use std::future::Future;

  // A 4 KiB pipe + a 64 KiB frame: the send must park on backpressure
  // with the frame partially on the wire.
  let (c, s) = duplex_with_capacity(4 * 1024);
  let negotiated = Negotiated::none();
  let mut client = WebSocket::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default(),
    Vec::new(),
  );
  let mut server = WebSocket::server(
    s.into_duplex(),
    &negotiated,
    &crate::options::AcceptOptions::default(),
    Vec::new(),
  );

  let payload = vec![0xCD_u8; 64 * 1024];
  {
    // Poll the send until it parks (adapter buffer + pipe both full),
    // then cancel it. The write cursor must survive in the connection.
    let mut fut = Box::pin(client.send_binary(&payload));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  // A fresh send resumes the cancelled frame first, then sends its own:
  // the peer must see BOTH messages intact, in order — no spliced bytes,
  // no duplicated chunk from a cursor reset.
  let expect = payload.clone();
  let server_task = compio_runtime::spawn(async move {
    let first = server.next().await.unwrap().unwrap();
    assert_eq!(first, Message::Binary(expect.into()));
    let second = server.next().await.unwrap().unwrap();
    assert_eq!(second, Message::Text("tail".into()));
    server
  });
  client.send_text("tail").await.unwrap();
  // Propagates any assertion panic from the server task.
  drop(server_task.await.unwrap());
}

#[compio::test]
async fn dropping_read_half_orphans_a_parked_batch() {
  use std::future::Future;

  // Bounded pipe: the pump's write of the 64 KiB frame parks mid-batch.
  let (_client, server) = {
    let (c, s) = duplex_with_capacity(4 * 1024);
    let negotiated = Negotiated::none();
    (
      WebSocket::<ClientRole, _>::client(
        c.into_duplex(),
        &negotiated,
        &crate::options::ClientOptions::default(),
        Vec::new(),
      ),
      WebSocket::<ServerRole, _>::server(
        s.into_duplex(),
        &negotiated,
        &crate::options::AcceptOptions::default(),
        Vec::new(),
      ),
    )
  };
  let (mut sread, mut swrite) = server.split();
  let writer = compio_runtime::spawn(async move {
    let payload = vec![0xEE_u8; 64 * 1024];
    swrite.send_binary(&payload).await
  });
  // Let the writer enqueue and park on the doorbell.
  compio::time::sleep(std::time::Duration::from_millis(10)).await;
  // One pump poll coalesces the frame into the in-progress batch and
  // parks on backpressure; cancelling it leaves the batch parked.
  {
    let mut fut = Box::pin(sread.next());
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  // Nothing will ever pump that batch again: the sender must fail, not
  // hang on the doorbell forever.
  drop(sread);
  let outcome = compio::time::timeout(std::time::Duration::from_secs(2), writer)
    .await
    .expect("the parked sender must resolve once the read half is gone");
  assert!(matches!(outcome.unwrap(), Err(Error::ReadHalfGone)));
}

#[compio::test]
async fn close_echo_flushes_before_buffered_data_delivery() {
  use std::future::Future;

  let (mut client, mut server) = pair_with(
    crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(100)),
    crate::options::AcceptOptions::default(),
  );
  client.send_text("data").await.unwrap();
  // Drive the client's close just far enough to put its Close frame on
  // the wire (it then parks waiting for the echo).
  let mut close_fut = Box::pin(client.close(CloseCode::Normal, "bye"));
  futures_util::future::poll_fn(|cx| {
    assert!(close_fut.as_mut().poll(cx).is_pending());
    std::task::Poll::Ready(())
  })
  .await;
  // The server sees [data][Close] in one read. Returning the data
  // message must NOT leave the echo unwritten — the client (which we do
  // not help by polling the server again) must complete cleanly rather
  // than hit its close deadline.
  let m = server.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("data".into()));
  let closed = close_fut.await.unwrap();
  assert!(
    closed.clean(),
    "the close echo reached the client without further server polls"
  );
  assert!(server.next().await.is_none());
  assert!(server.closed().unwrap().clean());
}

#[compio::test]
async fn write_half_close_flushes_despite_buffered_messages() {
  let (mut client, server) = pair();
  let (mut sread, mut swrite) = server.split();
  // Two buffered messages: the pump reads both into `ready` in one pass.
  client.send_text("a").await.unwrap();
  client.send_text("b").await.unwrap();
  let m = sread.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("a".into()));
  // Close while "b" is still buffered.
  let closer = compio_runtime::spawn(async move {
    swrite.close(CloseCode::Normal, "done").await.unwrap();
    swrite
  });
  compio::time::sleep(std::time::Duration::from_millis(10)).await;
  // The reader takes ONE more message and stops polling. The Close must
  // have been flushed before that delivery — the closer may not hang.
  let m = sread.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("b".into()));
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the close must flush before buffered delivery")
    .unwrap();
  // The client indeed observes the close without further server polls.
  assert!(client.next().await.is_none());
  assert_eq!(client.closed().unwrap().code(), CloseCode::Normal);
}

#[compio::test]
async fn peer_close_echo_flushes_behind_a_parked_batch() {
  use std::future::Future;

  // Bounded pipe so a cancelled 64 KiB send leaves a parked batch.
  let (c, s) = duplex_with_capacity(4 * 1024);
  let negotiated = Negotiated::none();
  let mut client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(200)),
    Vec::new(),
  );
  let mut server = WebSocket::<ServerRole, _>::server(
    s.into_duplex(),
    &negotiated,
    &crate::options::AcceptOptions::default(),
    Vec::new(),
  );
  {
    let payload = vec![0xBB_u8; 64 * 1024];
    let mut fut = Box::pin(server.send_binary(&payload));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  client.send_text("data").await.unwrap();
  // The client closes and pumps in its own task (it also drains the
  // server's 64 KiB batch, which precedes the echo on the wire).
  let closer =
    compio_runtime::spawn(async move { client.close(CloseCode::Normal, "bye").await.unwrap() });
  compio::time::sleep(std::time::Duration::from_millis(10)).await;
  // One server poll: the parked batch and the echo behind it must both
  // flush before "data" is delivered.
  let m = server.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("data".into()));
  let closed = compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the close completes without further server polls")
    .unwrap();
  assert!(closed.clean(), "echo arrived before the close deadline");
  assert!(server.next().await.is_none());
}

#[compio::test]
async fn delayed_poll_keeps_a_prompt_echo_clean() {
  use std::future::Future;

  let (client, mut server) = pair_with(
    crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(50)),
    crate::options::AcceptOptions::default(),
  );
  // Drive the close until its Close frame is out and it parks.
  let mut close_fut = Box::pin(client.close(CloseCode::Normal, "bye"));
  futures_util::future::poll_fn(|cx| {
    assert!(close_fut.as_mut().poll(cx).is_pending());
    std::task::Poll::Ready(())
  })
  .await;
  // The peer echoes PROMPTLY (well within the deadline)…
  assert!(server.next().await.is_none());
  assert!(server.closed().unwrap().clean());
  // …but the closer is not polled again until after the deadline. The
  // echo is already buffered: wall time alone must not turn it unclean.
  compio::time::sleep(std::time::Duration::from_millis(120)).await;
  let closed = close_fut.await.unwrap();
  assert!(
    closed.clean(),
    "a prompt echo beats the deadline clock even when polled late"
  );
}

#[compio::test]
async fn close_deadline_survives_inbound_flood() {
  let (client, mut server) = pair_with(
    crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(100)),
    crate::options::AcceptOptions::default(),
  );
  // The server floods data and NEVER pumps its reads, so the client's
  // Close is never echoed; the client's deadline must still fire while
  // its pump keeps receiving messages.
  //
  // Liveness smoke for the up-front overdue-timer check: over a real
  // socket a flood keeps the read arm permanently ready (arrival is
  // concurrent with processing) and would starve the parked timer; the
  // cooperative in-memory pipe always drains to empty before parking, so
  // this test cannot reproduce the starvation itself — it pins that the
  // deadline bounds close() under sustained inbound traffic.
  let flood = compio_runtime::spawn(async move {
    loop {
      if server.send_text("spam").await.is_err() {
        break;
      }
      compio::time::sleep(std::time::Duration::from_micros(200)).await;
    }
  });
  let closed = compio::time::timeout(
    std::time::Duration::from_secs(2),
    client.close(CloseCode::Normal, "bye"),
  )
  .await
  .expect("the close deadline must bound the handshake under flood")
  .unwrap();
  assert!(!closed.clean(), "no echo: the deadline close is unclean");
  drop(flood.await);
}

#[compio::test]
async fn pong_flushes_before_buffered_data_delivery() {
  let (mut client, mut server) = pair();
  // Ping + Text land in the server's pipe before it polls once.
  client.ping(b"are-you-there").await.unwrap();
  client.send_text("data").await.unwrap();
  let m = server.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("data".into()));
  // The Pong must already be on the wire — the client sees it without
  // any further server polls (RFC 6455 §5.5.3 "as soon as practical").
  let outcome = compio::time::timeout(std::time::Duration::from_millis(100), client.next()).await;
  assert!(outcome.is_err(), "no data message surfaces on the client");
  assert_eq!(client.pongs_seen(), 1, "the pong reached the client");
}

#[compio::test]
async fn close_budget_starts_at_flush_not_at_batching() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // Bounded pipe; 64 KiB of queued data and the Close coalesce into ONE
  // carrying batch. The protocol arms its deadline when the Close drains
  // into the batch (t≈0); the raw peer drains at t≈100ms (a slow flush,
  // within the flush bound) and echoes at t≈250ms — past the protocol's
  // 200ms deadline but within flush+budget. Without the driver
  // re-anchoring the budget at flush, the echo is misreported unclean.
  let (c, s) = duplex_with_capacity(4 * 1024);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(200)),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  // Enqueue 64 KiB without waiting for delivery (cancel after the first
  // poll: the frame stays queued), then close — one carrying batch.
  {
    use std::future::Future;
    let payload = vec![0xDD_u8; 64 * 1024];
    let mut fut = Box::pin(cwrite.send_binary(&payload));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  let closer = compio_runtime::spawn(async move {
    cwrite.close(CloseCode::Normal, "bye").await.unwrap();
  });
  let reader = compio_runtime::spawn(async move {
    while let Some(m) = cread.next().await {
      m.unwrap();
    }
    cread
  });
  // The raw peer: drains from t≈100ms on, echoes a bare unmasked
  // Close(1000) frame at t≈250ms.
  let (mut sr, mut sw) = s.split();
  let drainer = compio_runtime::spawn(async move {
    compio::time::sleep(std::time::Duration::from_millis(100)).await;
    loop {
      let compio_buf::BufResult(res, _buf) = sr.read(Vec::with_capacity(16 * 1024)).await;
      match res {
        Ok(0) | Err(_) => break,
        Ok(_) => {}
      }
    }
  });
  let echoer = compio_runtime::spawn(async move {
    compio::time::sleep(std::time::Duration::from_millis(250)).await;
    let frame = vec![0x88, 0x02, 0x03, 0xE8]; // FIN Close, len 2, code 1000
    let compio_buf::BufResult(res, _buf) = sw.write(frame).await;
    res.unwrap();
    sw
  });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the close marker flushes once the peer drains")
    .unwrap();
  let cread = compio::time::timeout(std::time::Duration::from_secs(2), reader)
    .await
    .expect("the reader runs to completion")
    .unwrap();
  assert!(
    cread.closed().unwrap().clean(),
    "an echo within flush+budget is clean"
  );
  drop(echoer.await);
  drop(drainer.await);
}

#[compio::test]
async fn close_times_out_when_the_peer_never_drains() {
  use std::future::Future;

  // Local rather than a module helper: this is the only test that needs it,
  // and a free function here would have to live beside code later commits add.
  fn timed_out(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut)
  }

  // The peer stops reading entirely: the carrying batch can never flush.
  // close_timeout must still bound the handshake — the flush phase gets
  // the budget, then everything fails and the transport tears down.
  //
  // **Either task may be the one that OBSERVES the timeout, and the test may
  // not assume which.** `close_flush_timed_out` fails every queued frame
  // first, so the closer always learns through its own frame state; what
  // varies is its RETURN, which goes to whoever is inside the pump — and only
  // the reader drives the pump here, because a split `close()` enqueues and
  // awaits rather than driving. Its two arms differ in what the reader sees:
  //
  // - `handle_timeout` produced a verdict (the Close had drained into a batch
  //   before the budget expired): the outcome is PUBLISHED, the arm answers
  //   `None`, and the reader's stream simply ends.
  // - it did not (the Close never drained): `terminate_io` poisons and the arm
  //   answers `Some(Err(TimedOut))`, which the reader receives.
  //
  // Which one fires is a race between the budget and the wedged pipe, and CI
  // took the second arm on a shape that had always taken the first. So the
  // reader treats the timeout as a terminal OBSERVATION rather than unwrapping
  // it, and the assertions below name what is true on each arm — including
  // that `closed()` is `None` on the second, because `terminate_io` records
  // poison rather than an outcome (see S-C1 in the report).
  let (c, _wedged_peer) = duplex_with_capacity(4 * 1024);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(100)),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  {
    let payload = vec![0xEE_u8; 64 * 1024];
    let mut fut = Box::pin(cwrite.send_binary(&payload));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "bye").await });
  let reader = compio_runtime::spawn(async move {
    let mut observed = None;
    while let Some(m) = cread.next().await {
      if let Err(e) = m {
        // The timeout is the terminal observation; anything else is a real
        // failure and still fails the test.
        assert!(
          timed_out(&e),
          "the only error this scenario may produce is the flush timeout, got {e:?}"
        );
        observed = Some(e);
        break;
      }
    }
    (cread, observed)
  });
  let close_result = compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the close resolves within the budget")
    .unwrap();
  let (cread, reader_observed) = compio::time::timeout(std::time::Duration::from_secs(2), reader)
    .await
    .expect("the reader observes the outcome")
    .unwrap();

  let closer_timed_out = close_result.as_ref().err().is_some_and(timed_out);
  assert!(
    closer_timed_out || reader_observed.as_ref().is_some_and(timed_out),
    "one of the two tasks must have seen the flush timeout; closer={close_result:?} \
     reader={reader_observed:?}"
  );
  match cread.closed() {
    // The arm that had a protocol verdict publishes the outcome and ends the
    // reader's stream; a never-draining peer is never a clean close.
    Some(closed) => assert!(!closed.clean(), "a never-draining peer is an unclean close"),
    // The arm that had none records poison instead, and poison is not an
    // outcome — so `closed()` stays `None`, and the ONLY way that is allowed
    // is the reader having received the error that says so.
    None => assert!(
      reader_observed.is_some(),
      "no recorded outcome is only permitted on the arm that returned the timeout to the reader"
    ),
  }
}

#[compio::test]
async fn dropping_read_half_drops_the_transport() {
  let (mut client, server) = pair();
  let (sread, _swrite) = server.split();
  drop(sread);
  // The write half stays alive, but with the pump gone the transport is
  // torn down: the peer must observe EOF rather than a parked forever.
  let outcome = compio::time::timeout(std::time::Duration::from_secs(2), client.next())
    .await
    .expect("the peer observes the teardown");
  let err = outcome.unwrap().unwrap_err();
  assert!(matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof));
}

#[compio::test]
async fn a_post_close_pong_flush_is_bounded_by_the_remaining_echo_budget() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // Built from `close_budget_starts_at_flush_not_at_batching`, which is the
  // test that reliably gets a Close FLUSHED through a bounded pipe. Once it is
  // flushed, `close_owed` is discharged and `close_flushed_at` is anchored — and a
  // peer Ping arriving then produces a Pong-only batch with
  // `carries_close == false`. The old two-way timer choice parked exactly that
  // batch on `pending()`, so a peer that stops reading wedges it forever and the
  // bound `close_timeout` documents is defeated. Nothing on `main` reached here:
  // post-Close Pongs were suppressed, and this branch created the case.
  //
  // The pipe is 64 bytes: the 4 KiB carrying batch still drains through it (the
  // drainer just reads more times), but the ten 10-byte masked Pongs the driver
  // owes (100 bytes) cannot fit once the peer stops reading. 4 KiB rather than
  // the model's 64 KiB because every byte of it crosses a 64-byte pipe one
  // read at a time, and a drain that does not finish inside the close budget
  // fails this test on a loaded machine for a reason it is not about.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  // A masked client Pong for a 4-byte payload: 2 header + 4 mask key + 4.
  const PONG_LEN: usize = 10;

  let (c, s) = duplex_with_capacity(PIPE_CAPACITY);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(200)),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();

  // Queued without waiting for delivery, then the Close: one carrying batch,
  // exactly as the model test builds it.
  {
    use std::future::Future;
    let payload = vec![0xDD_u8; 4 * 1024];
    let mut fut = Box::pin(cwrite.send_binary(&payload));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "bye").await });
  let reader = compio_runtime::spawn(async move {
    let mut ended = None;
    while let Some(m) = cread.next().await {
      if let Err(e) = m {
        ended = Some(e);
        break;
      }
    }
    (ended, cread)
  });

  let (mut sr, mut sw) = s.split();
  // Drain until the pipe stays EMPTY for 50 ms: an elapsed read is how this
  // harness learns the carrying batch is fully drained and the Close has
  // flushed. The task hands `sr` back and the test holds it to the end —
  // dropping it would EOF the client and turn the wedge into a BrokenPipe,
  // which is not the defect under test.
  let drainer = compio_runtime::spawn(async move {
    loop {
      match compio::time::timeout(
        std::time::Duration::from_millis(50),
        sr.read(Vec::with_capacity(16 * 1024)),
      )
      .await
      {
        Err(_elapsed) => break,
        Ok(compio_buf::BufResult(Ok(0) | Err(_), _)) => break,
        Ok(compio_buf::BufResult(Ok(_), _)) => {}
      }
    }
    sr
  });
  let mut sr = compio::time::timeout(std::time::Duration::from_secs(5), drainer)
    .await
    .expect("the carrying batch drains")
    .unwrap();
  // The quiet window above is a heuristic; THIS is the fact the rest of the
  // test rests on. `WriteHalf::close` resolves when the batch carrying the
  // Close reaches the wire, so an `Ok` here says `close_flushed_at` is anchored
  // and the third bound — the remaining echo budget — is the one under test.
  // Without it a scheduling pause could leave the original close-carrying batch
  // still in flight, and the FIRST bound would produce the timeout asserted
  // below.
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes once the peer drains")
    .unwrap()
    .expect("the Close flushes once the peer drains");

  // From here the peer never reads again. The Close is on the wire and the echo
  // budget is running.
  let t0 = std::time::Instant::now();
  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let sent = pings.len();
  assert!(
    sent <= PIPE_CAPACITY,
    "the pings fit the pipe, so one write takes all of them"
  );
  let compio_buf::BufResult(written, _) = sw.write(pings).await;
  assert_eq!(
    written.expect("the pings"),
    sent,
    "a short write would leave too few pongs owed to block the batch"
  );

  // Ten owed Pongs coalesce into one post-Close batch of 100 bytes, which
  // cannot fit, so the write wedges with `carries_close == false` and
  // `close_owed == None` — Codex's path exactly.
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the owed Pongs must not fit what is left of the pipe"
    );
  }
  let (ended, cread) = compio::time::timeout(std::time::Duration::from_secs(2), reader)
    .await
    .expect(
      "a post-Close Pong flush is bounded by the REMAINING echo budget \
       (`close_flushed_at + close_budget`), not parked unbounded because the \
       batch carries no Close and `close_owed` is already discharged",
    )
    .unwrap();
  let elapsed = t0.elapsed();

  // The outcome is a RECORDED unclean close, not `Err(TimedOut)`, and the
  // difference is `close_flush_timed_out`'s own branch: it asks the protocol
  // for a verdict first, and here there is one — our Close drained into a batch
  // and its deadline elapsed — so it publishes that verdict and surfaces no
  // error. `close_during_a_wedged_plain_flush_is_still_bounded` sees
  // `Err(TimedOut)` because there the Close never reached a batch and the
  // protocol has no verdict to give. Both are the same teardown; only this
  // scenario has something for the protocol to say.
  assert!(
    ended.is_none(),
    "the teardown publishes the protocol's verdict rather than an error: {ended:?}"
  );
  let closed = cread
    .closed()
    .expect("the wedged post-Close write must end the connection");
  assert!(
    !closed.clean(),
    "a Close whose echo never arrived is not a clean close"
  );
  assert!(
    elapsed < std::time::Duration::from_millis(500),
    "within the 200 ms budget plus slack, not merely eventually: {elapsed:?}"
  );

  // The wire says the batch was ABANDONED at the bound rather than completed
  // after it: the peer holds exactly what fit before the write blocked, and it
  // starts at a Pong. Both numbers come from the two constants above — widen
  // `PIPE_CAPACITY` past `PINGS * PONG_LEN` and the whole batch fits, no write
  // ever blocks, and this is the assertion that says so (the timeout ones do
  // not: a normal Phase 4 close deadline satisfies them just as well).
  let mut tail = Vec::new();
  loop {
    match compio::time::timeout(
      std::time::Duration::from_millis(200),
      sr.read(Vec::with_capacity(4096)),
    )
    .await
    {
      Err(_elapsed) => break,
      Ok(compio_buf::BufResult(Ok(0) | Err(_), _)) => break,
      Ok(compio_buf::BufResult(Ok(n), buf)) => tail.extend_from_slice(buf.get(..n).unwrap_or(&[])),
    }
  }
  assert_eq!(
    tail.len(),
    PIPE_CAPACITY,
    "only what fit before the write blocked, not all {} Pong bytes",
    PINGS * PONG_LEN
  );
  assert_eq!(
    tail.first().copied(),
    Some(0x8A),
    "the wedged prefix starts at the first Pong: {:02x?}",
    tail.get(..8).unwrap_or(&[])
  );
}

#[compio::test]
async fn close_during_a_wedged_plain_flush_is_still_bounded() {
  use std::future::Future;

  // The pump is ALREADY parked flushing a plain 64 KiB batch to a peer
  // that never drains when close() arrives: the doorbell must interrupt
  // the unbounded flush so the close budget takes over.
  let (c, _wedged_peer) = duplex_with_capacity(4 * 1024);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(100)),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  {
    let payload = vec![0xAB_u8; 64 * 1024];
    let mut fut = Box::pin(cwrite.send_binary(&payload));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  // The reader task starts the (plain, unbounded) flush first…
  let reader = compio_runtime::spawn(async move {
    let outcome = cread.next().await;
    (outcome, cread)
  });
  compio::time::sleep(std::time::Duration::from_millis(30)).await;
  // …and only then does the close arrive.
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "bye").await });
  let close_err = compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the close resolves within the budget despite the running flush")
    .unwrap()
    .unwrap_err();
  assert!(matches!(&close_err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut));
  let (outcome, _cread) = compio::time::timeout(std::time::Duration::from_secs(2), reader)
    .await
    .expect("the reader observes the outcome")
    .unwrap();
  let err = outcome.unwrap().unwrap_err();
  assert!(matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut));
}

#[compio::test]
async fn peer_close_is_not_clean_when_the_echo_fails() {
  use compio_io::{AsyncWrite as _, util::Splittable as _};
  use std::future::Future;

  // The peer sends a clean Close, but the carrying batch (64 KiB of
  // queued data + the echo) dies on a transport fault. The connection
  // must NOT report a clean close whose echo never reached the wire.
  let (s, c) = duplex_with_write_fault(4 * 1024);
  let negotiated = Negotiated::none();
  let server = WebSocket::<ServerRole, _>::server(
    s.into_duplex(),
    &negotiated,
    &crate::options::AcceptOptions::default(),
    Vec::new(),
  );
  let (mut sread, mut swrite) = server.split();
  // Park the pump FIRST: the data enqueue and the peer's Close both land
  // while it waits, so one resumed pass reads the Close and coalesces
  // [64 KiB data][echo] into a single carrying batch.
  let mut pump = Box::pin(sread.next());
  futures_util::future::poll_fn(|cx| {
    assert!(pump.as_mut().poll(cx).is_pending());
    std::task::Poll::Ready(())
  })
  .await;
  {
    let payload = vec![0xCC_u8; 64 * 1024];
    let mut fut = Box::pin(swrite.send_binary(&payload));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  // Raw peer: deliver a masked Close(1000) (all-zero mask key) and keep
  // its read half alive.
  let (_cr, mut cw) = c.split();
  let frame = vec![0x88, 0x82, 0, 0, 0, 0, 0x03, 0xE8];
  let compio_buf::BufResult(res, _buf) = cw.write(frame).await;
  res.unwrap();

  let err = compio::time::timeout(std::time::Duration::from_secs(2), pump.as_mut())
    .await
    .expect("the failed echo flush surfaces")
    .unwrap()
    .unwrap_err();
  assert!(matches!(&err, Error::Io(_)), "transport fault, got {err:?}");
  drop(pump);
  assert!(
    sread.closed().is_none_or(|c| !c.clean()),
    "a close whose echo never flushed must not read as clean, got {:?}",
    sread.closed()
  );
}

/// Delegates everything except `poll_close`, which never completes —
/// models a TLS close_notify wedged behind a peer that stopped reading.
struct NeverCloses<D>(D);

impl<D: futures_util::AsyncRead + Unpin> futures_util::AsyncRead for NeverCloses<D> {
  fn poll_read(
    mut self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &mut [u8],
  ) -> std::task::Poll<std::io::Result<usize>> {
    std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
  }
}

impl<D: futures_util::AsyncWrite + Unpin> futures_util::AsyncWrite for NeverCloses<D> {
  fn poll_write(
    mut self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &[u8],
  ) -> std::task::Poll<std::io::Result<usize>> {
    std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
  }

  fn poll_flush(
    mut self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    std::pin::Pin::new(&mut self.0).poll_flush(cx)
  }

  fn poll_close(
    self: std::pin::Pin<&mut Self>,
    _cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    std::task::Poll::Pending
  }
}

impl IntoDuplex for NeverCloses<PipeDuplex> {
  type Duplex = Self;

  fn into_duplex(self) -> Self::Duplex {
    self
  }
}

#[compio::test]
async fn teardown_is_bounded_when_close_notify_wedges() {
  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    NeverCloses(c.into_duplex()).into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(100)),
    Vec::new(),
  );
  let mut server = WebSocket::<ServerRole, _>::server(
    s.into_duplex(),
    &negotiated,
    &crate::options::AcceptOptions::default(),
    Vec::new(),
  );
  let server_task = compio_runtime::spawn(async move {
    assert!(server.next().await.is_none());
    assert!(server.closed().unwrap().clean());
  });
  // The close handshake itself completes; only the transport's own
  // close (close_notify) wedges. close() must still resolve.
  let closed = compio::time::timeout(
    std::time::Duration::from_secs(2),
    client.close(CloseCode::Normal, "bye"),
  )
  .await
  .expect("teardown is bounded by the close budget")
  .unwrap();
  assert!(closed.clean());
  server_task.await.unwrap();
}

#[compio::test]
async fn write_error_poisons_the_connection() {
  // The transport accepts 4 KiB, fails one write, then recovers — like a
  // socket whose send buffer hiccups after a partial frame went out.
  let (c, s) = duplex_with_write_fault(4 * 1024);
  let negotiated = Negotiated::none();
  let mut client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default(),
    Vec::new(),
  );
  let _server = WebSocket::<ServerRole, _>::server(
    s.into_duplex(),
    &negotiated,
    &crate::options::AcceptOptions::default(),
    Vec::new(),
  );

  let payload = vec![0xAA_u8; 64 * 1024];
  let err = client.send_binary(&payload).await.unwrap_err();
  let Error::Io(first) = err else {
    panic!("write fault surfaces as Io, got {err:?}");
  };
  // A partial frame is on the wire; even though the transport recovered,
  // nothing may be spliced after it.
  let err = client.send_text("tail").await.unwrap_err();
  assert!(
    matches!(&err, Error::Io(e) if e.kind() == first.kind()),
    "second send is refused with the poisoned kind, got {err:?}"
  );
  let err = client.next().await.unwrap().unwrap_err();
  assert!(matches!(&err, Error::Io(e) if e.kind() == first.kind()));
}

#[compio::test]
async fn write_half_close_drives_through_reader() {
  let (mut client, server) = pair();
  let (mut sread, mut swrite) = server.split();
  let reader = compio_runtime::spawn(async move {
    while sread.next().await.is_some() {}
    sread
  });
  swrite.close(CloseCode::Normal, "done").await.unwrap();
  // The client observes the close handshake cleanly.
  assert!(client.next().await.is_none());
  let closed = client.closed().unwrap();
  assert_eq!(closed.code(), CloseCode::Normal);
  let sread = reader.await.unwrap();
  assert!(sread.closed().unwrap().clean());
}

#[compio::test]
async fn a_close_budget_that_overflows_the_clock_does_not_panic() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // `with_close_timeout` takes any `Duration`, and `Duration::MAX` is a
  // representable duration whose SUM with an `Instant` is not. Every deadline
  // this driver computes after the Close flushed is therefore an overflow
  // waiting for a peer Ping: the post-Close write bound read
  // `close_flushed_at + close_budget` with the panicking `Instant::Add`, and
  // the timer it hands the answer to adds `Instant::now()` to it a second
  // time. A budget the caller is allowed to configure must not kill the
  // process, and an unreachable deadline is one that can never fire.
  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(std::time::Duration::MAX),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "bye").await });

  let (mut sr, mut sw) = s.split();
  let peer = compio_runtime::spawn(async move {
    // 1. Our Close reaches the wire: `close_flushed_at` is now anchored and
    //    every post-Close deadline is `anchor + Duration::MAX`.
    let compio_buf::BufResult(res, close_bytes) = sr.read(Vec::with_capacity(64)).await;
    let n = res.expect("the client's Close");
    // 2. A Ping the client still owes a Pong for (§5.5.2 keeps it owed until a
    //    Close is RECEIVED, and none has been).
    let compio_buf::BufResult(res, _) = sw.write(vec![0x89_u8, 0x00]).await;
    res.expect("the peer's ping");
    // 3. The Pong — the batch whose bound overflowed.
    let compio_buf::BufResult(res, pong) = sr.read(Vec::with_capacity(64)).await;
    let m = res.expect("the client's Pong");
    // 4. The peer's Close ends the handshake so the pump can finish.
    let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
    res.expect("the peer's Close");
    (
      close_bytes.get(..n).unwrap_or(&[]).to_vec(),
      pong.get(..m).unwrap_or(&[]).to_vec(),
    )
  });

  let pumped = compio::time::timeout(std::time::Duration::from_secs(5), async {
    while let Some(m) = cread.next().await {
      m.unwrap();
    }
  })
  .await;
  assert!(
    pumped.is_ok(),
    "an unrepresentable deadline can never fire, so the pump parks on the peer rather than on it"
  );
  closer.await.unwrap().expect("the Close flushes");
  let (close_bytes, pong) = peer.await.unwrap();
  assert_eq!(
    close_bytes.first().copied(),
    Some(0x88),
    "the client's Close, masked: {close_bytes:02x?}"
  );
  assert_eq!(
    pong.first().copied(),
    Some(0x8A),
    "the post-Close Pong is written rather than panicked on: {pong:02x?}"
  );
  assert!(
    cread.closed().expect("the handshake completes").clean(),
    "both Closes were exchanged"
  );
}

#[compio::test]
async fn a_ping_storm_cannot_restart_the_close_flush_budget() {
  use std::future::Future;

  // `close_during_a_wedged_plain_flush_is_still_bounded` with one addition:
  // something keeps ringing the doorbell while the Close flush is wedged.
  // Phase 3's `Reconsider` arm restores the partial batch and re-enters the
  // loop, and the close-involved bound used to be recomputed as the WHOLE
  // budget on every such re-entry — so a peer that never drains plus a local
  // sender that rings faster than the budget kept the flush alive forever and
  // `close_timeout` bounded nothing.
  //
  // The ring is a `WriteHalf::ping` that is polled once and dropped:
  // `enqueue` pushes the frame and notifies BEFORE its first await, so an
  // abandoned future still leaves a queued frame and a ring behind it. A Ping
  // in `CloseSent` is legal (§5.5.1 line 2002 bans further *data* frames
  // only), which is what makes this reachable from the public API.
  let (c, _wedged_peer) = duplex_with_capacity(4 * 1024);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(100)),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  // A second write half over the same shared state, because `close()` and
  // `ping()` each want `&mut` and the finding is about a second holder ringing
  // while the first one's Close is wedged. `split()` builds its pair out of
  // exactly these two `Rc` clones.
  let mut pinger = WriteHalf {
    inner: cread.inner.clone(),
    doorbell: cread.doorbell.clone(),
  };
  {
    let payload = vec![0xAB_u8; 64 * 1024];
    let mut fut = Box::pin(cwrite.send_binary(&payload));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  // The reader task starts the (plain, unbounded) flush first…
  let reader = compio_runtime::spawn(async move {
    let outcome = cread.next().await;
    (outcome, cread)
  });
  compio::time::sleep(std::time::Duration::from_millis(30)).await;
  // …then the close arrives and the budget starts.
  let t0 = std::time::Instant::now();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "bye").await });
  let storm = compio_runtime::spawn(async move {
    for _ in 0..200u32 {
      let mut fut = Box::pin(pinger.ping(b"x"));
      futures_util::future::poll_fn(|cx| {
        let _ = fut.as_mut().poll(cx);
        std::task::Poll::Ready(())
      })
      .await;
      drop(fut);
      compio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
  });
  let close_err = compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("a doorbell must not hand the wedged flush another budget")
    .unwrap()
    .unwrap_err();
  let elapsed = t0.elapsed();
  assert!(
    matches!(&close_err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
    "the wedged close still fails with the timeout, got {close_err:?}"
  );
  assert!(
    elapsed < std::time::Duration::from_millis(600),
    "the bound runs from the close REQUEST, not from the last doorbell: {elapsed:?}"
  );
  let (outcome, _cread) = compio::time::timeout(std::time::Duration::from_secs(2), reader)
    .await
    .expect("the reader observes the outcome")
    .unwrap();
  let err = outcome.unwrap().unwrap_err();
  assert!(matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut));
  drop(storm);
}

#[compio::test]
async fn a_queued_ping_is_not_written_after_both_close_frames() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};
  use std::future::Future;

  // Our Close has flushed and the pump is parked. The peer's Close and a
  // locally queued Ping then become ready together: Phase 4's `select_biased!`
  // is read-biased, so the Close is processed first and the handshake is
  // complete — §5.5.1 (line 2023 of `.rfc-cache/rfc6455.txt`) says the
  // connection is closed and the TCP connection MUST be closed, so nothing
  // more may go out. Phase 2 nevertheless drained the queued Ping, labelled
  // the batch `carries_close` from the driver's own "a close is owed" flag
  // although the protocol had no Close left to give, wrote the Ping past the
  // completed handshake, told its sender it succeeded, and treated that flush
  // as the Close's.
  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default(),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  // A second write half, because `close()` and `ping()` each want `&mut` and
  // this is a race between two senders (see the ping-storm regression).
  let mut pinger = WriteHalf {
    inner: cread.inner.clone(),
    doorbell: cread.doorbell.clone(),
  };
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let reader = compio_runtime::spawn(async move {
    let mut ended = None;
    while let Some(m) = cread.next().await {
      if let Err(e) = m {
        ended = Some(e);
        break;
      }
    }
    (ended, cread)
  });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes")
    .unwrap()
    .expect("the Close flushes");
  // The pump ran to its Phase 4 park to publish that flush, so it is parked
  // now.
  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, ours) = sr.read(Vec::with_capacity(64)).await;
  let n = res.expect("the peer drains our Close");
  assert_eq!(
    ours.get(..n).and_then(<[u8]>::first).copied(),
    Some(0x88),
    "our Close, masked: {:02x?}",
    ours.get(..n).unwrap_or(&[])
  );

  // Both of these complete without yielding — the pipe write takes its ready
  // path and `enqueue` pushes and notifies before its first await — so the
  // parked pump sees the peer's Close AND the queued Ping on the same wakeup.
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the peer's Close");
  // Cloned before the ping future borrows `pinger`, so the premise below can
  // still be read.
  let probe = pinger.inner.clone();
  let mut ping = Box::pin(pinger.ping(b"hi"));
  futures_util::future::poll_fn(|cx| {
    assert!(ping.as_mut().poll(cx).is_pending());
    std::task::Poll::Ready(())
  })
  .await;

  // The premise, asserted rather than assumed: neither of the two operations
  // above yields, so the pump has not run since. If a scheduling change ever
  // breaks that, this reds here instead of passing for the wrong reason.
  {
    let state = probe.borrow();
    assert!(
      state.closed.is_none(),
      "the peer's Close must still be unprocessed"
    );
    assert_eq!(state.outbound.len(), 1, "the Ping is queued behind it");
    assert!(
      state.inbound.is_empty(),
      "the peer's Close is still in the pipe, not in the driver"
    );
  }

  // Now let the reader run.
  let (ended, cread) = compio::time::timeout(std::time::Duration::from_secs(2), reader)
    .await
    .expect("the peer's Close completes the handshake")
    .unwrap();
  assert!(
    ended.is_none(),
    "a completed handshake is not an error: {ended:?}"
  );
  let after = compio::time::timeout(
    std::time::Duration::from_millis(100),
    sr.read(Vec::with_capacity(64)),
  )
  .await;
  let bytes = match after {
    Err(_elapsed) => Vec::new(),
    Ok(compio_buf::BufResult(Ok(n), buf)) => buf.get(..n).unwrap_or(&[]).to_vec(),
    Ok(compio_buf::BufResult(Err(_), _)) => Vec::new(),
  };
  assert!(
    bytes.is_empty(),
    "nothing may be written after both Close frames, got {bytes:02x?}"
  );
  let ping_result = ping.await;
  assert!(
    matches!(&ping_result, Err(Error::Closed)),
    "the frame the handshake overtook is refused, not reported written: {ping_result:?}"
  );
  assert!(
    cread.closed().expect("the handshake completes").clean(),
    "both Closes were exchanged"
  );
}

#[compio::test]
async fn a_peer_close_reaches_the_pump_through_a_wedged_post_close_write() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // The post-Close Pong wedge of
  // `a_post_close_pong_flush_is_bounded_by_the_remaining_echo_budget`, with the
  // peer FINISHING the handshake instead of going silent. The two transport
  // directions are independent, so the peer's Close is readable the instant it
  // is written while the Pong batch is still blocked. Phase 3 polled only the
  // write, the timer and the doorbell, so those bytes sat unread until the
  // remaining echo budget expired and a handshake that completed at once was
  // reported unclean at the deadline.
  //
  // No queued payload and no drainer here: that test needs a SLOW flush to
  // pin where the budget starts, and this one needs only a flushed Close, so
  // the Close goes out on its own and the peer takes it in one read. What is
  // left is the wedge itself.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  // A masked client Pong for a 4-byte payload: 2 header + 4 mask key + 4.
  const PONG_LEN: usize = 10;
  // A masked client Close carrying a code and no reason: 2 + 4 + 2.
  const CLOSE_LEN: usize = 8;
  const BUDGET: std::time::Duration = std::time::Duration::from_millis(200);

  let (c, s) = duplex_with_capacity(PIPE_CAPACITY);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  // Shared state, read from the test to learn WHEN the Pong batch is wedged:
  // the pump has no await between counting the last Ping and blocking on the
  // Pong write, so `pings_seen == PINGS` observed from another task means the
  // write is blocked. A sleep would only guess at that.
  let probe = cread.inner.clone();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let reader = compio_runtime::spawn(async move {
    let mut ended = None;
    while let Some(m) = cread.next().await {
      if let Err(e) = m {
        ended = Some(e);
        break;
      }
    }
    (ended, cread)
  });
  // `WriteHalf::close` resolves when the batch carrying the Close reaches the
  // wire, so an `Ok` here says `close_flushed_at` is anchored and the bound
  // under test is the third one, the remaining echo budget.
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes")
    .unwrap()
    .expect("the Close flushes");
  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  let n = res.expect("the peer drains our Close");
  assert_eq!(
    ours.get(..n).and_then(<[u8]>::first).copied(),
    Some(0x88),
    "our Close, masked: {:02x?}",
    ours.get(..n).unwrap_or(&[])
  );
  assert_eq!(
    n, CLOSE_LEN,
    "the whole pipe is free for the Pong batch that follows"
  );

  // From here the peer never reads again, and the echo budget is running.
  let t0 = std::time::Instant::now();
  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let sent = pings.len();
  assert!(sent <= PIPE_CAPACITY, "the pings fit the pipe in one write");
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  assert_eq!(
    res.expect("the pings"),
    sent,
    "every ping reaches the driver"
  );
  // A bounded WAIT, not a snapshot: the pump has no await between counting the
  // last Ping and blocking on the Pong write, so this condition means the write
  // is blocked — but only once it holds, and when it never does the failure has
  // to name the count it saw rather than a timing coincidence.
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }
  // `PINGS * PONG_LEN` bytes of Pongs cannot fit `PIPE_CAPACITY`, so the batch
  // is wedged now. The peer's Close goes the other way, where there is room.
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch cannot fit"
    );
  }
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the peer's Close");

  // The OUTCOME is what this bounds, so it is timed where it is RECORDED. What
  // follows it — the teardown's close_notify against the same wedged peer —
  // has its own budget and its own regression
  // (`teardown_is_bounded_when_close_notify_wedges`), so timing the reader's
  // return would measure that one instead.
  let mut recorded = None;
  while recorded.is_none() {
    assert!(
      t0.elapsed() < BUDGET * 2,
      "the peer's Close was readable at once; the pump must not park forever"
    );
    compio::time::sleep(std::time::Duration::from_millis(1)).await;
    recorded = probe.borrow().closed;
  }
  let elapsed = t0.elapsed();
  let closed = recorded.expect("checked by the loop");
  assert!(
    closed.clean(),
    "the peer's Close arrived on the inbound direction while the outbound one was wedged, \
     yet the outcome is {closed:?} after {elapsed:?}"
  );
  assert!(
    elapsed < BUDGET / 2,
    "the handshake completed at once, not at the deadline: {elapsed:?}"
  );

  let (ended, cread) = compio::time::timeout(std::time::Duration::from_secs(5), reader)
    .await
    .expect("the reader runs to completion")
    .unwrap();
  assert!(
    ended.is_none(),
    "a completed handshake is not an error: {ended:?}"
  );
  assert_eq!(
    cread.closed(),
    Some(closed),
    "the reader reports the outcome the pump recorded"
  );

  // The wedged prefix, and nothing more: the Pong batch was abandoned at the
  // completed handshake rather than finished after it.
  let mut tail = Vec::new();
  loop {
    match compio::time::timeout(
      std::time::Duration::from_millis(200),
      sr.read(Vec::with_capacity(4096)),
    )
    .await
    {
      Err(_elapsed) => break,
      Ok(compio_buf::BufResult(Ok(0) | Err(_), _)) => break,
      Ok(compio_buf::BufResult(Ok(n), buf)) => tail.extend_from_slice(buf.get(..n).unwrap_or(&[])),
    }
  }
  assert_eq!(
    tail.len(),
    PIPE_CAPACITY,
    "only what fit before the write blocked, not all {} Pong bytes",
    PINGS * PONG_LEN
  );
  assert_eq!(
    tail.first().copied(),
    Some(0x8A),
    "the wedged prefix starts at the first Pong: {:02x?}",
    tail.get(..8).unwrap_or(&[])
  );
}

#[compio::test]
async fn a_spent_budget_refuses_a_write_that_was_ready_to_go() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // F7 on its own. `select_biased!` polls the drive before the timer, so a
  // bound that has already reached zero still lets an immediately ready write
  // complete: the deadline is a boundary only because zero remaining resolves
  // to `FlushArm::Budget` BEFORE the drive is polled. Every other close
  // regression WEDGES its write, and a wedged write cannot tell the two orders
  // apart — the drive is `Pending` either way.
  //
  // So this pipe has room and the batch would go out at once. The driver's
  // echo anchor is moved into the past BY HAND, and that is what isolates the
  // arm: the protocol's own close deadline stays in the future, so
  // `effective_deadline` — the later of the two — has NOT elapsed and Phase
  // 1's settle does not fire. The only thing that is spent is Phase 3's arm-2
  // deadline.
  //
  // It is also the "already expired when the first poll happens" case, which
  // is why it is the test the in-poll deadline check is measured against:
  // deleting Phase 3's pre-entry short-circuit leaves this green, and did not
  // before that check existed. A case where the deadline passes BETWEEN the
  // pre-entry check and the first poll cannot be built deterministically —
  // nothing can advance the clock between two adjacent statements — so this
  // one stands in for it, with the pre-entry check removed.
  const BUDGET: std::time::Duration = std::time::Duration::from_millis(200);

  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let reader = compio_runtime::spawn(async move {
    let mut ended = None;
    while let Some(m) = cread.next().await {
      if let Err(e) = m {
        ended = Some(e);
        break;
      }
    }
    (ended, cread)
  });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes")
    .unwrap()
    .expect("the Close flushes");
  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, ours) = sr.read(Vec::with_capacity(64)).await;
  let n = res.expect("the peer drains our Close");
  assert_eq!(
    ours.get(..n).and_then(<[u8]>::first).copied(),
    Some(0x88),
    "our Close, masked: {:02x?}",
    ours.get(..n).unwrap_or(&[])
  );

  // The pump is parked here, so nothing else holds the borrow: move its echo
  // anchor a whole budget into the past.
  {
    let mut guard = probe.borrow_mut();
    guard.close_flushed_at = Some(
      std::time::Instant::now()
        .checked_sub(BUDGET + std::time::Duration::from_millis(50))
        .expect("the test clock is far enough past the epoch"),
    );
  }
  // One Ping, so a Pong batch is built and enters Phase 3 under arm 2 with
  // nothing left of the budget and a transport that would take it at once.
  let compio_buf::BufResult(res, _) = sw.write(vec![0x89_u8, 0x00]).await;
  res.expect("the peer's ping");

  let (ended, _cread) = compio::time::timeout(std::time::Duration::from_secs(2), reader)
    .await
    .expect("a spent budget ends the connection")
    .unwrap();
  let mut tail = Vec::new();
  loop {
    match compio::time::timeout(
      std::time::Duration::from_millis(200),
      sr.read(Vec::with_capacity(64)),
    )
    .await
    {
      Err(_elapsed) => break,
      Ok(compio_buf::BufResult(Ok(0) | Err(_), _)) => break,
      Ok(compio_buf::BufResult(Ok(n), buf)) => tail.extend_from_slice(buf.get(..n).unwrap_or(&[])),
    }
  }
  assert!(
    tail.is_empty(),
    "the budget was spent before the drive was polled, so nothing may reach the wire: {tail:02x?}"
  );
  assert!(
    matches!(&ended, Some(Error::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut),
    "a spent budget tears down; it does not write and then notice: {ended:?}"
  );
}

#[compio::test]
async fn a_recorded_outcome_discards_the_batch_it_finds_rather_than_writing_it() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};
  use std::future::Future;

  // Phase 4 cannot meet a recorded outcome — the terminal check returns before
  // it parks — but Phase 3 could: Phase 1's settle records an unclean close
  // and Phase 3 then finds a Pong batch left over from a cancelled pass and
  // treats it as live. §5.5.1 (line 2023 of `.rfc-cache/rfc6455.txt`) and the
  // elapsed deadline both say that batch is moot, so it is discarded and the
  // recorded outcome is what the pump reports.
  //
  // The batch is left over rather than built here: `next_message` is polled
  // ONCE and dropped, which is the documented cancellation path — the guard
  // restores the partial batch into `Inner` instead of losing it.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  // A masked client Pong for a 4-byte payload: 2 header + 4 mask key + 4.
  const PONG_LEN: usize = 10;
  // A masked client Close carrying a code and no reason: 2 + 4 + 2.
  const CLOSE_LEN: usize = 8;
  const BUDGET: std::time::Duration = std::time::Duration::from_millis(30);
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
  }

  let (c, s) = duplex_with_capacity(PIPE_CAPACITY);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  // Queue the Close without waiting for it: the marker frame stays queued and
  // the pump coalesces it with the Close on its next pass.
  {
    let mut fut = Box::pin(cwrite.close(CloseCode::Normal, ""));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  // One pass puts it on the wire.
  {
    let mut fut = Box::pin(cread.next());
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  assert!(
    probe.borrow().close_flushed_at.is_some(),
    "the Close reached the wire, so the echo budget is running"
  );

  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(
    res.expect("the peer drains our Close"),
    CLOSE_LEN,
    "the whole pipe is free for the Pong batch that follows"
  );

  // The peer stops reading here. Ten Pings owe `PINGS * PONG_LEN` bytes of
  // Pongs; only `PIPE_CAPACITY` of them can land.
  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let sent = pings.len();
  assert!(sent <= PIPE_CAPACITY, "the pings fit the pipe in one write");
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  assert_eq!(
    res.expect("the pings"),
    sent,
    "every ping reaches the driver"
  );

  // ONE poll reads them, builds the batch and wedges it; dropping the future
  // parks the partial batch rather than losing it.
  {
    let mut fut = Box::pin(cread.next());
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  assert!(
    probe.borrow().pending_write.is_some(),
    "the cancelled pass parked its partial batch"
  );

  // Past the budget, so the NEXT pass records the outcome in Phase 1 — before
  // Phase 3 ever looks at that batch.
  compio::time::sleep(BUDGET * 2).await;
  let outcome = compio::time::timeout(std::time::Duration::from_secs(2), cread.next())
    .await
    .expect("the pump settles rather than parking");
  assert!(
    outcome.is_none(),
    "the outcome was recorded before Phase 3 ran; the pump reports it rather than \
     the moot batch's own timeout: {outcome:?}"
  );
  let closed = cread.closed().expect("the settle recorded an outcome");
  assert!(!closed.clean(), "no echo ever arrived: {closed:?}");

  let mut tail = Vec::new();
  loop {
    match compio::time::timeout(
      std::time::Duration::from_millis(200),
      sr.read(Vec::with_capacity(4096)),
    )
    .await
    {
      Err(_elapsed) => break,
      Ok(compio_buf::BufResult(Ok(0) | Err(_), _)) => break,
      Ok(compio_buf::BufResult(Ok(n), buf)) => tail.extend_from_slice(buf.get(..n).unwrap_or(&[])),
    }
  }
  assert_eq!(
    tail.len(),
    PIPE_CAPACITY,
    "only what the cancelled pass had already written, not all {} Pong bytes",
    PINGS * PONG_LEN
  );
}

/// A transport whose FLUSH can be held pending while writes keep succeeding —
/// the shape a TLS record or an adapter buffer has, and the one the pipe alone
/// cannot express, because its flush is always ready. It counts every way this
/// driver could push bytes the transport is holding — `poll_flush` and
/// `poll_close` — but only AFTER the read that carried the peer's Close, which
/// is where the guarantee starts. Before it the blocked drive is still trying
/// to finish its batch and re-flushes on every wake, INCLUDING the wake that
/// delivers that Close; those are not pushes after the handshake.
///
/// The boundary is exact rather than timed: the test arms `watch` when the pipe
/// is empty and the peer's Close is the only thing left to send, so the next
/// read that returns bytes IS that Close.
///
/// `poll_flush` returns `Pending` WITHOUT registering a waker: nothing here ever
/// clears the flag, and the wakeups that matter come from the read side, which
/// does register one.
struct BlockedFlush {
  inner: PipeDuplex,
  flush_blocked: Rc<Cell<bool>>,
  watch: Rc<Cell<bool>>,
  saw_close_read: Rc<Cell<bool>>,
  pushes_after_close: Rc<Cell<usize>>,
  close_called: Rc<Cell<bool>>,
}

impl futures_util::AsyncRead for BlockedFlush {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &mut [u8],
  ) -> Poll<std::io::Result<usize>> {
    let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
    if self.watch.get()
      && let Poll::Ready(Ok(n)) = &polled
      && *n > 0
    {
      self.saw_close_read.set(true);
    }
    polled
  }
}

impl futures_util::AsyncWrite for BlockedFlush {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    if self.saw_close_read.get() {
      self
        .pushes_after_close
        .set(self.pushes_after_close.get().saturating_add(1));
    }
    if self.flush_blocked.get() {
      return Poll::Pending;
    }
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_close(
    mut self: Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    self.close_called.set(true);
    if self.saw_close_read.get() {
      self
        .pushes_after_close
        .set(self.pushes_after_close.get().saturating_add(1));
    }
    Pin::new(&mut self.inner).poll_close(cx)
  }
}

#[compio::test]
async fn a_batch_left_inside_the_transport_is_not_flushed_by_the_teardown() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // `discard_unwritten` drops the batch, but bytes `poll_write` already
  // accepted and `poll_flush` has not yet pushed are inside the transport and
  // out of the driver's reach. The teardown's graceful `close()` flushes them
  // ahead of its close_notify — a Pong on the wire after the peer's Close was
  // processed, §5.5.1 (line 2023 of `.rfc-cache/rfc6455.txt`) again through a
  // different door. Every other regression misses it because the pipe's flush
  // is always ready, so this one wraps the pipe in a transport whose flush can
  // be held.
  const BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let flush_blocked = Rc::new(Cell::new(false));
  let watch = Rc::new(Cell::new(false));
  let saw_close_read = Rc::new(Cell::new(false));
  let pushes_after_close = Rc::new(Cell::new(0usize));
  let close_called = Rc::new(Cell::new(false));
  let client = WebSocket::<ClientRole, _>::client(
    BlockedFlush {
      inner: c.into_duplex(),
      flush_blocked: flush_blocked.clone(),
      watch: watch.clone(),
      saw_close_read: saw_close_read.clone(),
      pushes_after_close: pushes_after_close.clone(),
      close_called: close_called.clone(),
    },
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let reader = compio_runtime::spawn(async move {
    let mut ended = None;
    while let Some(m) = cread.next().await {
      if let Err(e) = m {
        ended = Some(e);
        break;
      }
    }
    (ended, cread)
  });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes while the transport is still willing")
    .unwrap()
    .expect("the Close flushes while the transport is still willing");
  // From here the transport ACCEPTS writes and never completes a flush.
  flush_blocked.set(true);

  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, ours) = sr.read(Vec::with_capacity(64)).await;
  let n = res.expect("the peer drains our Close");
  assert_eq!(
    ours.get(..n).and_then(<[u8]>::first).copied(),
    Some(0x88),
    "our Close, masked: {:02x?}",
    ours.get(..n).unwrap_or(&[])
  );

  // One Ping. Its Pong batch is fully accepted by `poll_write` and then hangs
  // in `poll_flush`. The pump has no await between counting the Ping and that
  // hang, so seeing the count from here means the bytes are in the transport.
  let compio_buf::BufResult(res, _) = sw.write(vec![0x89_u8, 0x00]).await;
  res.expect("the peer's ping");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < 1 {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe a pong; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }

  // The pipe is empty and the peer's Close is the only thing left to send, so
  // the next read that returns bytes is that Close: arm the boundary.
  watch.set(true);

  // The peer's Close completes the handshake through the read behind that
  // blocked write.
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the peer's Close");

  let (ended, cread) = compio::time::timeout(std::time::Duration::from_secs(5), reader)
    .await
    .expect("the peer's Close completes the handshake")
    .unwrap();
  assert!(
    ended.is_none(),
    "a completed handshake is not an error: {ended:?}"
  );
  assert!(
    saw_close_read.get(),
    "the boundary must have been crossed for the count below to mean anything"
  );
  assert_eq!(
    pushes_after_close.get(),
    0,
    "nothing may push the abandoned bytes onto the wire after both Close frames"
  );
  assert!(
    !close_called.get(),
    "and a graceful close would push them ahead of its close_notify"
  );
  assert!(
    cread.closed().expect("the handshake completes").clean(),
    "both Closes were exchanged"
  );
}

#[compio::test]
async fn a_peer_flooding_data_behind_a_wedged_write_cannot_grow_the_ready_queue() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // The read behind a blocked write exists to SEE the peer's Close. Nothing
  // drains `ready` while that write is blocked — delivery comes after Phase 3 —
  // so a peer that stops reading and floods small data messages would grow an
  // unbounded queue for as long as the budget lasts, and the budget may be
  // `Duration::MAX`. Every read still happens, because the Close may be behind
  // any of them; what stops is ASSEMBLY, so the flood costs one read chunk of
  // scratch and nothing else, and the Close at the end of it is still seen.
  //
  // The two directions are bounded independently here: the client's is small
  // enough to wedge its Pong batch, the peer's is wide enough to flood in one
  // write.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  // An unmasked server-to-client Text frame with a one-byte payload.
  const DATA_FRAME: [u8; 3] = [0x81, 0x01, b'x'];
  const DATA_LEN: usize = DATA_FRAME.len();
  // More than twice what one read can carry, so the flood cannot be mistaken
  // for a single chunk's worth.
  const FLOOD: usize = 2 * (READ_CHUNK / DATA_LEN) + 1;
  const BUDGET: std::time::Duration = std::time::Duration::from_millis(200);
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
  }

  let (c, s) = duplex_with_capacities(PIPE_CAPACITY, 0);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let reader = compio_runtime::spawn(async move {
    let mut delivered = 0usize;
    let mut ended = None;
    while let Some(m) = cread.next().await {
      match m {
        Ok(_) => delivered += 1,
        Err(e) => {
          ended = Some(e);
          break;
        }
      }
    }
    (delivered, ended, cread)
  });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes")
    .unwrap()
    .expect("the Close flushes");

  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(
    res.expect("the peer drains our Close"),
    CLOSE_LEN,
    "the whole pipe is free for the Pong batch that follows"
  );

  // The peer stops reading here, and its owed Pongs wedge.
  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }

  // …and only then floods, on the direction the wedge does not bound.
  let t0 = std::time::Instant::now();
  let mut flood = Vec::with_capacity(FLOOD * DATA_LEN);
  for _ in 0..FLOOD {
    flood.extend_from_slice(&DATA_FRAME);
  }
  let expected = flood.len();
  let compio_buf::BufResult(res, _) = sw.write(flood).await;
  assert_eq!(res.expect("the flood"), expected, "the flood is one write");
  // The Close is last, behind more than a chunk of data — and it is still
  // read, because observation parses everything it is handed.
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the peer's Close");

  let (delivered, ended, cread) = compio::time::timeout(std::time::Duration::from_secs(5), reader)
    .await
    .expect("the flood is bounded by the budget, not by the peer")
    .unwrap();
  let elapsed = t0.elapsed();
  let high_water = probe.borrow().ready_high_water;
  // EXACTLY zero for the same reason: not one message of the flood is kept.
  assert_eq!(
    high_water, 0,
    "observation parses the {FLOOD}-frame flood and assembles none of it"
  );
  assert_eq!(
    delivered, 0,
    "so there is nothing to deliver from it either"
  );
  assert!(ended.is_none(), "the handshake completes: {ended:?}");
  let closed = cread.closed().expect("the connection ends");
  assert!(
    closed.clean(),
    "the Close behind the flood is read like everything else: {closed:?}"
  );
  assert!(
    elapsed < BUDGET,
    "seen at once, not at the deadline: {elapsed:?}"
  );
}

#[compio::test]
async fn a_long_partial_message_behind_a_wedged_write_is_not_retained() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // A queue-length bound cannot see a message that has not arrived yet: `ready`
  // stays empty for as long as the peer keeps sending continuation frames, so a
  // fragmented message begun before our Close can grow to `max_message_size`
  // behind a wedged write, whatever that cap is set to. The bound has to be on
  // what is RETAINED, and while the write is blocked the driver is observing
  // for the peer's Close, not receiving — so data is discarded rather than
  // assembled.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  // Unmasked server-to-client fragments: a non-final Text start, then
  // continuations, then an empty final continuation.
  const CHUNK_PAYLOAD: usize = 125;
  const FRAGMENTS: usize = 400;
  const FRAGMENT_BYTES: usize = FRAGMENTS * (2 + CHUNK_PAYLOAD);
  const BUDGET: std::time::Duration = std::time::Duration::from_millis(200);
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
    assert!(
      FRAGMENT_BYTES > READ_CHUNK,
      "the message must outgrow a read chunk"
    );
  }

  let (c, s) = duplex_with_capacities(PIPE_CAPACITY, 0);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(BUDGET)
      // Large on purpose: the cap is what the old bound leaned on.
      .with_max_message_size(8 * 1024 * 1024),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let reader = compio_runtime::spawn(async move {
    let mut delivered = 0usize;
    let mut ended = None;
    while let Some(m) = cread.next().await {
      match m {
        Ok(_) => delivered += 1,
        Err(e) => {
          ended = Some(e);
          break;
        }
      }
    }
    (delivered, ended, cread)
  });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes")
    .unwrap()
    .expect("the Close flushes");

  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);

  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }

  // One long message that never ends, then its final fragment, then the Close.
  let t0 = std::time::Instant::now();
  let mut fragments = Vec::with_capacity(FRAGMENT_BYTES);
  for i in 0..FRAGMENTS {
    // Text start on the first, continuation after; none is final.
    fragments.push(if i == 0 { 0x01_u8 } else { 0x00_u8 });
    fragments.push(CHUNK_PAYLOAD as u8);
    fragments.extend(std::iter::repeat_n(b'x', CHUNK_PAYLOAD));
  }
  fragments.extend_from_slice(&[0x80, 0x00]);
  fragments.extend_from_slice(&[0x88, 0x02, 0x03, 0xE8]);
  let expected = fragments.len();
  let compio_buf::BufResult(res, _) = sw.write(fragments).await;
  assert_eq!(res.expect("the fragments"), expected, "one write");

  let (delivered, ended, cread) = compio::time::timeout(std::time::Duration::from_secs(5), reader)
    .await
    .expect("the peer's Close is seen behind the fragments")
    .unwrap();
  let elapsed = t0.elapsed();
  let partial = probe.borrow().partial_high_water;
  // EXACTLY zero, not "within a chunk": observation assembles nothing at all,
  // and a bound of one chunk would be satisfied by a driver that retained one.
  // Unfixed, this read 50000 — the whole message.
  assert_eq!(
    partial, 0,
    "a message arriving while the write is blocked is observed, not retained: \
     {partial} bytes held of a {FRAGMENT_BYTES}-byte message"
  );
  assert_eq!(delivered, 0, "observed data is discarded, not delivered");
  assert!(ended.is_none(), "the handshake completes: {ended:?}");
  assert!(
    cread.closed().expect("the connection ends").clean(),
    "the peer's Close is behind the fragments and must still be seen"
  );
  assert!(
    elapsed < BUDGET,
    "seen at once, not at the deadline: {elapsed:?}"
  );
}

#[compio::test]
async fn a_completed_message_does_not_hide_the_close_in_the_next_read() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // A peer may finish its current fragmented message before answering our
  // Close. If that message completes in one read and the Close lands in the
  // next, a driver that stops reading once it holds a message never sees the
  // Close and reports an unclean timeout instead.
  //
  // The two reads are forced by the pipe rather than by a sleep: the inbound
  // direction holds exactly the message, so the peer's Close write parks until
  // the driver has drained it.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  const MSG_PAYLOAD: usize = 60;
  // A non-final Text start with its payload, then an empty final continuation.
  const MSG_BYTES: usize = (2 + MSG_PAYLOAD) + 2;
  const BUDGET: std::time::Duration = std::time::Duration::from_millis(200);
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
    assert!(
      MSG_BYTES == PIPE_CAPACITY,
      "the message must fill the inbound pipe exactly, so the Close parks behind it"
    );
    assert!(
      PINGS * PING_FRAME.len() <= PIPE_CAPACITY,
      "the pings must fit the same pipe"
    );
  }

  let (c, s) = duplex_with_capacity(PIPE_CAPACITY);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let reader = compio_runtime::spawn(async move {
    let mut ended = None;
    while let Some(m) = cread.next().await {
      if let Err(e) = m {
        ended = Some(e);
        break;
      }
    }
    (ended, cread)
  });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes")
    .unwrap()
    .expect("the Close flushes");

  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);

  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }

  // The whole message, filling the inbound pipe…
  let t0 = std::time::Instant::now();
  let mut message = vec![0x01_u8, MSG_PAYLOAD as u8];
  message.extend(std::iter::repeat_n(b'y', MSG_PAYLOAD));
  message.extend_from_slice(&[0x80, 0x00]);
  assert_eq!(message.len(), MSG_BYTES);
  let compio_buf::BufResult(res, _) = sw.write(message).await;
  assert_eq!(res.expect("the message"), MSG_BYTES, "one write, one read");
  // …and the Close behind it, which cannot land until the driver reads.
  let peer_close = compio_runtime::spawn(async move {
    let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
    res
  });

  let (ended, cread) = compio::time::timeout(std::time::Duration::from_secs(5), reader)
    .await
    .expect("the Close in the second read is seen")
    .unwrap();
  let elapsed = t0.elapsed();
  assert!(ended.is_none(), "the handshake completes: {ended:?}");
  assert!(
    cread.closed().expect("the connection ends").clean(),
    "a message completed in one read must not hide the Close in the next"
  );
  assert!(
    elapsed < BUDGET,
    "seen at once, not at the deadline: {elapsed:?}"
  );
  let _ = compio::time::timeout(std::time::Duration::from_secs(2), peer_close).await;
}

#[compio::test]
async fn observation_reads_behind_a_wedged_write_recycle_their_buffers() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // The read behind a blocked write used to allocate TWICE per read: the flush
  // phase's `read_scratch` was a local of a loop the `Input` arm leaves with
  // `continue 'pump`, so it was dropped and rebuilt on every one, and Phase 1
  // then took the stash it had been copied into and dropped that too. A peer
  // that keeps sending drives both, and the budget bounding it may be
  // `Duration::MAX`.
  //
  // The oracle is bytes ALLOCATED, not a capacity: a buffer that is freed and
  // reallocated at the same size reads identically by capacity, which is
  // exactly the defect. Both buffers reach their steady state during the ping
  // read, which happens before the counter is armed, so the bound over the
  // flood is zero-plus-noise rather than "one more chunk".
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  // An unmasked server-to-client Text frame with a one-byte payload.
  const DATA_FRAME: [u8; 3] = [0x81, 0x01, b'x'];
  // Enough to need at least ten reads of a full chunk.
  const READS: usize = 10;
  const FLOOD: usize = READS * (READ_CHUNK / DATA_FRAME.len()) + 1;
  const BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
  }

  let (c, s) = duplex_with_capacities(PIPE_CAPACITY, 0);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let reader = compio_runtime::spawn(async move {
    let mut ended = None;
    while let Some(m) = cread.next().await {
      if let Err(e) = m {
        ended = Some(e);
        break;
      }
    }
    (ended, cread)
  });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes")
    .unwrap()
    .expect("the Close flushes");

  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);

  // The peer stops reading here, and its owed Pongs wedge.
  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }

  // Everything this test allocates is allocated HERE, before the counter is
  // armed: the flood buffer, and the peer pipe's own queue as it accepts it.
  // The inbound direction is unbounded, so neither write parks — they resolve
  // on their first poll, which is what keeps the driver from running between
  // this point and the arming below.
  let mut flood = Vec::with_capacity(FLOOD * DATA_FRAME.len());
  for _ in 0..FLOOD {
    flood.extend_from_slice(&DATA_FRAME);
  }
  let expected = flood.len();
  let compio_buf::BufResult(res, _) = sw.write(flood).await;
  assert_eq!(res.expect("the flood"), expected, "the flood is one write");
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the peer's Close");
  assert_eq!(
    probe.borrow().observation_reads,
    0,
    "the driver has not read any of it yet"
  );

  crate::counting_alloc::arm();
  let outcome = compio::time::timeout(std::time::Duration::from_secs(5), reader).await;
  let allocated = crate::counting_alloc::disarm();
  let (ended, cread) = outcome.expect("the flood is read, not waited out").unwrap();

  let reads = probe.borrow().observation_reads;
  assert!(
    reads >= 8,
    "the bound is over at least eight observation reads; there were {reads}"
  );
  // MEASURED: 20 reads, 12 369 bytes. Unfixed, the same run allocated 487 502
  // — 29.8 chunks, about 24 KiB per read, which is the two buffers.
  assert!(
    allocated < READ_CHUNK as u64,
    "{reads} observation reads allocated {allocated} bytes, which is not under one \
     {READ_CHUNK}-byte read chunk"
  );
  // The same bound, scale-free. What is left in the total is the flush loop's
  // own per-pass cost — an `event_listener` node and a timer, neither of them
  // a read buffer and neither of them this round's subject — at about 600
  // bytes a pass, so the TOTAL above would stop holding somewhere past
  // twenty-five reads while the property it is testing still did. The defect
  // was two 16 KiB buffers per read; a kilobyte per read is not that, at any
  // length of flood.
  assert!(
    allocated < reads as u64 * 1024,
    "{allocated} bytes over {reads} reads is not under a kilobyte a read"
  );
  assert!(ended.is_none(), "the handshake completes: {ended:?}");
  assert!(
    cread.closed().expect("the connection ends").clean(),
    "the Close behind the flood is still seen"
  );
}

/// One compressed message on the wire, `fragments` frames long, whose payload
/// inflates to `inflated_bytes`.
///
/// The payload is mostly a repeated byte — that is what makes it a bomb — with
/// one incompressible kilobyte every sixty-four, so that the WIRE is long
/// enough to take several reads. A pure run of one byte compresses to a couple
/// of kilobytes and arrives in one read, which cannot state a bound "across at
/// least eight observation reads"; the noise buys the read count at a
/// still-large ratio.
///
/// Built with `websocket-proto`'s own compressor in the SERVER role, so the
/// frames are unmasked server-to-client exactly as this test's peer would send
/// them, and then re-framed: the crate encodes a whole message as one frame,
/// and a bomb wants many, because it is a fragmented message arriving after
/// our Close that the old code inflated one frame at a time.
#[cfg(feature = "deflate")]
fn compressed_bomb(inflated_bytes: usize, fragments: usize) -> Vec<u8> {
  use websocket_proto::negotiation::DeflateParams;

  let negotiated = Negotiated::none().with_deflate(Some(DeflateParams::default()));
  let mut peer = websocket_proto::Connection::<std::time::Instant, ServerRole>::new(
    &negotiated,
    websocket_proto::ConnectionConfig::default(),
    ServerRole::new(),
    std::time::Instant::now(),
  );
  let mut payload = Vec::with_capacity(inflated_bytes);
  let mut lcg: u32 = 0x1234_5678;
  while payload.len() < inflated_bytes {
    let run = (inflated_bytes - payload.len()).min(63 * 1024);
    payload.extend(std::iter::repeat_n(b'A', run));
    let noise = (inflated_bytes - payload.len()).min(1024);
    for _ in 0..noise {
      lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
      payload.push((lcg >> 24) as u8);
    }
  }

  let mut out = vec![0u8; inflated_bytes + 4096];
  let n = peer
    .encode_binary_compressed(&payload, &mut out)
    .expect("permessage-deflate is negotiated with 15-bit windows");
  out.truncate(n);

  // Strip the header the crate wrote: unmasked, so the length is 2, 4 or 10
  // bytes in from the front depending on the second byte's 7-bit length.
  let header = match out.get(1).copied().unwrap_or(0) {
    0..=125 => 2,
    126 => 4,
    _ => 10,
  };
  let body = out.split_off(header);
  assert!(
    body.len() * 16 < inflated_bytes,
    "the bomb must compress at least sixteenfold: {} bytes of wire for {inflated_bytes}",
    body.len()
  );

  let per_frame = body.len().div_ceil(fragments);
  let mut wire = Vec::new();
  let mut chunks = body.chunks(per_frame).peekable();
  let mut first = true;
  while let Some(chunk) = chunks.next() {
    let last = chunks.peek().is_none();
    // FIN only on the last; RSV1 only on the first (RFC 7692 §7.2.3.1).
    let opcode = if first { 0x02_u8 } else { 0x00 };
    let fin = if last { 0x80 } else { 0x00 };
    let rsv1 = if first { 0x40 } else { 0x00 };
    wire.push(fin | rsv1 | opcode);
    let len = chunk.len();
    if len < 126 {
      wire.push(len as u8);
    } else {
      wire.push(126);
      wire.extend_from_slice(&(len as u16).to_be_bytes());
    }
    wire.extend_from_slice(chunk);
    first = false;
  }
  wire
}

#[cfg(feature = "deflate")]
#[compio::test]
async fn a_compressed_bomb_behind_a_wedged_write_is_not_inflated() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};
  use websocket_proto::negotiation::DeflateParams;

  // The R7 finding: discarding at the assembler rather than the protocol discards
  // the EVENT, and with `deflate` the event is produced only after
  // `Connection::handle` has inflated the payload into the decompressor's
  // buffer and kept its capacity. So a peer that keeps sending compressed
  // fragments after our Close turned each read into megabytes of output that
  // nothing would ever read — up to the message cap, on a connection whose
  // application has already said it is done.
  //
  // The oracle is the counting allocator: inflating is allocating, so bytes
  // allocated across the observation reads sees both this and the buffer
  // churn of the round's other finding at once.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  const BOMB_BYTES: usize = 4 * 1024 * 1024;
  const FRAGMENTS: usize = 512;
  const BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
  }

  let (c, s) = duplex_with_capacities(PIPE_CAPACITY, 0);
  let negotiated = Negotiated::none().with_deflate(Some(DeflateParams::default()));
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let reader = compio_runtime::spawn(async move {
    let mut delivered = 0usize;
    let mut ended = None;
    while let Some(m) = cread.next().await {
      match m {
        Ok(_) => delivered += 1,
        Err(e) => {
          ended = Some(e);
          break;
        }
      }
    }
    (delivered, ended, cread)
  });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes")
    .unwrap()
    .expect("the Close flushes");

  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);

  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }

  // Compressed and written before the counter is armed, for the reason the
  // uncompressed sibling gives: neither write parks, so the driver does not
  // run between here and the arming.
  let bomb = compressed_bomb(BOMB_BYTES, FRAGMENTS);
  let wire = bomb.len();
  let compio_buf::BufResult(res, _) = sw.write(bomb).await;
  assert_eq!(res.expect("the bomb"), wire, "the bomb is one write");
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the peer's Close");

  crate::counting_alloc::arm();
  let outcome = compio::time::timeout(std::time::Duration::from_secs(30), reader).await;
  let allocated = crate::counting_alloc::disarm();
  let (delivered, ended, cread) = outcome.expect("the bomb is skipped, not inflated").unwrap();

  let reads = probe.borrow().observation_reads;
  assert!(
    reads >= 8,
    "the bound is over at least eight observation reads; there were {reads}"
  );
  // MEASURED: 77 845 bytes of wire inflating to 4 194 304, 10 reads, 6 209
  // bytes allocated. With the discard back at the assembler — `handle` where
  // `observe` now stands — the same run allocated 180 625. That number is the
  // inflate buffer's GROWTH and not the inflating: the buffer is reused across
  // frames, so the allocator sees the largest frame rather than the four
  // megabytes of output. `websocket-proto`'s own regression measures the work
  // directly, and reads 8 388 627 bytes inflated for 9 688 bytes of wire.
  assert!(
    allocated < READ_CHUNK as u64,
    "{wire} bytes of wire inflating to {BOMB_BYTES} allocated {allocated} bytes over \
     {reads} observation reads, which is not under one {READ_CHUNK}-byte read chunk"
  );
  // The scale-free form, for the reason the uncompressed sibling gives.
  assert!(
    allocated < reads as u64 * 1024,
    "{allocated} bytes over {reads} reads is not under a kilobyte a read"
  );
  assert_eq!(delivered, 0, "the bomb is discarded, not delivered");
  assert!(ended.is_none(), "the handshake completes: {ended:?}");
  assert!(
    cread.closed().expect("the connection ends").clean(),
    "the Close behind the bomb is still seen"
  );
}

#[compio::test]
async fn a_message_begun_before_observation_is_not_delivered_truncated() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // The cross-family review's probe. The peer opens a fragmented Binary
  // message and one non-final frame arrives while the driver is still
  // RECEIVING, so `MessageAssembler` holds it. The application then closes,
  // the peer wedges the Pong batch, and every later read is observed — and an
  // observed read of pure continuation payload yields NO events at all, so
  // nothing in the event loop can tell the assembler to let go. When the wedge
  // drains, the message's final frame arrives under `handle` and its
  // `MessageEnd` sealed the stale partial as a COMPLETE message: the
  // application received 125 bytes of a 50 125-byte message and a clean close,
  // with no way to tell it from a message the peer really ended there.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  const CHUNK: usize = 125;
  const CONTINUATIONS: usize = 400;
  const BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
  }

  let (c, s) = duplex_with_capacities(PIPE_CAPACITY, 0);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let (mut sr, mut sw) = s.split();

  // The reader must be running for the head to reach the assembler at all:
  // the pump is what feeds `push`, and it only runs while `next()` is polled.
  let reader = compio_runtime::spawn(async move {
    let mut delivered = Vec::new();
    let mut ended = None;
    while let Some(m) = cread.next().await {
      match m {
        Ok(msg) => delivered.push(msg.len()),
        Err(e) => {
          ended = Some(e);
          break;
        }
      }
    }
    (delivered, ended, cread)
  });

  // The head, BEFORE the close: assembled by `push` into the accumulator.
  let mut head = vec![0x02_u8, CHUNK as u8];
  head.extend(std::iter::repeat_n(b'H', CHUNK));
  let head_len = head.len();
  let compio_buf::BufResult(res, _) = sw.write(head).await;
  assert_eq!(res.expect("the head"), head_len);
  let waited = std::time::Instant::now();
  while probe.borrow().partial_high_water == 0 {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the head must reach the assembler before the close"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  assert_eq!(
    probe.borrow().partial_high_water,
    CHUNK,
    "the assembler is holding the head when observation begins"
  );

  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes")
    .unwrap()
    .expect("the Close flushes");
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);

  // The peer stops reading; its owed Pongs wedge and observation begins.
  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }

  // Pure continuation payload — every observed read of it yields ZERO events.
  let mut body = Vec::with_capacity(CONTINUATIONS * (2 + CHUNK));
  for _ in 0..CONTINUATIONS {
    body.push(0x00_u8);
    body.push(CHUNK as u8);
    body.extend(std::iter::repeat_n(b'C', CHUNK));
  }
  let body_len = body.len();
  let compio_buf::BufResult(res, _) = sw.write(body).await;
  assert_eq!(res.expect("the continuations"), body_len);
  let waited = std::time::Instant::now();
  while probe.borrow().observation_reads == 0 {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the continuations must be read behind the wedged write"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }

  // The peer drains the Pong batch, so the wedge clears and the pump returns
  // to `handle` — where the message's final frame lands.
  let mut drained = 0usize;
  while drained < PINGS * PONG_LEN {
    let compio_buf::BufResult(res, _) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
    match res {
      Ok(0) => break,
      Ok(n) => drained += n,
      Err(_) => break,
    }
  }
  // The premise of the rest of this test, asserted rather than assumed: the
  // wedge is gone, so the final frame below is fed through `handle` and not
  // observed. A change in the pump's re-entry conditions must red HERE, with
  // the state it actually reached, rather than let the test pass because it
  // never left observation.
  let waited = std::time::Instant::now();
  loop {
    let (pending, reads) = {
      let guard = probe.borrow();
      (guard.pending_write.is_some(), guard.observation_reads)
    };
    if !pending && reads > 0 {
      break;
    }
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the wedge must drain before the final frame: pending_write={pending}, \
       observation_reads={reads}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }

  let compio_buf::BufResult(res, _) = sw.write(vec![0x80_u8, 0x00]).await;
  res.expect("the final continuation");
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the peer's Close");

  let (delivered, ended, cread) = compio::time::timeout(std::time::Duration::from_secs(5), reader)
    .await
    .expect("the close handshake completes")
    .unwrap();
  // Unfixed this read `delivered=[125]` — the head, sealed by a `MessageEnd`
  // belonging to a message 400 frames of which were never seen.
  assert_eq!(
    delivered,
    Vec::<usize>::new(),
    "a message half of which was discarded must NOT be delivered"
  );
  assert!(ended.is_none(), "the handshake completes: {ended:?}");
  assert!(
    cread.closed().expect("the connection ends").clean(),
    "and the close is clean"
  );
}

#[cfg(feature = "deflate")]
#[compio::test]
async fn a_poisoned_compressed_message_is_dropped_not_delivered_empty() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};
  use websocket_proto::negotiation::DeflateParams;

  // The cross-family review's second probe. Observation poisons the inflate
  // context (by design), the wedge then drains, and the driver returns to
  // `handle` for the rest of the connection's life. Every later compressed
  // message is skipped by the protocol — `MessageStart` + `MessageEnd`, no
  // chunks — and an assembler that opens an accumulator on that start hands
  // the application a fabricated EMPTY message where the peer sent bytes.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  const BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
  }

  // One peer compressor for the whole connection: context takeover means the
  // messages share a DEFLATE stream, which is the state the poison is about.
  let negotiated = Negotiated::none().with_deflate(Some(DeflateParams::default()));
  let mut peer = websocket_proto::Connection::<std::time::Instant, ServerRole>::new(
    &negotiated,
    websocket_proto::ConnectionConfig::default(),
    ServerRole::new(),
    std::time::Instant::now(),
  );
  let mut scratch = vec![0u8; 8192];
  let n = peer
    .encode_binary_compressed(&[b'A'; 200], &mut scratch)
    .expect("compressed");
  let first = scratch.get(..n).unwrap_or(&[]).to_vec();
  let n = peer
    .encode_binary_compressed(&[b'B'; 300], &mut scratch)
    .expect("compressed");
  let second = scratch.get(..n).unwrap_or(&[]).to_vec();

  let (c, s) = duplex_with_capacities(PIPE_CAPACITY, 0);
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let reader = compio_runtime::spawn(async move {
    let mut delivered = Vec::new();
    let mut ended = None;
    while let Some(m) = cread.next().await {
      match m {
        Ok(msg) => delivered.push(msg.len()),
        Err(e) => {
          ended = Some(e);
          break;
        }
      }
    }
    (delivered, ended, cread)
  });
  compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the Close flushes")
    .unwrap()
    .expect("the Close flushes");

  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);

  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }

  // Observed behind the wedge: skipped, and the context is poisoned.
  let len = first.len();
  let compio_buf::BufResult(res, _) = sw.write(first).await;
  assert_eq!(res.expect("the observed message"), len);
  let waited = std::time::Instant::now();
  while probe.borrow().observation_reads == 0 {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the compressed message must be read behind the wedged write"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }

  // The peer drains the Pongs, so the pump goes back to `handle`…
  let mut drained = 0usize;
  while drained < PINGS * PONG_LEN {
    let compio_buf::BufResult(res, _) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
    match res {
      Ok(0) => break,
      Ok(n) => drained += n,
      Err(_) => break,
    }
  }
  // …where a compressed message carrying 300 bytes is skipped by the poison,
  // and an uncompressed one is unaffected and must still arrive. The premise
  // is that the wedge is gone AND the poison was set — both asserted, so a
  // change in the pump's re-entry conditions reds here rather than letting
  // this pass for the wrong reason.
  let waited = std::time::Instant::now();
  loop {
    let (pending, reads) = {
      let guard = probe.borrow();
      (guard.pending_write.is_some(), guard.observation_reads)
    };
    if !pending && reads > 0 {
      break;
    }
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the wedge must drain before the poisoned message: pending_write={pending}, \
       observation_reads={reads}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }

  let len = second.len();
  let compio_buf::BufResult(res, _) = sw.write(second).await;
  assert_eq!(res.expect("the poisoned message"), len);
  let mut plain = vec![0x82_u8, 4];
  plain.extend_from_slice(b"tail");
  let compio_buf::BufResult(res, _) = sw.write(plain).await;
  res.expect("an uncompressed message");
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the peer's Close");

  let (delivered, ended, cread) = compio::time::timeout(std::time::Duration::from_secs(5), reader)
    .await
    .expect("the close handshake completes")
    .unwrap();
  // Unfixed this read `delivered=[0, 0, 4]` — an EMPTY Binary fabricated for
  // each skipped compressed message, then the uncompressed one.
  //
  // Two facts, two assertions, because one list assertion reds for either and
  // names neither.
  assert!(
    !delivered.contains(&0),
    "a skipped compressed message must not surface as an empty message; \
     delivered {delivered:?}"
  );
  assert_eq!(
    delivered,
    vec![4],
    "and the uncompressed message after the poison must still be delivered \
     whole, alone; delivered {delivered:?}"
  );
  assert!(ended.is_none(), "the handshake completes: {ended:?}");
  assert!(
    cread.closed().expect("the connection ends").clean(),
    "and the close is clean"
  );
}

#[cfg(feature = "deflate")]
#[compio::test]
async fn an_unsplit_close_observes_reads_nobody_can_receive() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};
  use websocket_proto::negotiation::DeflateParams;

  // `WebSocket::close` CONSUMES the handle: no application code can receive
  // another message, and the loop inside it discards every one the pump
  // produces. There is no wedge here and nothing is blocked — this is the
  // ordinary echo wait — so Phase 4 stashed its reads unflagged and Phase 1
  // fed them to `handle`, inflating and assembling a peer's compressed bomb in
  // full, to the message cap, one line before throwing it away.
  const CLOSE_LEN: usize = 8;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const BOMB_BYTES: usize = 4 * 1024 * 1024;
  const FRAGMENTS: usize = 512;
  const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

  let (c, s) = duplex();
  let negotiated = Negotiated::none().with_deflate(Some(DeflateParams::default()));
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let probe = client.inner.clone();
  let closer = compio_runtime::spawn(async move { client.close(CloseCode::Normal, "").await });

  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, _) = sr.read(Vec::with_capacity(64)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);

  // One Ping first, so the read buffers reach their steady state before the
  // counter is armed and the window measures the bomb rather than the
  // driver's first read.
  let compio_buf::BufResult(res, _) = sw.write(PING_FRAME.to_vec()).await;
  res.expect("the ping");
  let waited = std::time::Instant::now();
  while probe.borrow().pings_seen == 0 {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the pump must still be reading during the echo wait"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }

  // Built and written before arming: the pipe is unbounded, so neither write
  // parks and the pump does not run between them and the arming below.
  let bomb = compressed_bomb(BOMB_BYTES, FRAGMENTS);
  let wire = bomb.len();
  let compio_buf::BufResult(res, _) = sw.write(bomb).await;
  assert_eq!(res.expect("the bomb"), wire, "the bomb is one write");
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the peer's Close");

  crate::counting_alloc::arm();
  let outcome = compio::time::timeout(std::time::Duration::from_secs(30), closer).await;
  let allocated = crate::counting_alloc::disarm();
  let closed = outcome
    .expect("the bomb is skipped, not inflated")
    .unwrap()
    .expect("the close handshake completes");

  // MEASURED: 77 845 bytes of wire inflating to 4 194 304 allocated 5 585
  // bytes. With the flag not reaching Phase 1, the same run allocated
  // 6 851 257 — 418 read chunks — because the inflater's buffer and then the
  // assembler's accumulator both grew for a message `close` discards on the
  // next line.
  assert!(
    allocated < READ_CHUNK as u64,
    "{wire} bytes of wire inflating to {BOMB_BYTES} allocated {allocated} bytes during \
     an unsplit close, which is not under one {READ_CHUNK}-byte read chunk"
  );
  assert!(closed.clean(), "and the close is clean: {closed:?}");
}

#[compio::test]
async fn a_dropped_read_half_leaves_nothing_to_read_with() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // The split twin of the flag above, and the reason it has no bomb
  // regression of its own: `ReadHalf::drop` is the pump's owner, so dropping
  // it does not leave a pump reading into nothing — it takes the transport
  // down with it and refuses the write half outright. `inbound_unread` is set
  // there for totality (the fact becomes true at that line), and this pins
  // that there is no read left for it to change.
  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default(),
    Vec::new(),
  );
  let (cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  drop(cread);

  assert!(
    probe.borrow().inbound_unread,
    "dropping the read half says nobody will read what arrives"
  );
  assert!(
    probe.borrow().stream.is_none(),
    "and it takes the transport with it, so nothing can arrive"
  );
  assert!(
    matches!(
      cwrite.close(CloseCode::Normal, "").await,
      Err(crate::Error::ReadHalfGone)
    ),
    "so the write half's close is refused rather than pumped"
  );

  // The peer sees EOF rather than a parked connection, and anything it sends
  // after that reaches no reader at all.
  let (mut sr, mut sw) = s.split();
  let compio_buf::BufResult(res, _) = sr.read(Vec::with_capacity(64)).await;
  assert_eq!(res.expect("the peer reads"), 0, "EOF");
  let compio_buf::BufResult(res, _) = sw.write(vec![0x89_u8, 0x00]).await;
  let _ = res;
}

#[compio::test]
async fn a_close_deadline_that_fires_drops_the_partial_it_will_never_finish() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // The connection ends on OUR timer: the peer drained our Close and then said
  // nothing, so no frame is decoded, no event is pushed, and the assembler's
  // terminal arms never run. A prefix accumulated before the close stayed in
  // the folder for as long as anything held the shared state — and a split
  // `WriteHalf` the caller keeps holding is exactly that.
  const CHUNK: usize = 125;
  const CLOSE_LEN: usize = 8;
  const BUDGET: std::time::Duration = std::time::Duration::from_millis(150);

  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let (mut sr, mut sw) = s.split();

  // A fragmented message the peer never finishes.
  let mut head = vec![0x01_u8, CHUNK as u8];
  head.extend(std::iter::repeat_n(b'H', CHUNK));
  let head_len = head.len();
  let compio_buf::BufResult(res, _) = sw.write(head).await;
  assert_eq!(res.expect("the head"), head_len);

  let reader = compio_runtime::spawn(async move {
    let mut ended = None;
    while let Some(m) = cread.next().await {
      if let Err(e) = m {
        ended = Some(e);
        break;
      }
    }
    (ended, cread)
  });
  let waited = std::time::Instant::now();
  while probe.borrow().assembler.buffered() == 0 {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the prefix must reach the assembler before the close"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  assert_eq!(probe.borrow().assembler.buffered(), CHUNK);

  cwrite
    .close(CloseCode::Normal, "")
    .await
    .expect("the Close flushes");
  let compio_buf::BufResult(res, _) = sr.read(Vec::with_capacity(64)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);
  // …and answers nothing. The budget is what ends this.

  let (ended, cread) = compio::time::timeout(std::time::Duration::from_secs(5), reader)
    .await
    .expect("the close deadline ends the connection")
    .unwrap();
  assert!(
    ended.is_none(),
    "the deadline is not an error here: {ended:?}"
  );
  assert!(
    !cread.closed().expect("an outcome is recorded").clean(),
    "the peer never echoed, so the close is unclean"
  );
  // Unfixed this read 125: nothing pushed, nothing reset.
  assert_eq!(
    probe.borrow().assembler.buffered(),
    0,
    "a close reached through our own timer must still drop the partial"
  );
  // The write half is still held, so the shared state is still alive — which
  // is the shape that made the retention observable.
  drop(cwrite);
}

#[compio::test]
async fn a_dropped_read_half_drops_the_partial_and_the_queue() {
  use compio_io::{AsyncWrite as _, util::Splittable as _};

  // Nobody can read either half of what is held: not the partial, and not the
  // complete messages already queued behind it.
  const CHUNK: usize = 125;

  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default(),
    Vec::new(),
  );
  let (mut cread, _cwrite) = client.split();
  let probe = cread.inner.clone();
  let (_sr, mut sw) = s.split();

  // Two whole messages and then a prefix, in one write: Phase 1 assembles both
  // into `ready`, delivery hands out the first, and the second stays queued.
  let mut wire = vec![0x81_u8, 3];
  wire.extend_from_slice(b"one");
  wire.push(0x81);
  wire.push(3);
  wire.extend_from_slice(b"two");
  wire.push(0x01);
  wire.push(CHUNK as u8);
  wire.extend(std::iter::repeat_n(b'H', CHUNK));
  let len = wire.len();
  let compio_buf::BufResult(res, _) = sw.write(wire).await;
  assert_eq!(res.expect("the write"), len);

  let first = cread
    .next()
    .await
    .expect("a message")
    .expect("a message, not an error");
  assert_eq!(first.len(), 3);
  assert_eq!(probe.borrow().ready.len(), 1, "the second is still queued");
  assert_eq!(
    probe.borrow().assembler.buffered(),
    CHUNK,
    "and a prefix held"
  );

  drop(cread);

  // Unfixed these read 1 and 125.
  assert_eq!(
    probe.borrow().ready.len(),
    0,
    "a message nobody can receive is not kept"
  );
  assert_eq!(
    probe.borrow().assembler.buffered(),
    0,
    "and neither is a partial nobody can finish"
  );
}

#[compio::test]
async fn an_unsplit_close_drops_the_partial_and_the_queue() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // The same on the unsplit path, where `close(self, …)` consumes the handle:
  // the messages its own loop would discard are dropped up front instead of
  // being assembled, and what was already held goes with them.
  const CHUNK: usize = 125;
  const CLOSE_LEN: usize = 8;

  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let mut client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default(),
    Vec::new(),
  );
  let probe = client.inner.clone();
  let (mut sr, mut sw) = s.split();

  let mut wire = vec![0x81_u8, 3];
  wire.extend_from_slice(b"one");
  wire.push(0x81);
  wire.push(3);
  wire.extend_from_slice(b"two");
  wire.push(0x01);
  wire.push(CHUNK as u8);
  wire.extend(std::iter::repeat_n(b'H', CHUNK));
  let len = wire.len();
  let compio_buf::BufResult(res, _) = sw.write(wire).await;
  assert_eq!(res.expect("the write"), len);

  let first = client
    .next()
    .await
    .expect("a message")
    .expect("a message, not an error");
  assert_eq!(first.len(), 3);
  assert_eq!(probe.borrow().ready.len(), 1);
  assert_eq!(probe.borrow().assembler.buffered(), CHUNK);

  // The assertion is taken WHILE the close is in flight, not after it. Both
  // are empty by the end whatever happens — the terminal events reset the
  // folder and `close`'s own loop drains `ready` — so the fact under test is
  // that they go at the TRANSITION: `close` consumes the handle, and from
  // that instant nothing held is reachable. `inbound_unread` and the reset are
  // set under one borrow, so the flag being visible means the reset has run.
  let closer = compio_runtime::spawn(async move { client.close(CloseCode::Normal, "").await });
  let waited = std::time::Instant::now();
  while !probe.borrow().inbound_unread {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the close must reach the no-reader transition"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  // Unfixed these read 1 and 125.
  let (queued, held) = {
    let guard = probe.borrow();
    (guard.ready.len(), guard.assembler.buffered())
  };
  assert_eq!(
    queued, 0,
    "queued for nobody, and dropped at the transition"
  );
  assert_eq!(held, 0, "held for nobody, and dropped at the transition");

  // Then let the handshake finish, so the test ends on a clean close rather
  // than a budget.
  let compio_buf::BufResult(res, _) = sr.read(Vec::with_capacity(64)).await;
  assert_eq!(res.expect("our Close"), CLOSE_LEN);
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the echo");
  let closed = compio::time::timeout(std::time::Duration::from_secs(5), closer)
    .await
    .expect("the close handshake completes")
    .unwrap()
    .expect("the close handshake completes");
  assert!(closed.clean());
}

#[compio::test]
async fn a_flush_that_times_out_drops_the_partial_it_will_never_finish() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // The OTHER settle: `close_flush_timed_out`, reached when a batch built
  // after our Close wedges and its slice of the budget runs out. It records
  // the protocol's verdict exactly as Phase 1's settle does, and for the same
  // reason must let go of a message nothing will ever finish — no peer frame
  // arrives, so no event is pushed, and no data run is skipped, so no
  // `MessageAbandoned` either.
  //
  // Reaching THIS site rather than Phase 1's takes two facts at once: our
  // Close must have drained (that is what arms the protocol's deadline — a
  // Close still queued gives `handle_timeout` nothing to report and the
  // function takes its poisoning arm instead), and a LATER batch must be
  // wedged when the budget expires. A Pong batch behind a peer that stopped
  // reading is that batch.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  const CHUNK: usize = 125;
  const BUDGET: std::time::Duration = std::time::Duration::from_millis(150);
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
  }

  let (c, s) = duplex_with_capacities(PIPE_CAPACITY, 0);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let (mut sr, mut sw) = s.split();

  // A fragmented message the peer never finishes, accumulated under `handle`
  // before anything closes.
  let mut head = vec![0x01_u8, CHUNK as u8];
  head.extend(std::iter::repeat_n(b'H', CHUNK));
  let head_len = head.len();
  let compio_buf::BufResult(res, _) = sw.write(head).await;
  assert_eq!(res.expect("the head"), head_len);

  let reader = compio_runtime::spawn(async move {
    let mut ended = None;
    while let Some(m) = cread.next().await {
      if let Err(e) = m {
        ended = Some(e);
        break;
      }
    }
    (ended, cread)
  });
  let waited = std::time::Instant::now();
  while probe.borrow().assembler.buffered() == 0 {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the prefix must reach the assembler before the close"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  assert_eq!(probe.borrow().assembler.buffered(), CHUNK);

  cwrite
    .close(CloseCode::Normal, "")
    .await
    .expect("the Close flushes");
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);

  // The peer pings and then stops reading: the owed Pongs wedge, and the echo
  // arm's budget is what ends the connection.
  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }
  // …and nothing else is ever sent. No further data means no skipped run,
  // so nothing in the event stream can say the message is over.

  let (ended, cread) = compio::time::timeout(std::time::Duration::from_secs(5), reader)
    .await
    .expect("the echo budget ends the connection")
    .unwrap();
  assert!(
    ended.is_none(),
    "the flush timeout records an outcome rather than an error here: {ended:?}"
  );
  assert!(
    !cread.closed().expect("an outcome is recorded").clean(),
    "the peer never echoed, so the close is unclean"
  );
  // Unfixed — with this site's `reset()` deleted — this read 125.
  assert_eq!(
    probe.borrow().assembler.buffered(),
    0,
    "the flush-timeout settle must drop the partial too"
  );
  drop(cwrite);
}

#[compio::test]
async fn a_timeout_close_still_hands_out_the_messages_it_already_holds() {
  use compio_io::{AsyncWrite as _, util::Splittable as _};
  use std::future::Future;

  // Why `ready` is KEPT when Phase 1's settle records a timeout close, while
  // the no-reader transitions clear it: this pump promises to hand out every
  // complete message before it answers `None`, and a message that arrived
  // before the close is one the application is still entitled to. Stated as a
  // test rather than as a sentence in a comment, because the reset that sits
  // beside it could clear `ready` just as easily and nothing would have said
  // otherwise.
  const BUDGET: std::time::Duration = std::time::Duration::from_millis(120);

  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let (_sr, mut sw) = s.split();

  // Two whole messages in one write, so one feed assembles both and delivery
  // hands out only the first — the second is what this test is about.
  let mut wire = vec![0x81_u8, 3];
  wire.extend_from_slice(b"one");
  wire.push(0x81);
  wire.push(3);
  wire.extend_from_slice(b"two");
  let len = wire.len();
  let compio_buf::BufResult(res, _) = sw.write(wire).await;
  assert_eq!(res.expect("the messages"), len);

  // Polled ONCE, not spawned: on the split path the pump is `ReadHalf::next`,
  // which this test drives itself one call at a time, and a spawned closer
  // would race the first of those calls — enqueueing after the pump had
  // already built its batch and then waiting for a pump nobody is running.
  // One poll gets the Close into the queue and leaves the future pending.
  let mut closer = Box::pin(cwrite.close(CloseCode::Normal, ""));
  futures_util::future::poll_fn(|cx| {
    assert!(closer.as_mut().poll(cx).is_pending());
    std::task::Poll::Ready(())
  })
  .await;

  let first = compio::time::timeout(std::time::Duration::from_secs(2), cread.next())
    .await
    .expect("the first message is already assembled")
    .expect("a message")
    .expect("a message, not an error");
  assert_eq!(first, Message::Text("one".into()));
  compio::time::timeout(std::time::Duration::from_secs(2), closer.as_mut())
    .await
    .expect("the Close flushed on that pass")
    .expect("the Close flushed on that pass");
  assert_eq!(
    probe.borrow().ready.len(),
    1,
    "the second is queued, and the Close has flushed"
  );
  assert!(
    probe.borrow().close_flushed_at.is_some(),
    "so the protocol's close deadline is armed"
  );

  // Nothing polls the pump while the budget runs out — on this path the
  // reader IS the pump — and the peer never echoes.
  compio::time::sleep(BUDGET + std::time::Duration::from_millis(80)).await;

  // The settle fires on this pass, BEFORE delivery. Unfixed — with that
  // settle clearing `ready` as the no-reader transitions do — this call
  // answered `None` and the message was lost.
  let second = compio::time::timeout(std::time::Duration::from_secs(2), cread.next())
    .await
    .expect("the settle fires on this pass rather than parking")
    .expect("the message queued before the close is still owed")
    .expect("a message, not an error");
  assert_eq!(second, Message::Text("two".into()));
  assert!(
    cread.closed().is_some(),
    "and the outcome was recorded by the settle on that same pass"
  );
  assert!(
    compio::time::timeout(std::time::Duration::from_secs(2), cread.next())
      .await
      .expect("and then it ends")
      .is_none(),
    "and only then, None"
  );
  assert!(
    !cread.closed().expect("an outcome").clean(),
    "the peer never echoed"
  );
}

/// The `ErrorKind` a pump outcome carries, for tests that assert a sender saw
/// the same one the connection recorded.
#[cfg(test)]
fn first_io_kind(ended: &Option<Error>) -> Option<std::io::ErrorKind> {
  match ended {
    Some(Error::Io(e)) => Some(e.kind()),
    _ => None,
  }
}

/// Drives a split client until the pump reports an error, and answers what the
/// folder was still holding when it did.
///
/// The shared body of the four `terminate_io` regressions: each reaches a
/// different irreversible transport condition, and every one of them must end
/// with the partial dropped and the queue empty, because a sticky poison makes
/// the pump answer the error before it ever reaches delivery.
#[cfg(test)]
async fn held_after_termination<S: crate::into_duplex::Duplex>(
  cread: &mut ReadHalf<ClientRole, S>,
  probe: &std::rc::Rc<std::cell::RefCell<Inner<ClientRole, S>>>,
) -> (usize, usize, Option<Error>) {
  let mut ended = None;
  loop {
    match compio::time::timeout(std::time::Duration::from_secs(5), cread.next()).await {
      Ok(Some(Ok(_))) => continue,
      Ok(Some(Err(e))) => {
        ended = Some(e);
        break;
      }
      Ok(None) => break,
      Err(_) => panic!("the pump must terminate rather than park"),
    }
  }
  let guard = probe.borrow();
  (guard.assembler.buffered(), guard.ready.len(), ended)
}

#[compio::test]
async fn a_close_flush_that_never_batched_releases_what_it_holds() {
  use compio_io::{AsyncWrite as _, util::Splittable as _};
  use std::future::Future;

  // (a) The close flush expires while a plain batch is still wedged, so the
  // Close never drained and `handle_timeout` has no verdict to report: the
  // connection is poisoned rather than closed. The transport is already gone
  // and the poison is sticky, so nothing held can ever be handed out.
  const CHUNK: usize = 125;

  let (c, s) = duplex_with_capacities(4 * 1024, 0);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(100)),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let (_sr, mut sw) = s.split();

  // Two whole messages and a prefix, all before anything closes, and one pump
  // pass to take them in: the first message is delivered, the second stays in
  // `ready`, and the prefix stays in the folder. The pass has to happen HERE,
  // before the wedging send — once the plain flush parks, Phase 4 never runs
  // and nothing would ever be read at all.
  let mut wire = vec![0x81_u8, 3];
  wire.extend_from_slice(b"one");
  wire.push(0x81);
  wire.push(3);
  wire.extend_from_slice(b"two");
  wire.push(0x01);
  wire.push(CHUNK as u8);
  wire.extend(std::iter::repeat_n(b'H', CHUNK));
  let len = wire.len();
  let compio_buf::BufResult(res, _) = sw.write(wire).await;
  assert_eq!(res.expect("the write"), len);

  let first = compio::time::timeout(std::time::Duration::from_secs(2), cread.next())
    .await
    .expect("the messages are already on the wire")
    .expect("a message")
    .expect("a message, not an error");
  assert_eq!(first.len(), 3);
  assert_eq!(probe.borrow().ready.len(), 1, "the second is queued");
  assert_eq!(
    probe.borrow().assembler.buffered(),
    CHUNK,
    "the prefix is held"
  );

  // A 64 KiB send the peer never drains: the pump parks in an unbounded plain
  // flush BEFORE delivery, so the queued message stays queued and the Close
  // that follows cannot reach a batch.
  {
    let payload = vec![0xAB_u8; 64 * 1024];
    let mut fut = Box::pin(cwrite.send_binary(&payload));
    futures_util::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  let watch = probe.clone();
  let reader = compio_runtime::spawn(async move {
    let held = held_after_termination(&mut cread, &watch).await;
    (held, cread)
  });
  compio::time::sleep(std::time::Duration::from_millis(30)).await;
  let closer = compio_runtime::spawn(async move { cwrite.close(CloseCode::Normal, "").await });
  let close_err = compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the close resolves within the budget")
    .unwrap()
    .unwrap_err();
  assert!(matches!(&close_err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut));

  let ((held, queued, ended), _cread) =
    compio::time::timeout(std::time::Duration::from_secs(5), reader)
      .await
      .expect("the reader observes the termination")
      .unwrap();
  assert!(
    matches!(&ended, Some(Error::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut),
    "the flush timeout with no verdict is an error, not an outcome: {ended:?}"
  );
  // Unfixed these read 125 and 1.
  assert_eq!(held, 0, "a partial nothing can finish is not kept");
  assert_eq!(
    queued, 0,
    "nor a message the sticky poison makes unreachable"
  );
}

#[compio::test]
async fn a_write_fault_releases_what_it_holds() {
  use compio_io::{AsyncWrite as _, util::Splittable as _};
  use std::future::Future;

  // (b) The write path faults mid-batch. A partial frame may be on the wire,
  // so the connection is poisoned for good.
  const CHUNK: usize = 125;

  let (c, s) = duplex_with_write_fault(4 * 1024);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default(),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let (_sr, mut sw) = s.split();

  // TWO whole messages and a prefix, and one pump pass to take them in, so
  // that when the fault arms the state is one the test has CHECKED rather
  // than one it hopes for: the first message delivered, the second queued,
  // the prefix held. Without the pass the queue could be empty by then and
  // the `ready` half of this test would prove nothing.
  let mut wire = vec![0x81_u8, 3];
  wire.extend_from_slice(b"one");
  wire.push(0x81);
  wire.push(3);
  wire.extend_from_slice(b"two");
  wire.push(0x01);
  wire.push(CHUNK as u8);
  wire.extend(std::iter::repeat_n(b'H', CHUNK));
  let len = wire.len();
  let compio_buf::BufResult(res, _) = sw.write(wire).await;
  assert_eq!(res.expect("the write"), len);

  let first = compio::time::timeout(std::time::Duration::from_secs(2), cread.next())
    .await
    .expect("the messages are already on the wire")
    .expect("a message")
    .expect("a message, not an error");
  assert_eq!(first.len(), 3);
  {
    let guard = probe.borrow();
    assert_eq!(
      guard.ready.len(),
      1,
      "one message is queued when the fault arms"
    );
    assert_eq!(guard.assembler.buffered(), CHUNK, "and a prefix is held");
  }

  // 64 KiB, whose first 4 KiB arm the fault. Polled ONCE before the pump runs
  // rather than spawned: a spawned sender races the pump's next pass, and if
  // the pump wins it delivers the queued message before the batch even exists
  // — which is how the `ready` half of this test measured nothing.
  let payload = vec![0xAB_u8; 64 * 1024];
  let mut sender = Box::pin(cwrite.send_binary(&payload));
  futures_util::future::poll_fn(|cx| {
    assert!(sender.as_mut().poll(cx).is_pending());
    std::task::Poll::Ready(())
  })
  .await;
  assert_eq!(
    probe.borrow().ready.len(),
    1,
    "the queued message is still queued when the faulting batch is built"
  );

  let (held, queued, ended) = held_after_termination(&mut cread, &probe).await;
  // The IN-HAND batch's sender, required to COMPLETE rather than merely
  // awaited: this is the only path where `terminate_io` is handed a batch the
  // state does not hold, and a helper that ignored that argument would leave
  // this frame `Queued` for ever while a discarded timeout hid it.
  let sent = compio::time::timeout(std::time::Duration::from_secs(2), sender.as_mut())
    .await
    .expect("the in-hand batch's sender must be failed, not left queued")
    .expect_err("with the sticky kind the termination recorded");
  assert!(
    matches!(&sent, Error::Io(e) if Some(e.kind()) == first_io_kind(&ended)),
    "the sender's kind is the connection's: {sent:?} against {ended:?}"
  );
  assert!(
    matches!(&ended, Some(Error::Io(_))),
    "the write fault surfaces as an error: {ended:?}"
  );
  // MEASURED unfixed, on this shape: held=125 queued=1.
  assert_eq!(held, 0);
  assert_eq!(queued, 0);
}

#[compio::test]
async fn an_eof_in_the_parked_read_releases_what_it_holds() {
  use compio_io::{AsyncWrite as _, util::Splittable as _};

  // (c) The peer goes away with the connection still open: Phase 4's parked
  // read answers EOF. Nothing more will ever arrive, so nothing held can ever
  // be finished or delivered.
  const CHUNK: usize = 125;

  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default(),
    Vec::new(),
  );
  let (mut cread, _cwrite) = client.split();
  let probe = cread.inner.clone();
  let (sr, mut sw) = s.split();

  let mut wire = vec![0x81_u8, 3];
  wire.extend_from_slice(b"one");
  wire.push(0x81);
  wire.push(3);
  wire.extend_from_slice(b"two");
  wire.push(0x01);
  wire.push(CHUNK as u8);
  wire.extend(std::iter::repeat_n(b'H', CHUNK));
  let len = wire.len();
  let compio_buf::BufResult(res, _) = sw.write(wire).await;
  assert_eq!(res.expect("the write"), len);
  // Both whole messages are handed out first; then the peer goes away.
  drop(sw);
  drop(sr);

  let (held, queued, ended) = held_after_termination(&mut cread, &probe).await;
  assert!(
    matches!(&ended, Some(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof),
    "EOF before a close handshake is an error: {ended:?}"
  );
  // Unfixed this read 125.
  assert_eq!(held, 0, "a partial the peer will never finish is not kept");
  assert_eq!(queued, 0);
}

#[compio::test]
async fn an_eof_behind_a_blocked_write_releases_what_it_holds() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // (d) The same EOF, reached through the OTHER read: the one the flush phase
  // takes behind a blocked post-Close write.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  const CHUNK: usize = 125;
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
  }

  let (c, s) = duplex_with_capacities(PIPE_CAPACITY, 0);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(std::time::Duration::from_secs(5)),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let (mut sr, mut sw) = s.split();

  let mut head = vec![0x01_u8, CHUNK as u8];
  head.extend(std::iter::repeat_n(b'H', CHUNK));
  let head_len = head.len();
  let compio_buf::BufResult(res, _) = sw.write(head).await;
  assert_eq!(res.expect("the head"), head_len);

  let watch = probe.clone();
  let reader = compio_runtime::spawn(async move {
    let held = held_after_termination(&mut cread, &watch).await;
    (held, cread)
  });
  let waited = std::time::Instant::now();
  while probe.borrow().assembler.buffered() == 0 {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the prefix must reach the assembler first"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }

  cwrite
    .close(CloseCode::Normal, "")
    .await
    .expect("the Close flushes");
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);

  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }

  // The peer stops WRITING, and only that: its read half stays alive, so our
  // Pong batch remains merely blocked rather than broken, and the read the
  // flush phase races against it is the one that answers EOF. Dropping both
  // halves instead reaches the write-fault site, which is (b)'s subject.
  drop(sw);

  let ((held, queued, ended), _cread) =
    compio::time::timeout(std::time::Duration::from_secs(5), reader)
      .await
      .expect("the EOF ends the connection")
      .unwrap();
  assert!(
    matches!(&ended, Some(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof),
    "EOF behind the blocked write is an error: {ended:?}"
  );
  // Unfixed this read 125.
  assert_eq!(held, 0);
  assert_eq!(queued, 0);
  drop(sr);
  drop(cwrite);
}

#[compio::test]
async fn a_termination_wakes_a_sender_blocked_behind_the_wedged_batch() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // A control frame queued while a post-Close batch is wedged waits on its
  // own `FrameState`, and only the pump changes that state. A termination
  // that failed `outbound` but not the ACTIVE batch, and returned without
  // ringing the doorbell, left this sender asleep on a `Queued` state under a
  // sticky poison — nothing would ever run again to settle it.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
  }

  let (c, s) = duplex_with_capacities(PIPE_CAPACITY, 0);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_secs(30)),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let (mut sr, mut sw) = s.split();

  let watch = probe.clone();
  let reader = compio_runtime::spawn(async move {
    let held = held_after_termination(&mut cread, &watch).await;
    (held, cread)
  });

  cwrite
    .close(CloseCode::Normal, "")
    .await
    .expect("the Close flushes");
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);

  // The peer pings and stops reading: the Pong batch wedges.
  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }

  // A control frame of our own, behind that wedge, in a SPAWNED task: it must
  // be genuinely ASLEEP on the doorbell when the termination happens. A future
  // the test polls itself re-reads its frame's state on the next poll and
  // needs no wake at all, which is how a missing notify hides.
  let pinger = compio_runtime::spawn(async move {
    let outcome = cwrite.ping(b"mine").await;
    (outcome, cwrite)
  });
  let waited = std::time::Instant::now();
  while probe.borrow().outbound.is_empty() {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(1),
      "the ping must be queued behind the wedged batch"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  // The wedged batch itself is NOT observable here: `PumpIo` moves it out of
  // the shared state for the duration of the flush await, which is precisely
  // why the termination arms have to drop that guard before they can fail it
  // — and why failing only `outbound` left it behind.

  // The peer's write side goes away: the read the flush phase races answers
  // EOF, and the connection is over for good.
  drop(sw);

  // Unfixed the ping never resolved: its frame's state stayed `Queued`, the
  // active batch was left in the state, and no doorbell rang — so this timed
  // out.
  let (ping_outcome, mut cwrite) = compio::time::timeout(std::time::Duration::from_secs(2), pinger)
    .await
    .expect("a termination must wake every sender it strands")
    .unwrap();
  let ping_err = ping_outcome.expect_err("and hand it the sticky error");
  assert!(
    matches!(&ping_err, Error::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
    "with the kind the termination recorded: {ping_err:?}"
  );

  let ((_held, _queued, ended), _cread) =
    compio::time::timeout(std::time::Duration::from_secs(5), reader)
      .await
      .expect("the reader observes the termination")
      .unwrap();
  assert!(
    matches!(&ended, Some(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof),
    "{ended:?}"
  );
  {
    let guard = probe.borrow();
    assert!(
      guard.pending_write.is_none(),
      "the active batch is failed and gone, not left in the state"
    );
    assert!(guard.outbound.is_empty(), "and the queue with it");
  }
  // And a second send is refused at once by the sticky poison.
  let again = compio::time::timeout(std::time::Duration::from_secs(2), cwrite.ping(b"again"))
    .await
    .expect("a poisoned connection refuses without waiting")
    .expect_err("with the recorded kind");
  assert!(
    matches!(&again, Error::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
    "{again:?}"
  );
  drop(sr);
}

#[compio::test]
async fn phase_four_is_only_reached_with_nothing_outstanding_to_wake() {
  use compio_io::util::Splittable as _;

  // The Phase-4 EOF arm notifies the doorbell like every other termination —
  // the entrance does it, so no arm can forget — but on THIS arm the notify
  // wakes nobody, and that is a property of the pump rather than an accident
  // worth leaving unstated: Phase 2 empties `outbound` into a batch on every
  // pass and Phase 3 must finish that batch before Phase 4 is reached, so
  // when the pump parks on a read there is no `Queued` frame for a sender to
  // be waiting on. A sender CAN only be stranded where a batch and a queued
  // frame coexist, which is the flush phase — the sibling test above.
  //
  // Pinned rather than argued, because a future change that let Phase 4 be
  // reached with something outstanding would make that notify load-bearing
  // and nothing else would say so.
  let (c, s) = duplex();
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default(),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let (sr, sw) = s.split();

  // The reader IS the pump, so it starts first; only then can a send
  // complete, and only a completed send leaves the pump with nothing
  // outstanding.
  let watch = probe.clone();
  let reader = compio_runtime::spawn(async move {
    let held = held_after_termination(&mut cread, &watch).await;
    (held, cread)
  });
  cwrite
    .send_binary(&[0xCD_u8; 32])
    .await
    .expect("the peer's pipe is unbounded");
  compio::time::sleep(std::time::Duration::from_millis(30)).await;
  {
    let guard = probe.borrow();
    assert!(
      guard.outbound.is_empty(),
      "nothing is queued when the pump parks on a read"
    );
    assert!(
      guard.pending_write.is_none(),
      "and no batch is in flight either — so the EOF below strands no sender"
    );
  }

  drop(sw);

  let ((_held, _queued, ended), _cread) =
    compio::time::timeout(std::time::Duration::from_secs(5), reader)
      .await
      .expect("the EOF ends the connection")
      .unwrap();
  assert!(
    matches!(&ended, Some(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof),
    "{ended:?}"
  );
  // And a send AFTER it is refused at once by the sticky poison rather than
  // parked on a pump that will never run again.
  let refused = compio::time::timeout(
    std::time::Duration::from_secs(2),
    cwrite.send_binary(&[0x01_u8; 4]),
  )
  .await
  .expect("a poisoned connection refuses without waiting")
  .expect_err("with the recorded kind");
  assert!(
    matches!(&refused, Error::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
    "{refused:?}"
  );
  drop(sr);
}

#[compio::test]
async fn the_driver_retains_exactly_one_read_chunk() {
  use compio_io::{AsyncRead as _, AsyncWrite as _, util::Splittable as _};

  // The retained inbound bound, read off the vector rather than inferred from
  // an allocator total: ONE `READ_CHUNK`, whatever the connection has done.
  // It was two — a scratch and a stash, swapped on every read and each
  // resized back to a full chunk — so a connection that had read once held
  // ~32 KiB in two vectors. Both read paths are driven here, because the
  // recycling used to be a claim about two of them agreeing.
  const PIPE_CAPACITY: usize = 64;
  const PINGS: usize = 10;
  const PING_FRAME: [u8; 6] = [0x89, 0x04, b'p', b'i', b'n', b'g'];
  const PONG_LEN: usize = 10;
  const CLOSE_LEN: usize = 8;
  // An unmasked server-to-client Text frame with a one-byte payload.
  const DATA_FRAME: [u8; 3] = [0x81, 0x01, b'x'];
  // More than eight chunks' worth on each path.
  const FLOOD: usize = 10 * (READ_CHUNK / DATA_FRAME.len()) + 1;
  const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
  const {
    assert!(
      PINGS * PONG_LEN > PIPE_CAPACITY,
      "the Pong batch must not fit the pipe"
    );
  }

  let (c, s) = duplex_with_capacities(PIPE_CAPACITY, 0);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default().with_close_timeout(BUDGET),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();
  let probe = cread.inner.clone();
  let (mut sr, mut sw) = s.split();

  let reader = compio_runtime::spawn(async move {
    while let Some(m) = cread.next().await {
      if m.is_err() {
        break;
      }
    }
    cread
  });

  // ── the ordinary path: Phase 4's parked read, many chunks of it ──────────
  let mut flood = Vec::with_capacity(FLOOD * DATA_FRAME.len());
  for _ in 0..FLOOD {
    flood.extend_from_slice(&DATA_FRAME);
  }
  let expected = flood.len();
  let compio_buf::BufResult(res, _) = sw.write(flood).await;
  assert_eq!(res.expect("the flood"), expected);
  let waited = std::time::Instant::now();
  while probe.borrow().reads_seen < 8 {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(2),
      "the ordinary read path must run at least eight times; it ran {}",
      probe.borrow().reads_seen
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  {
    let guard = probe.borrow();
    // Unfixed this was two vectors of 16 384 each, so 32 768 between them.
    assert_eq!(
      guard.inbound_capacity_high_water, READ_CHUNK,
      "one chunk retained across {} ordinary reads",
      guard.reads_seen
    );
  }

  // ── the read-behind path: the same vector, the other phase ───────────────
  cwrite
    .close(CloseCode::Normal, "")
    .await
    .expect("the Close flushes");
  let compio_buf::BufResult(res, _ours) = sr.read(Vec::with_capacity(PIPE_CAPACITY)).await;
  assert_eq!(res.expect("the peer drains our Close"), CLOSE_LEN);
  let mut pings = Vec::new();
  for _ in 0..PINGS {
    pings.extend_from_slice(&PING_FRAME);
  }
  let compio_buf::BufResult(res, _) = sw.write(pings).await;
  res.expect("the pings");
  let mut seen = probe.borrow().pings_seen;
  let waited = std::time::Instant::now();
  while seen < PINGS {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(2),
      "the driver must owe {PINGS} pongs; it counted {seen}"
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    seen = probe.borrow().pings_seen;
  }
  let mut flood = Vec::with_capacity(FLOOD * DATA_FRAME.len());
  for _ in 0..FLOOD {
    flood.extend_from_slice(&DATA_FRAME);
  }
  let expected = flood.len();
  let compio_buf::BufResult(res, _) = sw.write(flood).await;
  assert_eq!(res.expect("the second flood"), expected);
  let waited = std::time::Instant::now();
  while probe.borrow().observation_reads < 8 {
    assert!(
      waited.elapsed() < std::time::Duration::from_secs(2),
      "the read-behind path must run at least eight times; it ran {}",
      probe.borrow().observation_reads
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  {
    let guard = probe.borrow();
    assert_eq!(
      guard.inbound_capacity_high_water, READ_CHUNK,
      "and one chunk across {} reads behind the blocked write",
      guard.observation_reads
    );
  }

  // Let it end so the test does not leave a task parked.
  let compio_buf::BufResult(res, _) = sw.write(vec![0x88_u8, 0x02, 0x03, 0xE8]).await;
  res.expect("the peer's Close");
  let cread = compio::time::timeout(std::time::Duration::from_secs(5), reader)
    .await
    .expect("the close handshake completes")
    .unwrap();
  assert!(cread.closed().expect("an outcome").clean());
  assert_eq!(
    probe.borrow().inbound_capacity(),
    READ_CHUNK,
    "and still one chunk at the end"
  );
  drop(cwrite);
  drop(sr);
}

#[compio::test]
async fn a_cancelled_read_gives_back_the_window_it_armed() {
  use std::future::Future;

  // ONE inbound vector means its `len` IS the protocol's unconsumed input, so
  // an armed-but-uncommitted read window is 16 KiB of zeros this driver wrote
  // sitting where the peer's bytes go. Every ordinary exit from a read commits
  // the window; a caller that drops `next()` from inside the `.await` has no
  // exit to commit on, and the guard's own drop is what must give it back.
  // Unfixed, the next pass fed those zeros to `handle` as if the peer had sent
  // them — a continuation frame with no message — and the connection died.
  //
  // The two-buffer design could not have this defect: a scratch separate from
  // the input carried no meaning in its `len`. It is the price of one vector,
  // and it is paid in `PumpIo::drop`.
  let (mut client, mut server) = pair();
  let probe = server.inner.clone();
  {
    let mut fut = Box::pin(server.next());
    futures_util::future::poll_fn(|cx| {
      assert!(
        fut.as_mut().poll(cx).is_pending(),
        "the pump must park on its read for there to be a window to cancel"
      );
      std::task::Poll::Ready(())
    })
    .await;
  }
  {
    let guard = probe.borrow();
    assert!(
      guard.inbound.is_empty(),
      "the cancelled read left {} bytes of its own window behind",
      guard.inbound.len()
    );
    assert_eq!(
      guard.inbound_capacity(),
      READ_CHUNK,
      "and gave back the window without giving back the allocation"
    );
  }
  // The connection still reads what the peer ACTUALLY sends.
  client.send_text("after cancel").await.unwrap();
  let m = server
    .next()
    .await
    .expect("a message rather than a terminal outcome")
    .expect("and not a protocol error over zeros nobody sent");
  assert_eq!(m, Message::Text("after cancel".into()));
}
