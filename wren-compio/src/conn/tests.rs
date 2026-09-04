use super::*;
use crate::{
  IntoDuplex,
  duplex::{Pipe, duplex, duplex_with_capacity, duplex_with_write_fault},
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
  // flushed, `close_pending` is clear and `close_flushed_at` is anchored — and a
  // peer Ping arriving then produces a Pong-only batch with
  // `carries_close == false`. The old two-way timer choice parked exactly that
  // batch on `pending()`, so a peer that stops reading wedges it forever and the
  // bound `close_timeout` documents is defeated. Nothing on `main` reached here:
  // post-Close Pongs were suppressed, and this branch created the case.
  //
  // The pipe is 64 bytes: the 64 KiB carrying batch still drains through it (the
  // drainer just reads more times), but the ten 10-byte masked Pongs the driver
  // owes (100 bytes) cannot fit once the peer stops reading.
  let (c, s) = duplex_with_capacity(64);
  let negotiated = Negotiated::none();
  let client = WebSocket::<ClientRole, _>::client(
    c.into_duplex(),
    &negotiated,
    &crate::options::ClientOptions::default()
      .with_close_timeout(std::time::Duration::from_millis(200)),
    Vec::new(),
  );
  let (mut cread, mut cwrite) = client.split();

  // 64 KiB queued without waiting for delivery, then the Close: one carrying
  // batch, exactly as the model test builds it.
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
  let _sr = compio::time::timeout(std::time::Duration::from_secs(5), drainer)
    .await
    .expect("the carrying batch drains")
    .unwrap();

  // From here the peer never reads again. The Close is on the wire and the echo
  // budget is running.
  let t0 = std::time::Instant::now();
  let mut pings = Vec::new();
  for _ in 0..10 {
    pings.extend_from_slice(&[0x89, 0x04, b'p', b'i', b'n', b'g']);
  }
  let compio_buf::BufResult(written, _) = sw.write(pings).await;
  written.expect("60 bytes of pings fit the 64-byte pipe");

  // Ten owed Pongs coalesce into one post-Close batch of 100 bytes, which
  // cannot fit, so the write wedges with `carries_close == false` and
  // `close_pending == false` — Codex's path exactly.
  let (ended, cread) = compio::time::timeout(std::time::Duration::from_secs(2), reader)
    .await
    .expect(
      "a post-Close Pong flush is bounded by the REMAINING echo budget \
       (`close_flushed_at + close_budget`), not parked unbounded because the \
       batch carries no Close and `close_pending` is already clear",
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

  let _ = compio::time::timeout(std::time::Duration::from_secs(2), closer).await;
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
