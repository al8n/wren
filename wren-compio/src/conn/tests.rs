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

  // The peer stops reading entirely: the carrying batch can never flush.
  // close_timeout must still bound the handshake — the flush phase gets
  // the budget, then everything fails and the transport tears down.
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
    while let Some(m) = cread.next().await {
      m.unwrap();
    }
    cread
  });
  let close_err = compio::time::timeout(std::time::Duration::from_secs(2), closer)
    .await
    .expect("the close resolves within the budget")
    .unwrap()
    .unwrap_err();
  assert!(
    matches!(&close_err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
    "the parked closer fails with the timeout, got {close_err:?}"
  );
  let cread = compio::time::timeout(std::time::Duration::from_secs(2), reader)
    .await
    .expect("the reader observes the outcome")
    .unwrap();
  assert!(
    !cread.closed().unwrap().clean(),
    "a never-draining peer is an unclean close"
  );
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
