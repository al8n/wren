use super::*;
use crate::duplex::{Pipe, duplex, duplex_with_capacity};
use agnostic_lite::tokio::TokioRuntime;

type Client = WebSocket<TokioRuntime, ClientRole, Pipe>;
type Server = WebSocket<TokioRuntime, ServerRole, Pipe>;

fn pair() -> (Client, Server) {
  pair_with(Default::default(), Default::default())
}

fn pair_cap(cap: usize) -> (Client, Server) {
  let (c, s) = duplex_with_capacity(cap);
  let n = Negotiated::none();
  (
    WebSocket::client(c, &n, &Default::default(), Vec::new()),
    WebSocket::server(s, &n, &Default::default(), Vec::new()),
  )
}

fn pair_with(
  co: crate::options::ClientOptions,
  so: crate::options::AcceptOptions,
) -> (Client, Server) {
  let (c, s) = duplex();
  let n = Negotiated::none();
  (
    WebSocket::client(c, &n, &co, Vec::new()),
    WebSocket::server(s, &n, &so, Vec::new()),
  )
}

#[tokio::test]
async fn echo_text_round_trip() {
  let (mut client, mut server) = pair();
  client.send_text("hello").await.unwrap();
  let task = tokio::spawn(async move {
    let m = server.next().await.unwrap().unwrap();
    server.send(m).await.unwrap();
    server
  });
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("hello".into()));
  drop(task.await);
}

#[tokio::test]
async fn large_binary_round_trip() {
  let (mut client, mut server) = pair();
  let payload = vec![0xAB_u8; 1 << 20];
  let expect = payload.clone();
  let task = tokio::spawn(async move {
    let m = server.next().await.unwrap().unwrap();
    assert_eq!(m, Message::Binary(expect.into()));
  });
  client.send_binary(&payload).await.unwrap();
  task.await.unwrap();
}

#[tokio::test]
async fn inbound_arrives_while_outbound_is_backpressured() {
  // The property wren-compio's single pump could not satisfy: a large
  // outbound write to a slow-reading peer must NOT delay inbound delivery.
  // 4 KiB pipes in both directions; the client pushes a 1 MiB outbound the
  // server does not drain yet, while the server's small messages must reach
  // the client's reader promptly.
  let (client, server) = pair_cap(4 * 1024);
  let (mut cread, mut cwrite) = client.split();
  let (mut sread, mut swrite) = server.split();

  let big = vec![0xCD_u8; 1 << 20];
  let expect = big.clone();
  // Client writer: stuck pushing 1 MiB (server reads it only later).
  let client_writer = tokio::spawn(async move {
    cwrite.send_binary(&big).await.unwrap();
    cwrite
  });
  // Server: send 5 small messages first, THEN drain the big inbound.
  let server_task = tokio::spawn(async move {
    for i in 0..5u32 {
      swrite.send_text(&format!("s{i}")).await.unwrap();
    }
    let m = sread.next().await.unwrap().unwrap();
    assert_eq!(m, Message::Binary(expect.into()));
    (sread, swrite)
  });

  // The client receives all 5 promptly while its writer is backpressured.
  for i in 0..5u32 {
    let m = tokio::time::timeout(std::time::Duration::from_secs(5), cread.next())
      .await
      .expect("inbound delivered while outbound is backpressured")
      .unwrap()
      .unwrap();
    assert_eq!(m, Message::Text(format!("s{i}").into()));
  }
  client_writer.await.unwrap();
  drop(server_task.await.unwrap());
}

#[tokio::test]
async fn ping_flood_with_a_stuck_writer_backpressures() {
  // Reading generates outbound (a pong per ping). If the writer is stuck —
  // the peer never drains our pongs — the driver must stop reading once the
  // outbound queue backs up, rather than buffering pongs without bound. We
  // prove that by flooding masked client pings while never reading the
  // victim's pongs: the victim stops draining, so this large write blocks.
  use futures_util::{AsyncReadExt as _, AsyncWriteExt as _};
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let _victim =
    WebSocket::<TokioRuntime, ServerRole, Pipe>::server(v, &n, &Default::default(), Vec::new());
  // Masked client ping, empty payload (FIN+ping, MASK+len0, 4-byte key).
  let ping = [0x89u8, 0x80, 0x12, 0x34, 0x56, 0x78];
  let flood: Vec<u8> = std::iter::repeat_n(ping, 20_000).flatten().collect();
  // Keep the read half alive (so pongs buffer in the pipe) but never read it.
  let (_peer_read, mut peer_write) = peer.split();
  let r = tokio::time::timeout(Duration::from_secs(2), peer_write.write_all(&flood)).await;
  assert!(
    r.is_err(),
    "victim must stop draining once outbound is backed up"
  );
}

#[tokio::test]
async fn writer_does_not_leak_on_a_stuck_write() {
  // A frame larger than the pipe is queued, then every app handle is dropped
  // while the writer is blocked mid-write on a peer that never drains. The
  // driver's exit must release the writer rather than leave it pending forever.
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let _peer = peer; // kept alive but never read → the writer blocks, not errors
  let (vread, mut vwrite) = victim.split();
  let probe = vread.shared_for_test();
  // Stick the writer on a frame larger than the pipe, then pile enough behind it
  // to fill the outbound queue, so the command arm is exercised while the queue
  // is full — it must still observe the handles dropping and shut the
  // connection (and the stuck writer) down.
  vwrite.try_enqueue(Message::Binary(vec![0u8; 1 << 20].into()));
  for _ in 0..24 {
    vwrite.try_enqueue(Message::Binary(vec![0u8; 64].into()));
  }
  drop(vwrite);
  drop(vread);
  let released = tokio::time::timeout(Duration::from_secs(5), async {
    while !probe.writer_done() {
      tokio::task::yield_now().await;
    }
  })
  .await;
  assert!(
    released.is_ok(),
    "a stuck writer must terminate when all handles drop"
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_both_halves_tears_down_in_any_order() {
  // Drop order must not leak: drop the WriteHalf first (the driver notes it but
  // stays up for the reader), then drop the ReadHalf while the connection is IDLE.
  // The driver must still observe the reader drop, finish, and tear the writer
  // down. (Regression: with no arm watching the reader drop, an idle driver parked
  // on `read` forever, leaking both tasks.)
  let (client, _server) = pair(); // keep the peer so the client never EOFs
  let (cread, cwrite) = client.split();
  let probe = cread.shared_for_test();
  drop(cwrite);
  // Let the driver observe the write-handle drop while the reader is still alive.
  tokio::time::sleep(Duration::from_millis(20)).await;
  drop(cread); // reader gone while idle (no inbound, keepalive off)
  let released = tokio::time::timeout(Duration::from_secs(5), async {
    while !probe.writer_done() {
      tokio::task::yield_now().await;
    }
  })
  .await;
  assert!(
    released.is_ok(),
    "both tasks must tear down once both halves drop, regardless of order"
  );
}

#[tokio::test]
async fn close_completes_when_outbound_is_backpressured() {
  // The outbound queue is full and the writer is stuck (peer never reads). A
  // close must still be accepted and its deadline armed, so the handshake
  // resolves (unclean) within the timeout instead of hanging behind the queue.
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_close_timeout(Duration::from_millis(100));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let _peer = peer; // never read → the writer blocks and the queue backs up
  let (mut vread, mut vwrite) = victim.split();
  vwrite.try_enqueue(Message::Binary(vec![0u8; 1 << 20].into()));
  for _ in 0..24 {
    vwrite.try_enqueue(Message::Binary(vec![0u8; 64].into()));
  }
  let drive = async move {
    vwrite.close(CloseCode::Normal, "bye").await.unwrap();
    while vread.next().await.is_some() {}
    vread
  };
  let vread = tokio::time::timeout(Duration::from_secs(2), drive)
    .await
    .expect("close must complete under outbound backpressure");
  // The peer never reads, so the close resolves uncleanly — either via the close
  // deadline (unclean `Closed`) or, since the writer can make no progress, via the
  // write timeout (an `Io` transport failure interrupting the close, `closed()`
  // left `None`). Both mean "did not close cleanly, within the bound".
  assert!(
    vread.closed().is_none_or(|c| !c.clean()),
    "a close to a non-reading peer does not complete cleanly"
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_completes_when_out_queue_is_saturated_by_pongs() {
  // out_queue is held full by a continuous ping flood (each ping makes a pong)
  // while the writer is stuck (the peer never reads). A close issued in this state
  // must still arm its deadline and complete — proto arms the close deadline only
  // when the one-shot Close frame actually drains, so that frame has to get out
  // even though the staging queue is at the cap. (Regression: gating ALL proto
  // transmits at the cap held the Close frame in proto, so the deadline never
  // armed and close hung forever.)
  use futures_util::AsyncWriteExt as _;
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_close_timeout(Duration::from_millis(100));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let (mut vread, mut vwrite) = victim.split();
  let (_peer_read, mut peer_write) = peer.split();
  // Continuously flood unmasked server pings so the victim keeps making pongs; the
  // peer never reads them, so the writer stalls and out_queue saturates.
  let flooder = tokio::spawn(async move {
    let ping = [0x89u8, 0x00]; // unmasked empty ping (server -> client)
    let chunk: Vec<u8> = std::iter::repeat_n(ping, 4096).flatten().collect();
    while peer_write.write_all(&chunk).await.is_ok() {}
  });
  // Let the flood saturate out_queue (reads gated, writer stuck).
  tokio::time::sleep(Duration::from_millis(200)).await;
  // The close must still complete (uncleanly, via the deadline) rather than hang.
  let drive = async move {
    let _ = vwrite.close(CloseCode::Normal, "bye").await;
    while vread.next().await.is_some() {}
    vread
  };
  let vread = tokio::time::timeout(Duration::from_secs(3), drive)
    .await
    .expect("close must complete even when out_queue is saturated by pongs");
  assert!(
    vread.closed().is_none_or(|c| !c.clean()),
    "a deadline close under saturation is unclean"
  );
  flooder.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_stall_tears_down_when_peer_stops_reading() {
  // The close-liveness class, resolved structurally. A peer floods pings to
  // saturate our outbound queue with pongs and then stops reading; the read arm
  // gates on out_full and the writer is stalled, so with no close in flight every
  // select arm would park forever. The outbound-stall deadline must instead tear
  // the connection down within the bound and surface the failure, rather than hang.
  use futures_util::AsyncWriteExt as _;
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_write_timeout(Duration::from_millis(150));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let (mut vread, _vwrite) = victim.split();
  let (_peer_read, mut peer_write) = peer.split();
  let flooder = tokio::spawn(async move {
    let ping = [0x89u8, 0x00]; // unmasked empty ping (server -> client)
    let chunk: Vec<u8> = std::iter::repeat_n(ping, 4096).flatten().collect();
    while peer_write.write_all(&chunk).await.is_ok() {}
  });
  let outcome = tokio::time::timeout(Duration::from_secs(5), async {
    let mut last = None;
    while let Some(m) = vread.next().await {
      last = Some(m);
    }
    last
  })
  .await
  .expect("a peer that stops reading must not hang the connection");
  assert!(
    matches!(outcome, Some(Err(Error::Io(_)))),
    "the outbound stall must surface as an Io error (got {outcome:?})"
  );
  flooder.abort();
}

#[tokio::test]
async fn a_lone_send_to_a_non_reading_peer_times_out() {
  // A single large send to a peer that stops reading parks the writer mid-write
  // with nothing queued behind it (the frame has already left out_queue). The
  // writer's no-progress timeout must fail the send rather than hang forever — a
  // driver-side queue-depth clock would miss this case entirely.
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_write_timeout(Duration::from_millis(150));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let _peer = peer; // never read → the writer parks mid-write
  let (_vread, mut vwrite) = victim.split();
  let err = tokio::time::timeout(
    Duration::from_secs(5),
    vwrite.send_binary(&vec![0u8; 1 << 20]),
  )
  .await
  .expect("a send to a non-reading peer must not hang")
  .unwrap_err();
  assert!(
    matches!(err, Error::Io(_)),
    "the stalled write must surface as Io (got {err:?})"
  );
}

#[tokio::test]
async fn clean_close_flushes_queued_frames_under_backpressure() {
  // A peer-initiated close arrives while our writer is backed up behind a large
  // frame. The queued frame and our close echo must still be flushed before we
  // tear down, so the peer receives the full message and a clean close — rather
  // than the writer being aborted mid-frame.
  use futures_util::SinkExt;
  let (c, s) = duplex_with_capacity(4 * 1024);
  let n = Negotiated::none();
  let client =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &Default::default(), Vec::new());
  let server =
    WebSocket::<TokioRuntime, ServerRole, Pipe>::server(s, &n, &Default::default(), Vec::new());
  let (mut cread, mut cwrite) = client.split();
  let (sread, mut swrite) = server.split();

  let big = vec![0x5A_u8; 256 * 1024];
  let expect = big.clone();
  // Server queues a large frame while the client is not yet reading → the
  // server writer backs up on the small pipe.
  swrite.feed(Message::Binary(big.into())).await.unwrap();
  // Client initiates the close; the server echoes it behind the queued frame.
  cwrite.close(CloseCode::Normal, "bye").await.unwrap();
  // The client now drains: it must receive the whole large frame, then a clean
  // close — proving the server flushed both instead of aborting them.
  let received = tokio::time::timeout(Duration::from_secs(5), async {
    let m = cread.next().await.unwrap().unwrap();
    assert_eq!(m, Message::Binary(expect.into()));
    assert!(cread.next().await.is_none());
    cread.closed().unwrap()
  })
  .await
  .expect("clean close must flush queued frames");
  assert!(received.clean(), "the close completed cleanly");
  drop((sread, swrite));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_close_with_queued_data_drains_a_slow_peer() {
  // A SELF-initiated close behind a large queued frame must flush all of it to a
  // slow-but-progressing peer. The close-echo deadline is anchored at when the
  // writer flushes the Close, not when proto drained it into the queue — otherwise
  // the deadline fires during the data flush and abandons it.
  use futures_util::{AsyncReadExt as _, SinkExt};
  let (v, peer) = duplex_with_capacity(4 * 1024);
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_close_timeout(Duration::from_millis(100));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let (_vread, mut vwrite) = victim.split();
  vwrite
    .feed(Message::Binary(vec![0x5A_u8; 256 * 1024].into()))
    .await
    .unwrap();
  // Close in a task: it now awaits the fed write (confirm_pending), which needs
  // the peer to drain concurrently.
  let closer = tokio::spawn(async move {
    let _ = vwrite.close(CloseCode::Normal, "bye").await;
    vwrite
  });
  // The peer reads our output SLOWLY (4 KiB / 5 ms ⇒ ≫ the 100 ms close timeout).
  let (mut peer_read, _peer_write) = peer.split();
  let got = tokio::time::timeout(Duration::from_secs(20), async {
    let mut got = 0usize;
    let mut buf = vec![0u8; 4096];
    loop {
      let nr = peer_read.read(&mut buf).await.unwrap_or(0);
      if nr == 0 {
        break;
      }
      got += nr;
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    got
  })
  .await
  .expect("the slow drain must finish");
  let _hold = closer.await;
  assert!(
    got >= 256 * 1024,
    "queued data flushed before the close-echo deadline, even to a slow peer (got {got})"
  );
}

#[tokio::test]
async fn clean_close_echo_write_failure_surfaces() {
  // A peer-initiated clean close whose echo write faults must NOT be reported as
  // a clean close. The writer records the failure in write_err and exits, which
  // bypasses the WriterGone arm that normally surfaces it — so the terminal
  // clean-drain has to surface it instead. (Regression: the clean-drain called
  // finish() without consulting write_err, masking the failure as None /
  // Closed(clean).)
  use futures_util::AsyncWriteExt as _;
  // The victim's first transport write — its close echo — faults, then recovers.
  let (v, peer) = crate::duplex::duplex_with_write_fault(0);
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let (mut vread, _vwrite) = victim.split();
  // Feed an unmasked server Close (Normal, 1000): the client records a clean
  // close and queues the echo, whose write then faults.
  let (_peer_read, mut peer_write) = peer.split();
  peer_write
    .write_all(&[0x88, 0x02, 0x03, 0xE8])
    .await
    .unwrap();
  let first = tokio::time::timeout(Duration::from_secs(5), vread.next())
    .await
    .expect("the reader must not hang");
  assert!(
    matches!(first, Some(Err(Error::Io(_)))),
    "the close-echo write failure must surface, not a clean close (got {first:?})"
  );
}

#[tokio::test]
async fn failed_close_keeps_the_connection_usable() {
  // An invalid close code must not enter closing mode: the close fails and the
  // connection stays usable, so a later send still completes. (Regression: the
  // driver set closing before proto validated the code, wedging the command
  // arm shut and stranding subsequent sends.)
  let (client, mut server) = pair();
  let (cread, mut cwrite) = client.split();
  // 1005 NoStatusReceived is reserved — proto rejects it in a Close frame.
  let err = cwrite
    .close(CloseCode::NoStatusReceived, "")
    .await
    .unwrap_err();
  assert!(
    matches!(err, Error::Encode(_)),
    "invalid close code is rejected"
  );
  let m = tokio::time::timeout(Duration::from_secs(2), async {
    cwrite.send_text("still alive").await.unwrap();
    server.next().await.unwrap().unwrap()
  })
  .await
  .expect("connection stays usable after a failed close");
  assert_eq!(m, Message::Text("still alive".into()));
  drop((cread, cwrite));
}

#[tokio::test]
async fn writer_does_not_leak_when_transport_close_stalls() {
  // A clean close over a Duplex whose poll_close never completes (a hung TLS
  // close_notify) must not leak the writer: the grace expires and the final
  // transport close is aborted by the shutdown signal.
  use futures_util::{AsyncReadExt as _, AsyncWriteExt as _};
  let (v, peer) = crate::duplex::duplex_with_stalling_close();
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_close_timeout(Duration::from_millis(100));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let (vread, _vwrite) = victim.split();
  let probe = vread.shared_for_test();
  // Feed an unmasked server Close (Normal, 1000): the client echoes and the
  // close completes cleanly, so the writer reaches its final transport close.
  let (_peer_read, mut peer_write) = peer.split();
  peer_write
    .write_all(&[0x88, 0x02, 0x03, 0xE8])
    .await
    .unwrap();
  let released = tokio::time::timeout(Duration::from_secs(5), async {
    while !probe.writer_done() {
      tokio::task::yield_now().await;
    }
  })
  .await;
  assert!(
    released.is_ok(),
    "writer must not leak when transport close stalls"
  );
}

#[tokio::test]
async fn stalled_final_close_surfaces_io() {
  // A clean WebSocket close whose final transport shutdown stalls must not be
  // reported as fully clean: the writer's close deadline records the timeout,
  // surfaced to the reader as Io. (Regression: the final close error/timeout was
  // discarded, so a stalled shutdown read as a clean close.)
  use futures_util::AsyncWriteExt as _;
  let (v, peer) = crate::duplex::duplex_with_stalling_close();
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_close_timeout(Duration::from_millis(100));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let (mut vread, _vwrite) = victim.split();
  // Peer initiates a clean close (unmasked server Close, 1000); the client echoes
  // and completes the handshake, then its final transport close stalls.
  let (_peer_read, mut peer_write) = peer.split();
  peer_write
    .write_all(&[0x88, 0x02, 0x03, 0xE8])
    .await
    .unwrap();
  let outcome = tokio::time::timeout(Duration::from_secs(5), async {
    let mut last = None;
    while let Some(m) = vread.next().await {
      last = Some(m);
    }
    last
  })
  .await
  .expect("the reader must not hang");
  assert!(
    matches!(outcome, Some(Err(Error::Io(_)))),
    "a stalled final transport close surfaces as Io (got {outcome:?})"
  );
}

#[tokio::test]
async fn sink_backpressures_on_a_stuck_writer() {
  // The Sink must backpressure on the actual write: with a non-reading peer,
  // feeding many large messages cannot all complete (which would grow the
  // outbound queue without bound) — each feed blocks on the prior write.
  use futures_util::SinkExt;
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let _peer = peer; // never read → the writer stays stuck
  let (_vread, mut vwrite) = victim.split();
  let pump = async {
    for _ in 0..1000 {
      vwrite
        .feed(Message::Binary(vec![0u8; 4096].into()))
        .await
        .unwrap();
    }
  };
  let r = tokio::time::timeout(Duration::from_secs(2), pump).await;
  assert!(r.is_err(), "Sink must backpressure on a stuck writer");
}

#[tokio::test]
async fn sink_surfaces_write_error_not_closed() {
  // After a transport write fault poisons the connection, using the WriteHalf as
  // a Sink must surface the real Io error — not a generic Closed, and (the worse
  // case) not a silently-flushed Ok, since mpsc's poll_flush treats a dropped
  // receiver as flushed. (Regression: the Sink mapped channel closure to Closed
  // and never consulted write_err, and poll_flush lost the fault entirely.)
  use futures_util::SinkExt;
  let (c, _s) = crate::duplex::duplex_with_write_fault(0); // first transport write faults
  let n = Negotiated::none();
  let client =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &Default::default(), Vec::new());
  let (_vread, mut vwrite) = client.split();
  // Trigger the fault and confirm the connection is poisoned (write_err recorded).
  let err = vwrite.send_binary(&[0u8; 100]).await.unwrap_err();
  assert!(
    matches!(err, Error::Io(_)),
    "the write fault surfaces on the inherent send"
  );
  // The Sink must report the same Io error — on flush (the silent-Ok case)...
  let flushed = SinkExt::flush(&mut vwrite).await;
  assert!(
    matches!(flushed, Err(Error::Io(_))),
    "Sink flush must surface the write error, not a clean flush (got {flushed:?})"
  );
  // ...and on send (the Closed-masking case).
  let sent = SinkExt::send(&mut vwrite, Message::Text("x".into())).await;
  assert!(
    matches!(sent, Err(Error::Io(_))),
    "Sink send must surface Io, not Closed (got {sent:?})"
  );
}

#[tokio::test]
async fn sink_send_confirms_the_write() {
  // SinkExt::send must not return Ok for a frame whose write then fails: poll_flush
  // awaits the queued write's result and surfaces the Io. (Regression: start_send
  // dropped the reply, so the Sink acknowledged before the writer's result.)
  use futures_util::SinkExt;
  let (c, _s) = crate::duplex::duplex_with_write_fault(0); // the frame's write faults
  let n = Negotiated::none();
  let client =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &Default::default(), Vec::new());
  let (_vread, mut vwrite) = client.split();
  let sent = tokio::time::timeout(
    Duration::from_secs(5),
    SinkExt::send(&mut vwrite, Message::Text("x".into())),
  )
  .await
  .expect("send must not hang");
  assert!(
    matches!(sent, Err(Error::Io(_))),
    "Sink send must confirm the write and surface Io (got {sent:?})"
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inherent_close_flushes_queued_sink_writes() {
  // `feed(..)` then the inherent `close(..)` must deliver the fed frame: close
  // confirms queued Sink writes before the control-plane close — otherwise the
  // close can set `closing` before the fed data is admitted, dropping it. Repeated
  // to defeat the underlying data-vs-control ordering race.
  use futures_util::SinkExt;
  for _ in 0..20 {
    let (client, server) = pair();
    let (cread, mut cwrite) = client.split();
    let (mut sread, _swrite) = server.split();
    cwrite.feed(Message::Text("queued".into())).await.unwrap();
    cwrite.close(CloseCode::Normal, "bye").await.unwrap();
    let m = tokio::time::timeout(Duration::from_secs(2), sread.next())
      .await
      .expect("must not hang")
      .expect("the fed frame must be delivered before close, not dropped")
      .unwrap();
    assert_eq!(m, Message::Text("queued".into()));
    drop((cread, sread));
  }
}

#[tokio::test]
async fn sink_close_after_write_fault_reports_the_error() {
  // A repeated Sink close after a transport write fault must report the Io error,
  // not mask it as a clean close via the close_sent fast path. (Regression: the
  // close_sent check ran before the write_err check.)
  use futures_util::SinkExt;
  let (c, _s) = crate::duplex::duplex_with_write_fault(0); // first transport write faults
  let n = Negotiated::none();
  let client =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &Default::default(), Vec::new());
  let (vread, mut vwrite) = client.split();
  let probe = vread.shared_for_test();
  // First close queues the Normal close (close_sent = true) and returns Ok.
  SinkExt::close(&mut vwrite).await.unwrap();
  // The queued close frame's write then faults; wait for write_err to be recorded.
  tokio::time::timeout(Duration::from_secs(2), async {
    while probe.write_err().is_none() {
      tokio::task::yield_now().await;
    }
  })
  .await
  .expect("the close-frame write must fault");
  // A repeated close now reports the error rather than the close_sent Ok.
  let again = SinkExt::close(&mut vwrite).await;
  assert!(
    matches!(again, Err(Error::Io(_))),
    "a repeated close after a write fault must report Io (got {again:?})"
  );
}

#[tokio::test]
async fn write_error_does_not_hang_when_flush_stalls() {
  // A transport that errors the write and then stalls the flush must still
  // surface the error to the sender, not park the writer forever in flush.
  let (c, _s) = crate::duplex::duplex_with_write_fault_then_stuck_flush();
  let n = Negotiated::none();
  let mut client =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &Default::default(), Vec::new());
  let err = tokio::time::timeout(Duration::from_secs(2), client.send_binary(&[0u8; 100]))
    .await
    .expect("send must not hang when flush stalls after a write error")
    .unwrap_err();
  assert!(matches!(err, Error::Io(_)), "the write error surfaces");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_data_transfer_to_a_silent_reader_completes() {
  // A large app-data send to a peer that reads SLOWLY and sends nothing back must
  // simply complete via backpressure — never false-aborted. The library imposes no
  // autonomous write deadline (tungstenite parity), so a slow-but-progressing
  // transfer is never killed; only the opt-in `write_timeout` (unset here) would.
  use futures_util::AsyncReadExt as _;
  let (v, peer) = duplex_with_capacity(4 * 1024);
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default();
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let (_vread, mut vwrite) = victim.split();
  // The peer reads SLOWLY (4 KiB / 5 ms) and never writes anything.
  let (mut peer_read, _peer_write) = peer.split();
  let reader = tokio::spawn(async move {
    let mut buf = vec![0u8; 4096];
    loop {
      tokio::time::sleep(Duration::from_millis(5)).await;
      match peer_read.read(&mut buf).await {
        Ok(0) | Err(_) => break,
        Ok(_) => {}
      }
    }
  });
  let res = tokio::time::timeout(
    Duration::from_secs(10),
    vwrite.send_binary(&vec![0x5A_u8; 512 * 1024]),
  )
  .await
  .expect("a steadily-progressing transfer must not hang");
  assert!(
    res.is_ok(),
    "a long transfer to a slow-but-reading peer must not be false-failed (got {res:?})"
  );
  reader.abort();
}

#[tokio::test]
async fn peer_clean_close_over_a_stalling_flush_is_bounded() {
  // A peer-initiated clean close whose echo flush never completes (a buffered
  // transport whose peer stopped reading) must be bounded by the liveness
  // deadline in the clean-drain — surfacing Io rather than hanging the driver
  // forever awaiting the writer. (Regression: the clean-drain awaited the writer
  // unconditionally, with no liveness servicing, so a stuck flush deadlocked the
  // driver against a writer parked in `flush`.)
  use futures_util::AsyncWriteExt as _;
  let (v, peer) = crate::duplex::duplex_with_stalling_flush();
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default()
    .with_keepalive(Some(Duration::from_millis(20)))
    .with_close_timeout(Duration::from_millis(50));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let (mut vread, _vwrite) = victim.split();
  // Feed an unmasked server Close (Normal, 1000): the client records a clean close
  // and queues the echo, whose flush then stalls.
  let (_peer_read, mut peer_write) = peer.split();
  peer_write
    .write_all(&[0x88, 0x02, 0x03, 0xE8])
    .await
    .unwrap();
  let outcome = tokio::time::timeout(Duration::from_secs(5), vread.next())
    .await
    .expect("a stalling close-echo flush must not hang the driver");
  assert!(
    matches!(outcome, Some(Err(Error::Io(_)))),
    "a stalled clean-drain flush must surface Io (got {outcome:?})"
  );
}

#[tokio::test]
async fn cancelled_close_keeps_pending_confirmations() {
  // confirm_pending must be cancellation-safe: a close cancelled while awaiting a
  // fed Sink write must leave that confirmation in the queue, so a retried close
  // re-confirms it instead of skipping ahead — which would let `closing` be set
  // before the data is admitted and silently drop it. (Regression: confirm_pending
  // popped each receiver BEFORE awaiting, so a cancelled close lost the token.)
  use futures_util::SinkExt;
  // The writer parks on its first write, so the fed frame never gets confirmed.
  let (v, peer, _trigger) = crate::duplex::duplex_with_stalled_then_faulting_write();
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let _peer = peer; // keep the transport open
  let (_vread, mut vwrite) = victim.split();
  // Feed one frame via the Sink: its confirmation is now pending.
  vwrite
    .feed(Message::Binary(vec![0u8; 64].into()))
    .await
    .unwrap();
  assert_eq!(vwrite.pending_len(), 1, "the fed write awaits confirmation");
  // Poll an inherent close exactly once, then drop (cancel) it: confirm_pending
  // parks on the pending receiver, and the cancellation must not consume it.
  {
    let mut close_fut = std::pin::pin!(vwrite.close(CloseCode::Normal, "bye"));
    assert!(
      futures_util::poll!(close_fut.as_mut()).is_pending(),
      "close parks on confirm_pending while the write is unconfirmed"
    );
    // `close_fut` dropped here → the close is cancelled mid-confirm.
  }
  assert_eq!(
    vwrite.pending_len(),
    1,
    "a cancelled close must not drop the pending confirmation"
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unread_inbound_backpressure_keeps_the_connection_alive() {
  // The app pausing its reads (local inbound backpressure) must not break the
  // connection: there is no autonomous liveness, so a paused reader is never
  // misread as a dead peer. The connection survives and keeps delivering buffered
  // data once the app resumes (tungstenite parity).
  use futures_util::SinkExt;
  let co = crate::options::ClientOptions::default();
  let (client, server) = pair_with(co, crate::options::AcceptOptions::default());
  let (mut cread, _cwrite) = client.split();
  let (sread, mut swrite) = server.split();
  // Keep the server reading (so it stays alive and answers the client's pings).
  let s_drainer = tokio::spawn(async move {
    let mut sread = sread;
    while sread.next().await.is_some() {}
  });
  // Flood the client with messages; it backs up once the client stops draining.
  let flooder = tokio::spawn(async move {
    for i in 0..300u32 {
      if swrite
        .feed(Message::Binary(vec![i as u8; 8].into()))
        .await
        .is_err()
      {
        break;
      }
    }
    let _ = swrite.flush().await;
    swrite
  });
  // The client does NOT read for well past the 70 ms liveness timeout, so its
  // inbound staging fills and the driver gates reads (last_inbound frozen).
  tokio::time::sleep(Duration::from_millis(200)).await;
  // Now drain: the connection must still be alive and deliver data — no Io.
  let mut ok = 0usize;
  let result = tokio::time::timeout(Duration::from_secs(5), async {
    while ok < 64 {
      match cread.next().await {
        Some(Ok(_)) => ok += 1,
        Some(Err(e)) => return Err(e),
        None => return Ok(()),
      }
    }
    Ok(())
  })
  .await
  .expect("draining must not hang");
  assert!(
    result.is_ok() && ok >= 64,
    "unread inbound backpressure must not be failed as peer silence (ok={ok}, result={result:?})"
  );
  flooder.abort();
  s_drainer.abort();
}

#[tokio::test]
async fn write_timeout_bounds_a_stuck_close_flush() {
  // A SELF close whose Close-frame flush never completes (a buffered transport
  // whose peer stopped reading) is bounded by the opt-in write_timeout and
  // surfaces Io rather than hanging the driver. Keepalive is off so write_timeout
  // is unambiguously the bound — by contract, disabling keepalive WITHOUT setting
  // write_timeout would leave such a flush unbounded.
  let (v, _peer) = crate::duplex::duplex_with_stalling_flush();
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default()
    .with_keepalive(None)
    .with_write_timeout(Duration::from_millis(50));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let res = tokio::time::timeout(
    Duration::from_secs(5),
    victim.close(CloseCode::Normal, "bye"),
  )
  .await
  .expect("write_timeout must bound a stuck close flush");
  assert!(
    matches!(res, Err(Error::Io(_))),
    "the stuck Close flush must surface Io, not hang (got {res:?})"
  );
}

#[tokio::test]
async fn write_timeout_bounds_a_stuck_open_send_flush() {
  // An ordinary (open-phase) send whose flush stalls is bounded by write_timeout —
  // independent of keepalive, and NOT by close_timeout (which governs only the
  // close handshake). Keepalive and close_timeout are set far away so write_timeout
  // is provably the bound.
  let (v, _peer) = crate::duplex::duplex_with_stalling_flush();
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default()
    .with_keepalive(Some(Duration::from_secs(30)))
    .with_close_timeout(Duration::from_secs(30))
    .with_write_timeout(Duration::from_millis(50));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let (_vread, mut vwrite) = victim.split();
  let err = tokio::time::timeout(Duration::from_secs(5), vwrite.send_binary(&[0u8; 100]))
    .await
    .expect("write_timeout must bound a stuck open-send flush")
    .unwrap_err();
  assert!(
    matches!(err, Error::Io(_)),
    "the stuck open-send flush surfaces Io (got {err:?})"
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_timeout_does_not_abort_a_slow_open_send() {
  // close_timeout governs the close handshake ONLY; it must NOT bound ordinary send
  // flushes. With keepalive off and write_timeout unset, a send whose flush drains
  // SLOWLY (the peer reads, but slower than close_timeout) must still COMPLETE, not
  // be false-aborted. (Regression: a prior fix reused close_timeout as the
  // per-frame flush deadline, killing healthy slow transports.)
  use futures_util::AsyncReadExt as _;
  let (v, peer) = crate::duplex::duplex_with_draining_flush();
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default()
    .with_keepalive(None)
    .with_close_timeout(Duration::from_millis(50));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let (_vread, mut vwrite) = victim.split();
  // The peer reads slowly (64 B / 10 ms ⇒ a 512 B frame drains over ~80 ms ≫ the
  // 50 ms close_timeout) but DOES drain — a healthy slow transport.
  let (mut peer_read, _peer_write) = peer.split();
  let reader = tokio::spawn(async move {
    let mut buf = vec![0u8; 64];
    loop {
      tokio::time::sleep(Duration::from_millis(10)).await;
      match peer_read.read(&mut buf).await {
        Ok(0) | Err(_) => break,
        Ok(_) => {}
      }
    }
  });
  let res = tokio::time::timeout(Duration::from_secs(5), vwrite.send_binary(&[0x5A_u8; 512]))
    .await
    .expect("the slow send must not hang");
  assert!(
    res.is_ok(),
    "close_timeout must not abort a slow-but-progressing open send (got {res:?})"
  );
  reader.abort();
}

#[tokio::test]
async fn a_cancelled_send_is_still_delivered_once_admitted() {
  // Cancellation-safety is NOT transactional: once a send's command is admitted to
  // the channel (which happens before the future resolves with the write result),
  // the frame is delivered even if the caller drops the future. A timed-out send may
  // therefore already be on the wire and must not be blindly retried. This pins the
  // contract so the docs cannot drift back to implying retry-safety.
  let (client, server) = pair();
  let (cread, mut cwrite) = client.split();
  let (mut sread, _swrite) = server.split();
  // Poll the send exactly once — that admits the command, then awaits the write
  // result — and drop it, cancelling AFTER admission.
  {
    let mut fut = std::pin::pin!(cwrite.send_binary(b"hello"));
    let _ = futures_util::poll!(fut.as_mut());
  }
  // The frame is delivered despite the cancellation.
  let msg = tokio::time::timeout(Duration::from_secs(2), sread.next())
    .await
    .expect("the admitted frame must be delivered, not hang")
    .expect("a message")
    .expect("a clean message");
  assert_eq!(
    msg,
    Message::Binary(b"hello".to_vec().into()),
    "an admitted-then-cancelled send is still delivered"
  );
  drop((cread, cwrite));
}

#[tokio::test]
async fn close_delivers_a_cancelled_admitted_send() {
  // The "admitted send is still delivered" contract must hold even when a local close
  // FOLLOWS the cancelled send. The close travels the control plane, which the driver
  // services independently, so it must not overtake a data command already buffered in
  // the data channel and let the `closing` state reject it. (Regression: handle_close
  // set `closing` before draining admitted data, dropping the parked send.)
  use futures_util::poll;
  let (client, server) = pair_cap(64); // tiny pipe → the victim's writer stalls when the server isn't reading
  let (cread, mut cwrite) = client.split();
  let (mut sread, _swrite) = server.split();
  // Saturate outbound so the data arm gates and further sends PARK in the data channel
  // (the server is not reading yet, so the writer stalls on the oversized first frame).
  cwrite.try_enqueue(Message::Binary(vec![0u8; 4096].into()));
  for _ in 0..24 {
    cwrite.try_enqueue(Message::Binary(vec![7u8; 8].into()));
  }
  tokio::time::sleep(Duration::from_millis(20)).await;
  // Admit-then-cancel a DISTINCTIVE send: it parks in the gated data channel.
  {
    let mut fut = std::pin::pin!(cwrite.send_binary(b"CANCELLED_X"));
    let _ = poll!(fut.as_mut());
  }
  // Local close: must drain + deliver the parked send before applying `closing`.
  cwrite.close(CloseCode::Normal, "bye").await.unwrap();
  // The server now reads everything; the cancelled-but-admitted send must be among it,
  // not dropped by the close that followed it.
  let mut found = false;
  loop {
    let next = tokio::time::timeout(Duration::from_secs(5), sread.next())
      .await
      .expect("the server must not hang");
    match next {
      Some(Ok(msg)) => {
        if msg == Message::Binary(b"CANCELLED_X".to_vec().into()) {
          found = true;
        }
      }
      Some(Err(_)) => continue,
      None => break,
    }
  }
  assert!(
    found,
    "a send cancelled after admission is delivered despite a following local close"
  );
  drop((cread, cwrite));
}

#[tokio::test]
async fn queued_send_sees_io_not_closed_after_write_error() {
  // A send sits unadmitted in the data channel (the data arm is gated because the
  // outbound queue is saturated and the writer is stalled). When the writer then
  // hits a transport fault, the driver terminates and drops that command — its
  // reply is dropped, not answered. The send must surface the real Io error, not
  // a generic Closed. (Regression: issue() mapped the dropped reply straight to
  // Closed without rechecking write_err.)
  let (v, peer, fault) = crate::duplex::duplex_with_stalled_then_faulting_write();
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let _peer = peer; // held; the writer stalls writing to it
  let (vread, mut vwrite) = victim.split();
  // Saturate the outbound queue so the data arm is gated; the stalled writer keeps
  // it that way, so a further command stays parked in the data channel.
  for _ in 0..40 {
    vwrite.try_enqueue(Message::Binary(vec![0u8; 64].into()));
  }
  for _ in 0..50 {
    tokio::task::yield_now().await;
  }
  // This send is queued but never admitted (the data arm is gated).
  let send = tokio::spawn(async move { vwrite.send_binary(&[0u8; 64]).await });
  for _ in 0..5 {
    tokio::task::yield_now().await;
  }
  // The stalled write now faults: the driver terminates and drops the queued send.
  fault.fire();
  let err = tokio::time::timeout(Duration::from_secs(5), send)
    .await
    .expect("the queued send must resolve once the writer fails")
    .unwrap()
    .unwrap_err();
  assert!(
    matches!(err, Error::Io(_)),
    "a send dropped when the writer fails must surface Io, not Closed (got {err:?})"
  );
  drop(vread);
}

#[tokio::test]
async fn cancelled_sends_stay_backpressured() {
  // Polling a send until its command is queued, then dropping it, must not slip
  // the frame past write backpressure. Repeated cancellations against a stuck
  // writer must keep the outbound queue bounded, not grow it without end.
  use futures_util::FutureExt as _;
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let _peer = peer; // never read → the writer stays stuck
  let (vread, mut vwrite) = victim.split();
  let probe = vread.shared_for_test();
  // Each send is polled once (enough to queue its command) then dropped.
  for _ in 0..50 {
    let _ = vwrite.send_binary(&[0u8; 4096]).now_or_never();
  }
  // Let the driver process anything that was queued.
  for _ in 0..100 {
    tokio::task::yield_now().await;
  }
  let peak = probe.out_queue_peak();
  assert!(
    peak < 10,
    "cancelled sends must stay bounded; peak out_queue was {peak}"
  );
}

#[tokio::test]
async fn sink_close_sends_a_websocket_close() {
  // Closing the Sink must perform a real WebSocket close so the peer observes
  // it, rather than merely dropping the command channel.
  use futures_util::SinkExt;
  let (client, mut server) = pair();
  let (_cread, mut cwrite) = client.split();
  let server_task = tokio::spawn(async move {
    assert!(server.next().await.is_none());
    server.closed().unwrap()
  });
  SinkExt::close(&mut cwrite).await.unwrap();
  let closed = tokio::time::timeout(Duration::from_secs(2), server_task)
    .await
    .expect("Sink close must make the peer observe a close")
    .unwrap();
  assert_eq!(closed.code(), CloseCode::Normal);
  assert!(closed.clean());
}

// Multi-threaded so the flooder refills the inbound pipe concurrently with the
// driver draining it, keeping reads continuously ready — the condition under
// which biased reads would starve commands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_flood_does_not_starve_local_progress() {
  // A peer flooding control frames that yield no app messages must not starve
  // command/timer servicing behind biased reads: local send and close must
  // still make progress.
  use futures_util::{AsyncReadExt as _, AsyncWriteExt as _};
  let (v, peer) = duplex_with_capacity(256 * 1024);
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let (vread, mut vwrite) = victim.split();
  let (mut peer_read, mut peer_write) = peer.split();
  // Drain V's output so its writer never blocks (isolate scheduling from
  // write backpressure).
  let drainer = tokio::spawn(async move {
    let mut buf = vec![0u8; 16 * 1024];
    while peer_read.read(&mut buf).await.unwrap_or(0) > 0 {}
  });
  // Continuously flood unsolicited unmasked server Pongs: no app message, no
  // echo, so the inbound/outbound queues never fill and reads stay ready.
  let flooder = tokio::spawn(async move {
    let chunk: Vec<u8> = std::iter::repeat_n([0x8Au8, 0x00], 8192)
      .flatten()
      .collect();
    while peer_write.write_all(&chunk).await.is_ok() {}
  });
  // Let the flood reach steady state (reads continuously ready) before sending.
  tokio::time::sleep(Duration::from_millis(200)).await;
  let sent = tokio::time::timeout(Duration::from_secs(5), vwrite.send_text("hi")).await;
  assert!(
    matches!(sent, Ok(Ok(()))),
    "send must progress under inbound flood"
  );
  let closed =
    tokio::time::timeout(Duration::from_secs(5), vwrite.close(CloseCode::Normal, "")).await;
  assert!(
    matches!(closed, Ok(Ok(()))),
    "close must progress under inbound flood"
  );
  flooder.abort();
  drainer.abort();
  drop(vread);
}

// Multi-threaded so the client's send stream and the driver run concurrently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_sends_do_not_starve_inbound() {
  // A continuous stream of local sends must not starve inbound delivery: fair
  // scheduling services reads alongside commands (strict command priority would
  // delay the peer's message and Close).
  let (client, server) = pair();
  let (mut cread, mut cwrite) = client.split();
  let (mut sread, mut swrite) = server.split();
  // Server drains the client's stream so the client's writer never blocks.
  let s_drainer = tokio::spawn(async move { while sread.next().await.is_some() {} });
  // Client sends continuously (backpressured by reply-on-write).
  let c_sender = tokio::spawn(async move { while cwrite.send_text("x").await.is_ok() {} });
  tokio::time::sleep(Duration::from_millis(100)).await;
  swrite.send_text("from server").await.unwrap();
  let got = tokio::time::timeout(Duration::from_secs(5), cread.next()).await;
  assert!(
    matches!(got, Ok(Some(Ok(_)))),
    "inbound must arrive while the local side is sending"
  );
  c_sender.abort();
  s_drainer.abort();
}

#[tokio::test]
async fn close_propagates_a_read_side_failure() {
  // A transport failure that interrupts the close drain must surface as the
  // real error, not a generic `Closed`.
  let (c, peer) = duplex(); // unbounded, so the Close write never blocks
  let n = Negotiated::none();
  let client =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &Default::default(), Vec::new());
  // End the whole transport shortly after the close starts draining.
  tokio::spawn(async move {
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(peer);
  });
  let err = client.close(CloseCode::Normal, "").await.unwrap_err();
  assert!(
    !matches!(err, Error::Closed),
    "close must surface the real failure, not generic Closed (got {err:?})"
  );
}

#[tokio::test]
async fn close_surfaces_error_under_full_inbound() {
  // The inbound channel is full of unread messages when the transport fails.
  // The real error must still surface from close (durably), not be dropped
  // behind the stale messages and masked as a generic Closed.
  let (client, server) = pair();
  let (sread, mut swrite) = server.split();
  // Send more messages than the inbound channel holds, then end the transport.
  for _ in 0..40 {
    swrite.send_text("x").await.unwrap();
  }
  drop(sread);
  drop(swrite);
  // Let the client buffer the messages and observe the EOF.
  tokio::time::sleep(Duration::from_millis(100)).await;
  let err = client.close(CloseCode::Normal, "").await.unwrap_err();
  assert!(
    !matches!(err, Error::Closed),
    "the real failure must surface under a full inbound channel (got {err:?})"
  );
}

#[tokio::test]
async fn close_completes_after_a_cancelled_stuck_send() {
  // A send polled until queued then dropped leaves a stuck write reply pending.
  // Close must not block on it: it abandons the token, arms the close path, and
  // resolves (uncleanly, via the deadline).
  use futures_util::FutureExt as _;
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_close_timeout(Duration::from_millis(100));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let _peer = peer; // never read → the writer stays stuck
  let (mut vread, mut vwrite) = victim.split();
  let _ = vwrite.send_binary(&vec![0u8; 1 << 20]).now_or_never();
  let drive = async move {
    vwrite.close(CloseCode::Normal, "bye").await.unwrap();
    while vread.next().await.is_some() {}
    vread
  };
  let vread = tokio::time::timeout(Duration::from_secs(2), drive)
    .await
    .expect("close must complete after a cancelled stuck send");
  assert!(
    vread.closed().is_none_or(|c| !c.clean()),
    "a deadline close is unclean"
  );
}

#[tokio::test]
async fn unsplit_close_with_invalid_code_returns_error() {
  // An invalid close code never arms the close handshake, so the unsplit
  // `close` must return the validation error promptly, not hang draining a
  // live connection.
  let (client, _server) = pair();
  let err = tokio::time::timeout(
    Duration::from_secs(2),
    client.close(CloseCode::NoStatusReceived, ""),
  )
  .await
  .expect("close must not hang on invalid input")
  .unwrap_err();
  assert!(
    matches!(err, Error::Encode(_)),
    "invalid close code surfaces (got {err:?})"
  );
}

#[tokio::test]
async fn invalid_close_rejected_promptly_despite_pending_sink_write() {
  // An invalid close never arms a handshake, so it must be rejected IMMEDIATELY —
  // even with a Sink write stuck behind a non-reading peer and no write_timeout. It
  // must not wait on confirm_pending. (Regression: close validated only AFTER
  // confirm_pending, so an invalid close hung on the stuck write.)
  use futures_util::SinkExt;
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let _peer = peer; // never read → the fed write never confirms (no write_timeout)
  let (_vread, mut vwrite) = victim.split();
  // Feed a frame the non-reading peer never drains → a stuck pending confirmation.
  vwrite
    .feed(Message::Binary(vec![0u8; 1 << 20].into()))
    .await
    .unwrap();
  let err = tokio::time::timeout(
    Duration::from_secs(5),
    vwrite.close(CloseCode::NoStatusReceived, ""),
  )
  .await
  .expect("an invalid close must not hang on a pending write")
  .unwrap_err();
  assert!(
    matches!(err, Error::Encode(_)),
    "invalid close code is rejected promptly (got {err:?})"
  );
}

#[tokio::test]
async fn oversized_ping_rejected_promptly_under_saturated_outbound() {
  // An oversized ping (> 125 B control limit) never reaches the wire, so it must be
  // rejected IMMEDIATELY — even with the outbound queue saturated behind a stuck
  // writer — not wedged waiting for admission. Same invalid-input-before-
  // backpressure class as the invalid-close fix.
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let _peer = peer; // never read → the writer stalls and the outbound queue fills
  let (_vread, mut vwrite) = victim.split();
  // Stick the writer on a frame larger than the pipe, then pile enough behind it to
  // saturate the outbound queue (gating the data arm).
  vwrite.try_enqueue(Message::Binary(vec![0u8; 1 << 20].into()));
  for _ in 0..24 {
    vwrite.try_enqueue(Message::Binary(vec![0u8; 64].into()));
  }
  tokio::time::sleep(Duration::from_millis(20)).await;
  let err = tokio::time::timeout(Duration::from_secs(5), vwrite.ping(&[0u8; 200]))
    .await
    .expect("an oversized ping must not wedge behind the full outbound queue")
    .unwrap_err();
  assert!(
    matches!(err, Error::Encode(_)),
    "oversized ping is rejected promptly (got {err:?})"
  );
}

#[cfg(feature = "deflate")]
#[tokio::test]
async fn compressed_send_rejected_promptly_when_deflate_unavailable() {
  // A compressed send on a connection without usable permessage-deflate is
  // guaranteed to fail with CompressionUnavailable, so it must be rejected
  // IMMEDIATELY — even with the outbound queue saturated behind a stuck writer —
  // not wedged waiting for admission. Same invalid-input-before-backpressure class
  // as the invalid-close and oversized-ping fixes, on the compressed data path.
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none(); // deflate not negotiated → compression unavailable
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let _peer = peer; // never read → the writer stalls and the outbound queue fills
  let (_vread, mut vwrite) = victim.split();
  // Stick the writer on a frame larger than the pipe, then pile enough behind it to
  // saturate the outbound queue (gating the data arm).
  vwrite.try_enqueue(Message::Binary(vec![0u8; 1 << 20].into()));
  for _ in 0..24 {
    vwrite.try_enqueue(Message::Binary(vec![0u8; 64].into()));
  }
  tokio::time::sleep(Duration::from_millis(20)).await;
  let err = tokio::time::timeout(Duration::from_secs(5), vwrite.send_text_compressed("nope"))
    .await
    .expect("a doomed compressed send must not wedge behind the full outbound queue")
    .unwrap_err();
  assert!(
    matches!(
      err,
      Error::Encode(websocket_proto::connection::EncodeError::CompressionUnavailable)
    ),
    "compressed send without deflate is rejected promptly (got {err:?})"
  );
}

#[cfg(feature = "deflate")]
#[tokio::test]
async fn compressed_send_after_write_fault_reports_io_not_unavailable() {
  // On a no-deflate connection that has already recorded a transport write error, a
  // compressed send must surface the real Io cause — like every other send path —
  // not mask it as CompressionUnavailable. (Regression: ensure_compressible ran
  // before the write_err preflight, so a poisoned connection reported the wrong
  // terminal cause.)
  let (c, _s) = crate::duplex::duplex_with_write_fault(0); // first transport write faults
  let n = Negotiated::none(); // no deflate negotiated
  let client =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &Default::default(), Vec::new());
  let (vread, mut vwrite) = client.split();
  let probe = vread.shared_for_test();
  // Provoke the fault: the first send triggers the writer's faulting transport write.
  let _ = vwrite.send_binary(&[0u8; 100]).await;
  tokio::time::timeout(Duration::from_secs(2), async {
    while probe.write_err().is_none() {
      tokio::task::yield_now().await;
    }
  })
  .await
  .expect("the first write must fault");
  let err = vwrite.send_text_compressed("x").await.unwrap_err();
  assert!(
    matches!(err, Error::Io(_)),
    "a compressed send after a write fault reports Io, not CompressionUnavailable (got {err:?})"
  );
}

#[tokio::test]
async fn sends_after_peer_clean_close_return_closed_promptly() {
  // After a peer-initiated clean close the driver enters its bounded clean-drain and
  // stops servicing the data plane. A send issued in that window must fail fast with
  // Closed, not wedge until the drain bound elapses. (Regression: issue checked only
  // write_err, not the closed outcome, so a post-close send parked behind the drain.)
  use futures_util::AsyncWriteExt as _;
  // Stalling close → the final transport shutdown hangs, so the clean-drain occupies
  // the full (default 10 s) close budget — far longer than the assertion window.
  let (v, peer) = crate::duplex::duplex_with_stalling_close();
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let (vread, mut vwrite) = victim.split();
  let probe = vread.shared_for_test();
  // Peer sends an unmasked clean Close (Normal, 1000); the victim records it and
  // heads into its (stalled) clean-drain.
  let (_peer_read, mut peer_write) = peer.split();
  peer_write
    .write_all(&[0x88, 0x02, 0x03, 0xE8])
    .await
    .unwrap();
  tokio::time::timeout(Duration::from_secs(5), async {
    while !probe.is_closed() {
      tokio::task::yield_now().await;
    }
  })
  .await
  .expect("the victim must record the peer close");
  // A send now must not wait out the drain bound.
  let r = tokio::time::timeout(Duration::from_secs(2), vwrite.send_text("late")).await;
  assert!(
    matches!(r, Ok(Err(Error::Closed))),
    "a post-peer-close send returns Closed promptly (got {r:?})"
  );
}

#[tokio::test]
async fn sink_send_after_peer_clean_close_fails_fast() {
  // The Sink admission path (poll_ready/start_send) must also fail fast on a closed
  // connection — not admit a frame that then waits out the clean-drain in poll_flush.
  // (SinkExt::send is named explicitly because the inherent `send` shadows it.)
  use futures_util::{AsyncWriteExt as _, SinkExt};
  let (v, peer) = crate::duplex::duplex_with_stalling_close();
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let (vread, mut vwrite) = victim.split();
  let probe = vread.shared_for_test();
  let (_peer_read, mut peer_write) = peer.split();
  peer_write
    .write_all(&[0x88, 0x02, 0x03, 0xE8])
    .await
    .unwrap();
  tokio::time::timeout(Duration::from_secs(5), async {
    while !probe.is_closed() {
      tokio::task::yield_now().await;
    }
  })
  .await
  .expect("the victim must record the peer close");
  let r = tokio::time::timeout(
    Duration::from_secs(2),
    SinkExt::send(&mut vwrite, Message::Text("late".into())),
  )
  .await;
  assert!(
    matches!(r, Ok(Err(Error::Closed))),
    "a Sink send after a peer clean close fails fast with Closed (got {r:?})"
  );
}

#[tokio::test]
async fn oversized_ping_after_write_fault_reports_io() {
  // An oversized ping on a poisoned connection must report the real Io cause, not be
  // masked by the control-length guard. (Regression: ping ran the length check before
  // the terminal preflight, so the guard shadowed the terminal cause.)
  let (c, _s) = crate::duplex::duplex_with_write_fault(0);
  let n = Negotiated::none();
  let client =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &Default::default(), Vec::new());
  let (vread, mut vwrite) = client.split();
  let probe = vread.shared_for_test();
  let _ = vwrite.send_binary(&[0u8; 100]).await; // trigger the faulting first write
  tokio::time::timeout(Duration::from_secs(2), async {
    while probe.write_err().is_none() {
      tokio::task::yield_now().await;
    }
  })
  .await
  .expect("the first write must fault");
  let err = vwrite.ping(&[0u8; 200]).await.unwrap_err(); // oversized AND poisoned
  assert!(
    matches!(err, Error::Io(_)),
    "an oversized ping on a poisoned connection reports Io, not ControlTooLong (got {err:?})"
  );
}

#[tokio::test]
async fn oversized_ping_after_peer_clean_close_reports_closed() {
  // An oversized ping after a peer clean close must report the terminal Closed, not be
  // masked by the control-length guard.
  use futures_util::AsyncWriteExt as _;
  let (v, peer) = crate::duplex::duplex_with_stalling_close();
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let (vread, mut vwrite) = victim.split();
  let probe = vread.shared_for_test();
  let (_peer_read, mut peer_write) = peer.split();
  peer_write
    .write_all(&[0x88, 0x02, 0x03, 0xE8])
    .await
    .unwrap();
  tokio::time::timeout(Duration::from_secs(5), async {
    while !probe.is_closed() {
      tokio::task::yield_now().await;
    }
  })
  .await
  .expect("the victim must record the peer close");
  let r = tokio::time::timeout(Duration::from_secs(2), vwrite.ping(&[0u8; 200])).await;
  assert!(
    matches!(r, Ok(Err(Error::Closed))),
    "an oversized ping after a peer clean close reports Closed promptly (got {r:?})"
  );
}

#[tokio::test]
async fn sink_close_after_peer_clean_close_torn_down_is_ok() {
  // SinkExt::close on a connection the peer already closed cleanly must report Ok
  // idempotently — even after the driver has fully torn down and dropped the control
  // channel. (Regression: poll_close mapped the gone control channel to Closed, so the
  // result was timing-dependent: Ok during clean-drain, Err(Closed) after teardown.)
  use futures_util::{AsyncWriteExt as _, SinkExt};
  let (v, peer) = duplex(); // clean teardown (no stall)
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let (mut vread, mut vwrite) = victim.split();
  let (_peer_read, mut peer_write) = peer.split();
  peer_write
    .write_all(&[0x88, 0x02, 0x03, 0xE8])
    .await
    .unwrap();
  // Drain to None: the clean close completes and the driver tears down (control
  // channel dropped) before we call close.
  tokio::time::timeout(Duration::from_secs(5), async {
    while vread.next().await.is_some() {}
  })
  .await
  .expect("the reader must reach the close");
  let r = tokio::time::timeout(Duration::from_secs(2), SinkExt::close(&mut vwrite)).await;
  assert!(
    matches!(r, Ok(Ok(()))),
    "a Sink close after a clean peer-close teardown is Ok (got {r:?})"
  );
}

#[tokio::test]
async fn terminal_closure_closes_the_command_channel_before_drain() {
  // When the driver records closure it closes its command receivers, making the
  // channel the atomic admission gate: a send racing the close cannot be queued onto a
  // connection the driver will no longer service. With a stalled clean-drain the
  // channel must close promptly, not at teardown ~10 s later. (Closes the TOCTOU
  // enqueue race the preflight-only check left open.)
  use futures_util::AsyncWriteExt as _;
  let (v, peer) = crate::duplex::duplex_with_stalling_close();
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let (vread, vwrite) = victim.split();
  let (_peer_read, mut peer_write) = peer.split();
  peer_write
    .write_all(&[0x88, 0x02, 0x03, 0xE8])
    .await
    .unwrap();
  let closed = tokio::time::timeout(Duration::from_secs(3), async {
    while !vwrite.data_channel_closed() {
      tokio::task::yield_now().await;
    }
  })
  .await;
  assert!(
    closed.is_ok(),
    "the command channel closes at terminal closure, before the stalled clean-drain teardown"
  );
  let _ = vread;
}

#[tokio::test]
async fn command_channel_closes_on_peer_close_even_before_terminal() {
  // The driver rejects queued commands and closes the receivers the moment it RECORDS
  // closure, not only at terminal. With inbound left buffered (app not reading) the
  // connection never reaches terminal, yet the command channel must still close — else
  // a peer-initiated close (which does not set `closing`) would leave the data arm
  // gated by outbound backpressure and a queued/racing send could hang waiting for a
  // terminal that never arrives. (Regression for the pre-terminal hang.)
  use futures_util::AsyncWriteExt as _;
  let (v, peer) = crate::duplex::duplex_with_capacity(1 << 16);
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let (vread, vwrite) = victim.split(); // vread is NEVER polled → inbound stays buffered
  let (_peer_read, mut peer_write) = peer.split();
  // 40 unmasked zero-length server binary frames (0x82 0x00) overflow the inbound
  // channel (cap 32) so the driver's in_queue stays non-empty → not terminal. Then a
  // clean close (1000), read while the read arm is not yet inbound-gated.
  let mut bytes = Vec::new();
  for _ in 0..40 {
    bytes.extend_from_slice(&[0x82, 0x00]);
  }
  bytes.extend_from_slice(&[0x88, 0x02, 0x03, 0xE8]);
  peer_write.write_all(&bytes).await.unwrap();
  let closed = tokio::time::timeout(Duration::from_secs(3), async {
    while !vwrite.data_channel_closed() {
      tokio::task::yield_now().await;
    }
  })
  .await;
  assert!(
    closed.is_ok(),
    "the command channel closes when closure is recorded, even before terminal is reached"
  );
  let _ = vread;
}

#[tokio::test]
async fn failed_close_preserves_backpressure_after_cancelled_send() {
  // A rejected (invalid) close leaves the connection live, so it must NOT
  // discard the backpressure token from a cancelled stuck send — otherwise
  // repeated cancel-send + invalid-close would grow the outbound queue.
  use futures_util::FutureExt as _;
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let _peer = peer; // never read → the writer stays stuck
  let (vread, mut vwrite) = victim.split();
  let probe = vread.shared_for_test();
  for _ in 0..50 {
    let _ = vwrite.send_binary(&[0u8; 4096]).now_or_never();
    let _ = vwrite.close(CloseCode::NoStatusReceived, "").await;
  }
  for _ in 0..50 {
    tokio::task::yield_now().await;
  }
  let peak = probe.out_queue_peak();
  assert!(
    peak < 10,
    "backpressure preserved after failed closes; peak out_queue {peak}"
  );
}

#[tokio::test]
async fn commands_after_accepted_close_return_promptly() {
  // After an accepted close to a peer that never echoes (so the connection
  // stays in the closing state), a further send must fail fast (Closed) rather
  // than stall: the data arm stays serviced while closing (separate from the
  // always-serviced control plane) and replies promptly.
  let (v, peer) = duplex();
  let n = Negotiated::none();
  let victim =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &Default::default(), Vec::new());
  let _peer = peer; // raw pipe, never echoes → the client stays closing
  let (_vread, mut vwrite) = victim.split();
  vwrite.close(CloseCode::Normal, "bye").await.unwrap();
  let r = tokio::time::timeout(Duration::from_secs(2), vwrite.send_text("late")).await;
  assert!(
    matches!(r, Ok(Err(Error::Closed))),
    "a post-close send returns Closed promptly (got {r:?})"
  );
}

use std::time::Duration;

#[tokio::test]
async fn close_handshake_completes() {
  let (client, mut server) = pair();
  let server_task = tokio::spawn(async move {
    assert!(server.next().await.is_none());
    let c = server.closed().unwrap();
    assert_eq!(c.code(), CloseCode::Normal);
    assert!(c.clean());
  });
  let closed = client.close(CloseCode::Normal, "bye").await.unwrap();
  assert!(closed.clean());
  server_task.await.unwrap();
}

#[tokio::test]
async fn keepalive_pings_flow_while_idle() {
  let co = crate::options::ClientOptions::default().with_keepalive(Some(Duration::from_millis(50)));
  let (mut client, mut server) = pair_with(co, Default::default());
  // Both pumps idle: the client keepalive emits pings, the server auto-pongs,
  // and no data message surfaces — so the experiment times out.
  let outcome = tokio::time::timeout(Duration::from_millis(400), async {
    tokio::select! {
      m = client.next() => m,
      m = server.next() => m,
    }
  })
  .await;
  assert!(outcome.is_err(), "no data message may surface");
  assert!(server.pings_seen() >= 1, "server saw the keepalive ping(s)");
}

#[tokio::test]
async fn keepalive_under_a_stuck_writer_stays_bounded() {
  // With keepalive on and a peer that never drains, the timer re-arms a ping
  // every interval. Those protocol frames must respect the outbound bound — proto
  // coalesces a pending ping into a single flag — so out_queue cannot grow one
  // frame per interval. (Regression: drain_transmits appended every proto frame
  // to out_queue with no capacity gate, so keepalive against a stalled writer
  // grew it without bound, outside the channel/queue caps.)
  let (v, peer) = duplex_with_capacity(1024);
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_keepalive(Some(Duration::from_millis(5)));
  let victim = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(v, &n, &co, Vec::new());
  let _peer = peer; // never read → the writer stays stuck and out_tx fills
  let (vread, mut vwrite) = victim.split();
  let probe = vread.shared_for_test();
  // Stick the writer on a frame larger than the pipe and fill the queue to the cap.
  vwrite.try_enqueue(Message::Binary(vec![0u8; 1 << 20].into()));
  for _ in 0..24 {
    vwrite.try_enqueue(Message::Binary(vec![0u8; 64].into()));
  }
  // Let many keepalive intervals elapse against the stuck writer.
  tokio::time::sleep(Duration::from_millis(300)).await;
  let peak = probe.out_queue_peak();
  assert!(
    peak <= OUTBOUND_CAP,
    "keepalive under a stuck writer must stay bounded; peak out_queue was {peak} (cap {OUTBOUND_CAP})"
  );
  drop((vread, vwrite));
}

#[tokio::test]
async fn close_deadline_fires_without_peer_echo() {
  let (c, _held_open) = duplex(); // the peer never answers
  let n = Negotiated::none();
  let co = crate::options::ClientOptions::default().with_close_timeout(Duration::from_millis(80));
  let client = WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &co, Vec::new());
  let closed = client.close(CloseCode::Normal, "").await.unwrap();
  assert!(!closed.clean(), "deadline close is unclean");
}

#[tokio::test]
async fn write_half_close_drives_through_reader() {
  let (mut client, server) = pair();
  let (mut sread, mut swrite) = server.split();
  let reader = tokio::spawn(async move {
    while sread.next().await.is_some() {}
    sread
  });
  swrite.close(CloseCode::Normal, "done").await.unwrap();
  assert!(client.next().await.is_none());
  assert_eq!(client.closed().unwrap().code(), CloseCode::Normal);
  let sread = reader.await.unwrap();
  assert!(sread.closed().unwrap().clean());
}

#[tokio::test]
async fn pong_flushes_before_buffered_data_delivery() {
  let (mut client, mut server) = pair();
  // Ping + Text land in the server's pipe before it polls once.
  client.ping(b"are-you-there").await.unwrap();
  client.send_text("data").await.unwrap();
  let m = server.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("data".into()));
  // The Pong is already on the wire: the client sees it with no more server
  // polls (RFC 6455 §5.5.3 "as soon as practical").
  let outcome = tokio::time::timeout(Duration::from_millis(100), client.next()).await;
  assert!(outcome.is_err(), "no data message surfaces on the client");
  assert_eq!(client.pongs_seen(), 1, "the pong reached the client");
}

#[tokio::test]
async fn write_error_poisons_the_connection() {
  // The transport accepts 4 KiB, fails one write, then recovers.
  let (c, s) = crate::duplex::duplex_with_write_fault(4 * 1024);
  let n = Negotiated::none();
  let mut client =
    WebSocket::<TokioRuntime, ClientRole, Pipe>::client(c, &n, &Default::default(), Vec::new());
  let _server =
    WebSocket::<TokioRuntime, ServerRole, Pipe>::server(s, &n, &Default::default(), Vec::new());

  let payload = vec![0xAA_u8; 64 * 1024];
  let err = client.send_binary(&payload).await.unwrap_err();
  let Error::Io(first) = err else {
    panic!("write fault surfaces as Io, got {err:?}");
  };
  // A partial frame is on the wire; nothing may be spliced after it.
  let err = client.send_text("tail").await.unwrap_err();
  assert!(matches!(&err, Error::Io(e) if e.kind() == first.kind()));
  let err = client.next().await.unwrap().unwrap_err();
  assert!(matches!(&err, Error::Io(e) if e.kind() == first.kind()));
}

#[tokio::test]
async fn sends_survive_read_half_drop() {
  let (mut client, server) = pair();
  let (sread, mut swrite) = server.split();
  drop(sread);
  // The writer keeps working — it owns proto + the write transport.
  swrite.send_text("after drop").await.unwrap();
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("after drop".into()));
  // Dropping the writer too closes the transport: the peer sees EOF.
  drop(swrite);
  match client.next().await {
    None => {}
    Some(Err(Error::Io(_))) => {}
    other => panic!("expected EOF after both halves drop, got {other:?}"),
  }
}

#[tokio::test]
async fn sends_survive_read_half_drop_even_when_peer_sends() {
  // Send-only usage: the ReadHalf is dropped, then the PEER sends a data message.
  // The driver must DROP the undeliverable inbound (no reader) and keep the live
  // WriteHalf working — not tear down. (Regression: undeliverable inbound returned
  // Terminal, killing the writer; sends_survive_read_half_drop only covered a quiet
  // peer.)
  let (mut client, server) = pair();
  let (sread, mut swrite) = server.split();
  drop(sread); // server is now send-only
  // The peer sends data the server can no longer deliver to anyone.
  client
    .send_text("dropped by a reader-less peer")
    .await
    .unwrap();
  // Let the server driver read and discard the undeliverable inbound.
  tokio::time::sleep(Duration::from_millis(20)).await;
  // The server's WriteHalf must still work.
  swrite.send_text("still sending").await.unwrap();
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("still sending".into()));
  drop(swrite);
}

#[tokio::test]
async fn sink_close_then_immediate_drop_still_closes_the_peer() {
  // `Sink::close` enqueues the Close on the control channel and returns Ok; the
  // WriteHalf is then dropped IMMEDIATELY, racing data-channel closure against the
  // queued CloseRequest. The driver must still drain and send the Close — the peer
  // must observe a clean WebSocket close, not a bare EOF. (Regression: data-channel
  // closure gated the control arm, masking the queued close.)
  use futures_util::SinkExt;
  let (client, server) = pair();
  let (_cread, mut cwrite) = client.split();
  let (mut sread, _swrite) = server.split();
  // Enqueue the Close WITHOUT yielding to the driver (so it has not yet drained the
  // control channel), then drop — now data-close and the queued CloseRequest both
  // become ready in the same driver poll, exposing the select-order race.
  {
    let mut close_fut = std::pin::pin!(SinkExt::close(&mut cwrite));
    assert!(
      futures_util::poll!(close_fut.as_mut()).is_ready(),
      "Sink close enqueues the CloseRequest synchronously"
    );
  }
  drop(cwrite);
  let drained = tokio::time::timeout(Duration::from_secs(5), async {
    while let Some(item) = sread.next().await {
      let _ = item; // drain to the end
    }
    sread
  })
  .await
  .expect("the peer must not hang waiting for a close");
  assert!(
    drained.closed().is_some_and(|c| c.clean()),
    "the peer must observe a clean close (got {:?})",
    drained.closed()
  );
}

#[tokio::test]
async fn peer_close_with_unread_inbound_then_drop_still_echoes() {
  // A peer-initiated close arrives with inbound data still buffered (the app never
  // read it), then the app drops BOTH halves. The close must still complete — the
  // echo flushed via the terminal clean-drain — so the peer sees a clean close, not
  // a bare EOF. (Contract guard: plain-drop teardown must defer to a staged close,
  // peer-initiated as well as local.)
  use futures_util::SinkExt;
  let (client, server) = pair();
  let (cread, cwrite) = client.split();
  let (mut sread, mut swrite) = server.split();
  swrite.send_text("unread data").await.unwrap();
  SinkExt::close(&mut swrite).await.unwrap();
  // Let the client receive the data + Close; it never reads the data.
  tokio::time::sleep(Duration::from_millis(20)).await;
  drop(cwrite);
  drop(cread);
  let drained = tokio::time::timeout(Duration::from_secs(5), async {
    while let Some(_m) = sread.next().await {}
    sread
  })
  .await
  .expect("the close must complete, not hang");
  assert!(
    drained.closed().is_some_and(|c| c.clean()),
    "peer must observe a clean close echo (got {:?})",
    drained.closed()
  );
}

#[tokio::test]
async fn reads_survive_write_half_drop() {
  let (client, server) = pair();
  let (mut sread, swrite) = server.split();
  drop(swrite);
  // The reader still pumps — it can write control frames via the shared
  // transport and complete a peer-initiated clean close.
  let reader = tokio::spawn(async move {
    while sread.next().await.is_some() {}
    sread
  });
  let closed = client.close(CloseCode::Normal, "bye").await.unwrap();
  assert!(closed.clean());
  let sread = reader.await.unwrap();
  assert!(sread.closed().unwrap().clean());
}

#[tokio::test]
async fn cancelled_next_preserves_the_connection() {
  let (mut client, mut server) = pair();
  // Poll server.next() once (it parks on the read) then drop it — the
  // readiness model consumed nothing.
  {
    use std::future::Future;
    let mut fut = Box::pin(server.next());
    std::future::poll_fn(|cx| {
      assert!(fut.as_mut().poll(cx).is_pending());
      std::task::Poll::Ready(())
    })
    .await;
  }
  client.send_text("after cancel").await.unwrap();
  let m = server.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("after cancel".into()));
  // Reverse direction too.
  server.send_text("echo").await.unwrap();
  let m = client.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("echo".into()));
}

#[tokio::test]
async fn stream_sink_round_trip() {
  use futures_util::{SinkExt, StreamExt};
  let (client, server) = pair();
  let (mut cr, mut cw) = client.split();
  let (mut sr, mut sw) = server.split();
  SinkExt::send(&mut cw, Message::Text("hi".into()))
    .await
    .unwrap();
  let srv = tokio::spawn(async move {
    let m = StreamExt::next(&mut sr).await.unwrap().unwrap();
    SinkExt::send(&mut sw, m).await.unwrap();
    (sr, sw)
  });
  let got = StreamExt::next(&mut cr).await.unwrap().unwrap();
  assert_eq!(got, Message::Text("hi".into()));
  drop(srv.await.unwrap());
}

#[tokio::test]
async fn pending_accept_rejects_before_upgrade() {
  let (c, s) = duplex();
  let client = tokio::spawn(async move {
    crate::client::<TokioRuntime, _>(c, "intruder.example", "/admin", Default::default())
      .await
      .map(|_| ())
  });
  let pending = crate::accept_pending::<TokioRuntime, _>(s, Default::default())
    .await
    .unwrap();
  assert_eq!(pending.request().path(), "/admin");
  assert_eq!(pending.request().host(), "intruder.example");
  pending.reject(403, "Forbidden").await.unwrap();
  let err = client.await.unwrap().unwrap_err();
  assert!(matches!(err, crate::ConnectError::Rejected { status: 403 }));
}

#[tokio::test]
async fn pending_accept_accepts_after_inspection() {
  let (c, s) = duplex();
  let client = tokio::spawn(async move {
    crate::client::<TokioRuntime, _>(c, "example.com", "/ok", Default::default())
      .await
      .unwrap()
  });
  let pending = crate::accept_pending::<TokioRuntime, _>(s, Default::default())
    .await
    .unwrap();
  assert_eq!(pending.request().path(), "/ok");
  let (mut ws, summary) = pending.accept().await.unwrap();
  assert_eq!(summary.path(), "/ok");
  let (mut cws, _resp) = client.await.unwrap();
  cws.send_text("hi").await.unwrap();
  let m = ws.next().await.unwrap().unwrap();
  assert_eq!(m, Message::Text("hi".into()));
}
