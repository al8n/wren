//! Async drivers for the h1 opening handshake over the poll-based duplex.

use futures_util::{AsyncReadExt, AsyncWriteExt};
use smol_str::SmolStr;
use websocket_proto::{
  handshake::{
    ExtraHeaders,
    h1::{
      Accept, ClientHandshake, ClientHandshakeError, ClientOptions as ProtoClientOptions,
      ClientProgress, Rejection, ServerHandshake, ServerHandshakeError, ServerProgress,
    },
  },
  negotiation::{Negotiated, select_subprotocol},
};
use wren_trace::debug;

use crate::{
  error::{AcceptError, ConnectError},
  options::{AcceptOptions, ClientOptions},
  runtime::Duplex,
};

/// What the client handshake leaves behind.
pub(crate) struct ClientOutcome {
  pub(crate) negotiated: Negotiated,
  /// Frame bytes that arrived after the response head.
  pub(crate) leftover: Vec<u8>,
}

/// What the server handshake leaves behind.
pub(crate) struct ServerOutcome {
  pub(crate) negotiated: Negotiated,
  pub(crate) leftover: Vec<u8>,
  pub(crate) summary: crate::RequestSummary,
}

/// One classified upgrade request, everything the driver has to hold while the
/// application decides.
///
/// RFC 6455 §4.2.2 binds the answer to the request — only a subprotocol the
/// client offered may be echoed, only an extension its offers legalize may be
/// granted — and the request is readable only while `drive_server_request` holds
/// it, so those checks run there and settle INSIDE the handshake. That is why
/// there is no decision field beside it: the answer travels in the one object
/// that can write it, so nothing here can be paired with another handshake.
#[derive(Debug)]
pub(crate) struct PendingRequest {
  /// Advanced past classification, carrying its own validated answer, and owing
  /// the peer one — the 101 or the rejection is written through this same
  /// connection.
  pub(crate) handshake: ServerHandshake,
  pub(crate) summary: crate::RequestSummary,
  /// Bytes that arrived behind the request head: frames the client pipelined
  /// with its handshake, which belong to the connection machine.
  pub(crate) buffered: Vec<u8>,
}

// One head's growth is bounded by the proto handshake, not here: `handle` is
// re-offered the whole buffer on every read, and it fails the handshake once
// the head exceeds http1-proto's 16 KiB cap without a terminator — so the
// accumulator can never grow past that cap plus one read chunk. That bounds ONE
// head; the client loop reads a sequence of them, which is what
// `MAX_INTERIM_RESPONSES` and `drop_consumed` below bound.
const READ_CHUNK: usize = 4096;

/// How many interim (1xx) responses this driver reads before it stops waiting
/// for the final one.
///
/// RFC 9110 §15.2 makes parsing "one or more 1xx responses received prior to a
/// final response" a client MUST and puts no limit on how many may arrive, so
/// nothing in the specification ends this loop: a server that streams 1xx heads
/// forever keeps a client reading forever. Dropping the consumed prefix
/// ([`drop_consumed`]) bounds the MEMORY that costs; it does not bound the
/// WORK, and a hung connect with no error is the failure a caller cannot even
/// diagnose.
///
/// 32 is chosen against what a conforming server sends: RFC 9110 §10.1.1 gives
/// a request at most one `100 (Continue)`, and RFC 8297's `103 (Early Hints)`
/// is sent once or a small handful of times ahead of one final response. An
/// order of magnitude above that leaves every real pattern untouched while
/// bounding the work at 32 heads — at most 32 × http1-proto's 16 KiB head cap
/// of bytes read — before the attempt is abandoned. A driver-layer policy, not
/// a protocol rule: `websocket-proto` classifies one head per call and has no
/// loop to bound.
const MAX_INTERIM_RESPONSES: usize = 32;

/// Drops the prefix of `acc` the handshake has already consumed, keeping
/// whatever is still unread, and rewinds the cursor to the front.
///
/// A cursor alone was the bug: `start` advanced past each interim response while
/// later reads kept appending, so a peer that streams 1xx heads grew `acc`
/// without bound even though nothing behind `start` would ever be read again.
/// The memmove this costs is over the UNCONSUMED suffix — usually empty, and at
/// most one glued head — while what it drops is everything already answered.
fn drop_consumed(acc: &mut Vec<u8>, start: &mut usize) {
  acc.drain(..(*start).min(acc.len()));
  *start = 0;
}

pub(crate) async fn drive_client<S: Duplex>(
  mut stream: S,
  host: &str,
  path_and_query: &str,
  options: &ClientOptions,
) -> Result<(S, ClientOutcome), ConnectError> {
  let subs: Vec<&str> = options.subprotocols.iter().map(SmolStr::as_str).collect();
  let extras: Vec<(&str, &str)> = options
    .extra_headers
    .iter()
    .map(|(n, v)| (n.as_str(), v.as_str()))
    .collect();
  #[allow(unused_mut)]
  let mut popts = ProtoClientOptions::new(host, path_and_query)
    .with_subprotocols(&subs)
    .with_extra_headers(extras.as_slice());
  #[cfg(feature = "deflate")]
  if let Some(offer) = options.deflate {
    popts = popts.with_deflate(offer);
  }
  let mut hs = ClientHandshake::new(popts, &mut rand::rng())?;

  let mut request = vec![0u8; READ_CHUNK];
  let n = hs.encode_request(&mut request)?;
  stream.write_all(request.get(..n).unwrap_or(&[])).await?;
  // The duplex buffers (adapter and TLS records both); flush puts the
  // request on the wire.
  stream.flush().await?;

  let mut acc: Vec<u8> = Vec::with_capacity(READ_CHUNK);
  // The first byte of `acc` the handshake has not consumed. An interim
  // response is consumed where it sits, so the offer advances past it rather
  // than the buffer being rebuilt under it mid-head.
  let mut start = 0usize;
  let mut interims = 0usize;
  let mut chunk = vec![0u8; READ_CHUNK];
  loop {
    // What is already buffered is offered BEFORE the next read: RFC 9110 §15.2
    // lets any number of interim responses precede the answer, and they can
    // arrive glued to it — a driver that read first would wait for bytes the
    // server has already sent.
    match hs.handle(acc.get(start..).unwrap_or(&[]))? {
      // RFC 9110 §15.2: consumed, and the answer is still to come.
      ClientProgress::Interim { consumed, .. } => {
        interims = interims.saturating_add(1);
        if interims > MAX_INTERIM_RESPONSES {
          return Err(ConnectError::TooManyInterimResponses {
            limit: MAX_INTERIM_RESPONSES,
          });
        }
        start = start.saturating_add(consumed);
        // Answered and never read again: dropped here, so the next read grows
        // the buffer from what is LEFT rather than from everything that ever
        // arrived. Any suffix glued behind this head — the final response, when
        // one read carried both — survives the drop.
        drop_consumed(&mut acc, &mut start);
        continue;
      }
      ClientProgress::Complete(done) => {
        let leftover = acc
          .get(start.saturating_add(done.consumed())..)
          .unwrap_or(&[])
          .to_vec();
        debug!(leftover = leftover.len(), "client handshake complete");
        return Ok((
          stream,
          ClientOutcome {
            negotiated: done.into_negotiated(),
            leftover,
          },
        ));
      }
      // The peer answered, and the answer is no. RFC 6455 §4.1 hands a real
      // client on to "HTTP procedures" — authenticate on a 401, follow a 3xx —
      // which this driver's callers do not do, so the status is the whole
      // report. It is NOT a read-more state: a refusal folded into one would
      // spin until the peer closed and surface as an EOF, reporting a network
      // fault for an answer that arrived.
      ClientProgress::Refused { status, .. } => {
        return Err(ConnectError::Rejected { status });
      }
      // Nothing consumed: read more and offer the same bytes again.
      ClientProgress::NeedMore => {}
      // `ClientProgress` is `#[non_exhaustive]`, so this arm is mandatory
      // rather than chosen — and it is an error, not a silent read-more: every
      // outcome that ENDS this handshake is named above, so a variant a later
      // websocket-proto adds is one this driver cannot act on, and looping on
      // it would report the peer's close in place of what it said.
      _ => return Err(ClientHandshakeError::NotAnUpgrade.into()),
    }

    let got = stream.read(&mut chunk).await?;
    if got == 0 {
      return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    acc.extend_from_slice(chunk.get(..got).unwrap_or(&[]));
  }
}

/// Reads one complete upgrade request and decides its answer; nothing is
/// written to the transport.
///
/// Everything the answer states about the REQUEST is settled here, while the
/// request is still borrowed: `ServerHandshake::handle` advances a tunnel
/// connection, so the bytes cannot be classified a second time and the view
/// dies with this call's read buffer. What comes back is owned — the summary and
/// the bytes the client pipelined — plus the handshake itself, which carries the
/// answer it validated and still owes the peer either that or a rejection.
pub(crate) async fn drive_server_request<S: Duplex>(
  stream: &mut S,
  options: &AcceptOptions,
) -> Result<PendingRequest, AcceptError> {
  let mut hs = ServerHandshake::new();
  let mut acc: Vec<u8> = Vec::with_capacity(READ_CHUNK);
  let mut chunk = vec![0u8; READ_CHUNK];
  loop {
    let got = stream.read(&mut chunk).await?;
    if got == 0 {
      return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    acc.extend_from_slice(chunk.get(..got).unwrap_or(&[]));

    // RFC 6455 §4.2.1: a server that stops processing a handshake "MUST stop
    // processing the client's handshake and return an HTTP response with an
    // appropriate error code (such as 400 Bad Request)". The refusal is written
    // through the connection that read the request — which is still here, and
    // which the proto layer deliberately leaves reject-only for this — so the
    // fault ends in an answer rather than in a close the client has to time out
    // on.
    let progress = match hs.handle(&acc) {
      Ok(progress) => progress,
      Err(error) => return Err(refuse(stream, hs, error).await),
    };
    match progress {
      // Nothing consumed: offer the same bytes again with more behind them.
      ServerProgress::NeedMore => continue,
      ServerProgress::Upgrade(mut pending) => {
        let view = pending.request();
        let buffered = pending.leftover().to_vec();
        let summary = crate::RequestSummary {
          path: view.path().into(),
          query: view.query().map(Into::into),
          host: view.host().into(),
          // RFC 6454 serialises an origin in ASCII, so a value that is not
          // UTF-8 is not one. Decoded lossily rather than dropped: an origin
          // policy reads a replacement-char value as an origin it does not
          // allow, where `None` would read as "the client sent none".
          origin: view
            .origin()
            .map(|value| SmolStr::new(String::from_utf8_lossy(value))),
        };

        // The selection is an entry of `supported`; the offers it was chosen
        // from die with `view`, and the 101 still has to name it.
        let supported: Vec<&str> = options
          .supported_subprotocols
          .iter()
          .map(SmolStr::as_str)
          .collect();
        #[allow(unused_mut)]
        let mut accept =
          Accept::new().with_subprotocol(select_subprotocol(view.subprotocols(), &supported));
        #[cfg(feature = "deflate")]
        if let Some(config) = &options.deflate {
          let granted =
            websocket_proto::negotiation::accept_deflate_offer(view.extensions(), config);
          accept = accept.with_deflate(granted.map(|(_, response)| response));
        }

        // RFC 6455 §4.2.2's request-bound checks, made while the offers can
        // still be read. The pending upgrade holds the handshake they settle
        // into, so what they decide survives both the view and this function
        // without ever becoming a value some other handshake could be handed.
        //
        // Not answered with a refusal the way a classification fault is: the
        // subprotocol was selected from this request's own offers and the grant
        // derived from its own extension lines, so a failure here is this
        // server refusing its own answer, not the client's handshake being
        // invalid — and §4.2.1's 400 would blame the peer for it.
        pending.validate_accept(&accept)?;

        // The pending upgrade's borrow of `hs` ends here, which is what lets the
        // handshake — carrying the answer just settled — be moved out.
        return Ok(PendingRequest {
          handshake: hs,
          summary,
          buffered,
        });
      }
      // The peer closed without sending a request. This driver reports its own
      // EOF before offering more bytes, so reaching here still means there is
      // no request to answer.
      ServerProgress::Closed => {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
      }
      // `ServerProgress` is `#[non_exhaustive]`, so this arm is mandatory
      // rather than chosen: a classification this driver does not know is not
      // one it can answer with a 101. It is still a request that arrived, so it
      // is refused rather than dropped.
      _ => return Err(refuse(stream, hs, ServerHandshakeError::NotAnUpgrade).await),
    }
  }
}

/// Answers a handshake this driver has stopped processing, then reports the
/// fault that stopped it.
///
/// RFC 6455 §4.2.1 makes the answer a MUST, and §4.2.2 fixes the one case that
/// is not a 400: a version this server does not speak is a 426 carrying
/// `Sec-WebSocket-Version: 13`, so the client learns what to retry with instead
/// of only that it failed.
///
/// BEST-EFFORT, and the return is always the ORIGINAL error. A transport that
/// cannot carry the refusal, or a connection whose phase will not encode one,
/// must not replace "the request was malformed" with "the apology did not go
/// out" — the caller needs the first to know why the handshake failed, and the
/// second describes a connection it is about to drop anyway.
async fn refuse<S: Duplex>(
  stream: &mut S,
  handshake: ServerHandshake,
  error: ServerHandshakeError,
) -> AcceptError {
  let (status, rejection) = if error.is_unsupported_version() {
    (426, Rejection::unsupported_version())
  } else {
    // What the fault deserves is `http1-proto`'s reading of it; the reason
    // phrase is this layer's, and RFC 9112 §4 leaves it advisory. A code with
    // no phrase here is answered with §4.2.1's own example rather than with a
    // phrase that names a different status.
    let suggested = match &error {
      ServerHandshakeError::Http(fault) => fault.suggested_status().map(|status| status.code()),
      _ => None,
    };
    let (status, reason) = match suggested {
      Some(414) => (414, "URI Too Long"),
      Some(431) => (431, "Request Header Fields Too Large"),
      Some(501) => (501, "Not Implemented"),
      Some(505) => (505, "HTTP Version Not Supported"),
      _ => (400, "Bad Request"),
    };
    (status, Rejection::new(status, reason))
  };
  let answered = write_rejection(stream, handshake, &rejection).await.is_ok();
  debug!(status, answered, cause = %error, "upgrade refused");
  error.into()
}

/// Encodes and flushes the 101 for the answer the handshake settled when the
/// request was classified.
///
/// The extra response headers are rebuilt from `options` here rather than
/// carried alongside: nothing about them depends on the request, and
/// `encode_response` screens them for CR/LF, non-token names and collisions
/// with the fields the handshake manages.
pub(crate) async fn finish_accept<S: Duplex>(
  mut stream: S,
  mut handshake: ServerHandshake,
  summary: crate::RequestSummary,
  buffered: Vec<u8>,
  options: &AcceptOptions,
) -> Result<(S, ServerOutcome), AcceptError> {
  let extras: Vec<(&str, &str)> = options
    .extra_headers
    .iter()
    .map(|(n, v)| (n.as_str(), v.as_str()))
    .collect();
  let mut response = vec![0u8; READ_CHUNK];
  let (n, negotiated) =
    handshake.encode_response(&ExtraHeaders::from(extras.as_slice()), &mut response)?;

  stream.write_all(response.get(..n).unwrap_or(&[])).await?;
  stream.flush().await?;
  debug!(path = %summary.path, leftover = buffered.len(), "server handshake complete");
  Ok((
    stream,
    ServerOutcome {
      negotiated,
      leftover: buffered,
      summary,
    },
  ))
}

/// Encodes and flushes a non-101 rejection; the transport is then dropped
/// by the caller.
pub(crate) async fn finish_reject<S: Duplex>(
  stream: &mut S,
  handshake: ServerHandshake,
  status: u16,
  reason: &str,
) -> Result<(), AcceptError> {
  write_rejection(stream, handshake, &Rejection::new(status, reason)).await?;
  debug!(status, "upgrade rejected");
  Ok(())
}

/// The one place a rejection reaches the wire, so the application's refusal and
/// this driver's own are encoded and flushed the same way.
async fn write_rejection<S: Duplex>(
  stream: &mut S,
  mut handshake: ServerHandshake,
  rejection: &Rejection<'_>,
) -> Result<(), AcceptError> {
  let mut response = vec![0u8; READ_CHUNK];
  let n = handshake.encode_rejection(rejection, &mut response)?;
  stream.write_all(response.get(..n).unwrap_or(&[])).await?;
  stream.flush().await?;
  Ok(())
}

#[cfg(test)]
mod tests;
