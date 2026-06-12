//! Async drivers for the h1 opening handshake over the poll-based duplex.

use futures_util::{AsyncReadExt, AsyncWriteExt};
use smol_str::SmolStr;
use websocket_proto::{
  handshake::h1::{
    Accept, ClientHandshake, ClientHandshakeError, ClientOptions as ProtoClientOptions,
    ServerHandshake,
  },
  negotiation::{Negotiated, select_subprotocol},
};
use wren_trace::debug;

use crate::{
  error::{AcceptError, ConnectError},
  into_duplex::Duplex,
  options::{AcceptOptions, ClientOptions},
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

// Accumulator growth is bounded by the proto parser, not here: `handle` is
// re-run on every read, and it fails the handshake once the head exceeds
// its 8 KiB cap without a terminator — so the accumulator can never grow
// past that cap plus one read chunk.
const READ_CHUNK: usize = 4096;

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
  let hs = ClientHandshake::new(popts, &mut rand::rng())?;

  let mut request = vec![0u8; READ_CHUNK];
  let n = hs.encode_request(&mut request)?;
  stream.write_all(request.get(..n).unwrap_or(&[])).await?;
  // The duplex buffers (adapter and TLS records both); flush puts the
  // request on the wire.
  stream.flush().await?;

  let mut acc: Vec<u8> = Vec::with_capacity(READ_CHUNK);
  let mut chunk = vec![0u8; READ_CHUNK];
  loop {
    let got = stream.read(&mut chunk).await?;
    if got == 0 {
      return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    acc.extend_from_slice(chunk.get(..got).unwrap_or(&[]));
    match hs.handle(&acc) {
      Ok(progress) => {
        // `Err(progress)` is the need-more state: read again.
        let Ok(done) = progress.try_unwrap_complete() else {
          continue;
        };
        let leftover = acc.get(done.consumed()..).unwrap_or(&[]).to_vec();
        debug!(leftover = leftover.len(), "client handshake complete");
        return Ok((
          stream,
          ClientOutcome {
            negotiated: done.into_negotiated(),
            leftover,
          },
        ));
      }
      Err(ClientHandshakeError::UnexpectedStatus(status)) => {
        return Err(ConnectError::Rejected { status });
      }
      Err(e) => return Err(e.into()),
    }
  }
}

/// Reads one complete upgrade request head; nothing is written. The
/// returned buffer re-parses statelessly in [`finish_accept`] /
/// [`finish_reject`].
pub(crate) async fn drive_server_request<S: Duplex>(
  stream: &mut S,
) -> Result<(Vec<u8>, crate::RequestSummary), AcceptError> {
  let hs = ServerHandshake::new();
  let mut acc: Vec<u8> = Vec::with_capacity(READ_CHUNK);
  let mut chunk = vec![0u8; READ_CHUNK];
  loop {
    let got = stream.read(&mut chunk).await?;
    if got == 0 {
      return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    acc.extend_from_slice(chunk.get(..got).unwrap_or(&[]));

    let progress = hs.handle(&acc)?;
    // `Err(progress)` is the need-more state: read again.
    let Ok(view) = progress.try_unwrap_request() else {
      continue;
    };
    let summary = crate::RequestSummary {
      path: view.path().into(),
      query: view.query().map(Into::into),
      host: view.host().into(),
      origin: view.origin().map(Into::into),
    };
    return Ok((acc, summary));
  }
}

/// Encodes and flushes the 101 for a previously read request head.
pub(crate) async fn finish_accept<S: Duplex>(
  mut stream: S,
  acc: Vec<u8>,
  summary: crate::RequestSummary,
  options: &AcceptOptions,
) -> Result<(S, ServerOutcome), AcceptError> {
  let hs = ServerHandshake::new();
  // Stateless re-parse of the complete head read by drive_server_request.
  let progress = hs.handle(&acc)?;
  let Ok(view) = progress.try_unwrap_request() else {
    unreachable!("the head was complete when it was read")
  };

  // Everything below borrows `view` (and through it `acc`): build the
  // whole response and the outcome BEFORE the write await.
  let supported: Vec<&str> = options
    .supported_subprotocols
    .iter()
    .map(SmolStr::as_str)
    .collect();
  let chosen = select_subprotocol(view.subprotocols(), &supported);
  let extras: Vec<(&str, &str)> = options
    .extra_headers
    .iter()
    .map(|(n, v)| (n.as_str(), v.as_str()))
    .collect();
  #[allow(unused_mut)]
  let mut accept = Accept::new()
    .with_subprotocol(chosen)
    .with_extra_headers(extras.as_slice());
  #[cfg(feature = "deflate")]
  if let Some(config) = &options.deflate {
    let granted = websocket_proto::negotiation::accept_deflate_offer(view.extensions(), config);
    accept = accept.with_deflate(granted.map(|(_, response)| response));
  }

  let mut response = vec![0u8; READ_CHUNK];
  let (n, negotiated) = hs.encode_response(&view, &accept, &mut response)?;
  let consumed = view.consumed();
  let leftover = acc.get(consumed..).unwrap_or(&[]).to_vec();

  stream.write_all(response.get(..n).unwrap_or(&[])).await?;
  stream.flush().await?;
  debug!(path = %summary.path, leftover = leftover.len(), "server handshake complete");
  Ok((
    stream,
    ServerOutcome {
      negotiated,
      leftover,
      summary,
    },
  ))
}

/// Encodes and flushes a non-101 rejection; the transport is then dropped
/// by the caller.
pub(crate) async fn finish_reject<S: Duplex>(
  mut stream: S,
  status: u16,
  reason: &str,
) -> Result<(), AcceptError> {
  let hs = ServerHandshake::new();
  let rejection = websocket_proto::handshake::h1::Rejection::new(status, reason);
  let mut response = vec![0u8; READ_CHUNK];
  let n = hs.encode_rejection(&rejection, &mut response)?;
  stream.write_all(response.get(..n).unwrap_or(&[])).await?;
  stream.flush().await?;
  debug!(status, "upgrade rejected");
  Ok(())
}

#[cfg(test)]
mod tests;
