#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

mod conn;
#[cfg(test)]
mod duplex;
mod error;
mod handshake;
mod maybe_tls;
mod options;
mod runtime;
#[cfg(feature = "tls")]
mod tls;
mod url;

use std::marker::PhantomData;

use agnostic_lite::RuntimeLite;
use agnostic_net::{Net, TcpStream as _};

pub use conn::{ClientRole, ReadHalf, ServerRole, WebSocket, WriteHalf};
pub use error::{AcceptError, ConnectError, Error};
pub use maybe_tls::MaybeTls;
pub use options::{AcceptOptions, ClientOptions};
pub use runtime::Duplex;
pub use websocket_proto::{Negotiated, connection::Closed, frame::CloseCode, message::Message};

/// Connects to a `ws://` or `wss://` URL and completes the opening
/// handshake, dialing and timing over the runtime `N`.
///
/// `wss://` needs the `tls` feature. The default trust anchors are the
/// webpki (Mozilla) roots — the platform certificate store is **not**
/// consulted, so corporate or custom CAs need a caller-built connector via
/// [`ClientOptions::with_tls_connector`]. Prefer the runtime-specific
/// [`tokio::connect`] / [`smol::connect`] wrappers.
pub async fn connect<N: Net>(
  url: &str,
  options: ClientOptions,
) -> Result<
  (
    WebSocket<N::Runtime, ClientRole, MaybeTls<N::TcpStream>>,
    ConnectResponse,
  ),
  ConnectError,
> {
  let parsed = url::WsUrl::parse(url)?;
  #[cfg(not(feature = "tls"))]
  if parsed.tls {
    return Err(ConnectError::UnsupportedScheme);
  }
  wren_trace::debug!(url, "connecting");
  let tcp = N::TcpStream::connect((parsed.host_for_dial(), parsed.port)).await?;
  let stream = if parsed.tls {
    #[cfg(feature = "tls")]
    {
      let connector = options
        .tls
        .clone()
        .unwrap_or_else(tls::default_tls_connector);
      let domain = rustls::pki_types::ServerName::try_from(parsed.host_for_dial().to_string())
        .map_err(|_| ConnectError::InvalidUrl("invalid TLS server name"))?;
      MaybeTls::Tls(Box::new(connector.connect(domain, tcp).await?))
    }
    #[cfg(not(feature = "tls"))]
    unreachable!("wss:// is rejected above without the tls feature")
  } else {
    MaybeTls::Plain(tcp)
  };
  client::<N::Runtime, _>(stream, parsed.authority, parsed.path_and_query, options).await
}

/// Completes the client handshake over a caller-provided stream (custom
/// dialers, proxies, pre-wrapped TLS); `R` supplies the timers.
pub async fn client<R: RuntimeLite, S: Duplex>(
  stream: S,
  host: &str,
  path_and_query: &str,
  options: ClientOptions,
) -> Result<(WebSocket<R, ClientRole, S>, ConnectResponse), ConnectError> {
  let (stream, outcome) = handshake::drive_client(stream, host, path_and_query, &options).await?;
  let ws = WebSocket::<R, _, _>::client(stream, &outcome.negotiated, &options, outcome.leftover);
  Ok((
    ws,
    ConnectResponse {
      negotiated: outcome.negotiated,
    },
  ))
}

/// Accepts one WebSocket upgrade on a caller-provided stream, committing the
/// 101 unconditionally. Servers that authorize requests first use
/// [`accept_pending`].
pub async fn accept<R: RuntimeLite, S: Duplex>(
  stream: S,
  options: AcceptOptions,
) -> Result<(WebSocket<R, ServerRole, S>, RequestSummary), AcceptError> {
  accept_pending::<R, S>(stream, options)
    .await?
    .accept()
    .await
}

/// Reads one upgrade request and stops BEFORE answering, so the caller can
/// authorize it — reject by Origin, Host, path, or auth — without
/// establishing the connection first.
pub async fn accept_pending<R: RuntimeLite, S: Duplex>(
  mut stream: S,
  options: AcceptOptions,
) -> Result<PendingAccept<R, S>, AcceptError> {
  let (head, summary) = handshake::drive_server_request(&mut stream).await?;
  Ok(PendingAccept {
    stream,
    head,
    summary,
    options,
    _rt: PhantomData,
  })
}

/// An upgrade request that has been read but not yet answered. Inspect
/// [`request`](Self::request), then [`accept`](Self::accept) or
/// [`reject`](Self::reject).
#[derive(Debug)]
pub struct PendingAccept<R, S> {
  stream: S,
  head: Vec<u8>,
  summary: RequestSummary,
  options: AcceptOptions,
  _rt: PhantomData<fn() -> R>,
}

impl<R: RuntimeLite, S: Duplex> PendingAccept<R, S> {
  /// The upgrade request awaiting a decision.
  pub fn request(&self) -> &RequestSummary {
    &self.summary
  }
  /// Sends the 101 and establishes the connection.
  pub async fn accept(self) -> Result<(WebSocket<R, ServerRole, S>, RequestSummary), AcceptError> {
    let (stream, outcome) =
      handshake::finish_accept(self.stream, self.head, self.summary, &self.options).await?;
    let ws =
      WebSocket::<R, _, _>::server(stream, &outcome.negotiated, &self.options, outcome.leftover);
    Ok((ws, outcome.summary))
  }
  /// Answers with a non-101 rejection (status 300–599) and drops the
  /// transport.
  pub async fn reject(self, status: u16, reason: &str) -> Result<(), AcceptError> {
    handshake::finish_reject(self.stream, status, reason).await
  }
}

/// The negotiation outcome of a completed client handshake.
#[derive(Debug, Clone)]
pub struct ConnectResponse {
  pub(crate) negotiated: websocket_proto::Negotiated,
}

impl ConnectResponse {
  /// The agreed subprotocol, when one was negotiated.
  pub fn subprotocol(&self) -> Option<&str> {
    self.negotiated.subprotocol()
  }
  /// The agreed permessage-deflate parameters, when negotiated.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub fn deflate(&self) -> Option<websocket_proto::negotiation::DeflateParams> {
    self.negotiated.deflate()
  }
}

/// tokio-runtime entry points.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio {
  use super::*;

  type Rt = agnostic_lite::tokio::TokioRuntime;
  type Tcp = <agnostic_net::tokio::Net as Net>::TcpStream;

  /// The connection type [`connect`] returns.
  pub type ClientWebSocket = WebSocket<Rt, ClientRole, MaybeTls<Tcp>>;

  /// See [`crate::connect`].
  pub async fn connect(
    url: &str,
    options: ClientOptions,
  ) -> Result<(ClientWebSocket, ConnectResponse), ConnectError> {
    super::connect::<agnostic_net::tokio::Net>(url, options).await
  }
  /// See [`crate::client`].
  pub async fn client<S: Duplex>(
    stream: S,
    host: &str,
    path_and_query: &str,
    options: ClientOptions,
  ) -> Result<(WebSocket<Rt, ClientRole, S>, ConnectResponse), ConnectError> {
    super::client::<Rt, S>(stream, host, path_and_query, options).await
  }
  /// See [`crate::accept`].
  pub async fn accept<S: Duplex>(
    stream: S,
    options: AcceptOptions,
  ) -> Result<(WebSocket<Rt, ServerRole, S>, RequestSummary), AcceptError> {
    super::accept::<Rt, S>(stream, options).await
  }
  /// See [`crate::accept_pending`].
  pub async fn accept_pending<S: Duplex>(
    stream: S,
    options: AcceptOptions,
  ) -> Result<PendingAccept<Rt, S>, AcceptError> {
    super::accept_pending::<Rt, S>(stream, options).await
  }
}

/// smol-runtime entry points.
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub mod smol {
  use super::*;

  type Rt = agnostic_lite::smol::SmolRuntime;
  type Tcp = <agnostic_net::smol::Net as Net>::TcpStream;

  /// The connection type [`connect`] returns.
  pub type ClientWebSocket = WebSocket<Rt, ClientRole, MaybeTls<Tcp>>;

  /// See [`crate::connect`].
  pub async fn connect(
    url: &str,
    options: ClientOptions,
  ) -> Result<(ClientWebSocket, ConnectResponse), ConnectError> {
    super::connect::<agnostic_net::smol::Net>(url, options).await
  }
  /// See [`crate::client`].
  pub async fn client<S: Duplex>(
    stream: S,
    host: &str,
    path_and_query: &str,
    options: ClientOptions,
  ) -> Result<(WebSocket<Rt, ClientRole, S>, ConnectResponse), ConnectError> {
    super::client::<Rt, S>(stream, host, path_and_query, options).await
  }
  /// See [`crate::accept`].
  pub async fn accept<S: Duplex>(
    stream: S,
    options: AcceptOptions,
  ) -> Result<(WebSocket<Rt, ServerRole, S>, RequestSummary), AcceptError> {
    super::accept::<Rt, S>(stream, options).await
  }
  /// See [`crate::accept_pending`].
  pub async fn accept_pending<S: Duplex>(
    stream: S,
    options: AcceptOptions,
  ) -> Result<PendingAccept<Rt, S>, AcceptError> {
    super::accept_pending::<Rt, S>(stream, options).await
  }
}

/// Owned snapshot of an accepted upgrade request.
///
/// The borrowed request view dies with the handshake buffer; this carries
/// the routing-relevant fields. Applications that need arbitrary request
/// headers should drive the [`proto`] handshake machines directly.
#[derive(Debug, Clone)]
pub struct RequestSummary {
  pub(crate) path: smol_str::SmolStr,
  pub(crate) query: Option<smol_str::SmolStr>,
  pub(crate) host: smol_str::SmolStr,
  pub(crate) origin: Option<smol_str::SmolStr>,
}

impl RequestSummary {
  /// The resource path (always `/`-leading).
  pub fn path(&self) -> &str {
    self.path.as_str()
  }

  /// The query component, when the target carried one.
  pub fn query(&self) -> Option<&str> {
    self.query.as_deref()
  }

  /// The effective authority the request addressed.
  pub fn host(&self) -> &str {
    self.host.as_str()
  }

  /// The Origin header, when present.
  pub fn origin(&self) -> Option<&str> {
    self.origin.as_deref()
  }
}

/// The Sans-I/O protocol layer, re-exported as an escape hatch for bespoke
/// handshake or framing flows the driver API does not cover.
pub mod proto {
  pub use websocket_proto::*;
}
