#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

mod conn;
mod error;
mod handshake;
mod maybe_tls;
mod options;
mod url;

pub use conn::{ClientRole, ReadHalf, ServerRole, WebSocket, WriteHalf};
pub use maybe_tls::MaybeTls;
pub use websocket_proto::{Negotiated, connection::Closed, frame::CloseCode, message::Message};

/// The connection type [`connect`] returns.
pub type ClientWebSocket = WebSocket<ClientRole, MaybeTls>;

/// Connects to a `ws://` or `wss://` URL and completes the opening
/// handshake. (`wss://` needs the `tls` feature; the default trust roots
/// are webpki-roots, overridable via
/// [`ClientOptions::with_tls_connector`].)
pub async fn connect(
  url: &str,
  options: ClientOptions,
) -> Result<(ClientWebSocket, ConnectResponse), ConnectError> {
  let parsed = url::WsUrl::parse(url)?;
  #[cfg(not(feature = "tls"))]
  if parsed.tls {
    return Err(ConnectError::UnsupportedScheme);
  }
  let tcp = compio_net::TcpStream::connect((parsed.host_for_dial(), parsed.port)).await?;
  let stream = if parsed.tls {
    #[cfg(feature = "tls")]
    {
      let connector = options.tls.clone().unwrap_or_else(default_tls_connector);
      MaybeTls::Tls(Box::new(
        connector.connect(parsed.host_for_dial(), tcp).await?,
      ))
    }
    #[cfg(not(feature = "tls"))]
    unreachable!("wss:// is rejected above without the tls feature")
  } else {
    MaybeTls::Plain(tcp)
  };
  client(stream, parsed.authority, parsed.path_and_query, options).await
}

/// Completes the client handshake over a caller-provided stream (custom
/// dialers, proxies, pre-wrapped TLS).
pub async fn client<S>(
  stream: S,
  host: &str,
  path_and_query: &str,
  options: ClientOptions,
) -> Result<(WebSocket<ClientRole, S>, ConnectResponse), ConnectError>
where
  S: compio_io::AsyncRead + compio_io::AsyncWrite + 'static,
{
  let (stream, outcome) = handshake::drive_client(stream, host, path_and_query, &options).await?;
  let ws = WebSocket::client(stream, &outcome.negotiated, &options, outcome.leftover);
  Ok((
    ws,
    ConnectResponse {
      negotiated: outcome.negotiated,
    },
  ))
}

/// Accepts one WebSocket upgrade on a caller-provided stream (accept the
/// TCP connection — and wrap TLS, if any — first).
pub async fn accept<S>(
  stream: S,
  options: AcceptOptions,
) -> Result<(WebSocket<ServerRole, S>, RequestSummary), AcceptError>
where
  S: compio_io::AsyncRead + compio_io::AsyncWrite + 'static,
{
  let (stream, outcome) = handshake::drive_server(stream, &options).await?;
  let ws = WebSocket::server(stream, &outcome.negotiated, &options, outcome.leftover);
  Ok((ws, outcome.summary))
}

/// rustls client config trusting the webpki (Mozilla) roots — deterministic
/// builds, no platform cert store reads.
#[cfg(feature = "tls")]
fn default_tls_connector() -> compio_tls::TlsConnector {
  let mut roots = rustls::RootCertStore::empty();
  roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
  let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  compio_tls::TlsConnector::from(std::sync::Arc::new(config))
}

#[cfg(test)]
mod duplex;

pub use error::{AcceptError, ConnectError, Error};
pub use options::{AcceptOptions, ClientOptions};

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

/// The Sans-I/O protocol layer, re-exported as an escape hatch for bespoke
/// handshake or framing flows the driver API does not cover.
pub mod proto {
  pub use websocket_proto::*;
}
