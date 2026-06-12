//! Connection options for [`connect`](crate::connect) and
//! [`accept`](crate::accept).

use core::time::Duration;
use smol_str::SmolStr;

/// Client options for [`connect`](crate::connect) / [`client`](crate::client).
#[derive(Debug, Clone, Default)]
pub struct ClientOptions {
  pub(crate) subprotocols: Vec<SmolStr>,
  pub(crate) extra_headers: Vec<(SmolStr, SmolStr)>,
  pub(crate) keepalive: Option<Duration>,
  pub(crate) close_timeout: Option<Duration>,
  pub(crate) max_message_size: Option<usize>,
  #[cfg(feature = "deflate")]
  pub(crate) deflate: Option<websocket_proto::negotiation::DeflateOffer>,
  #[cfg(feature = "tls")]
  pub(crate) tls: Option<compio_tls::TlsConnector>,
}

impl ClientOptions {
  /// Options with every knob at its default (no subprotocols, no extras,
  /// proto's default timers, 64 MiB message cap).
  pub fn new() -> Self {
    Self::default()
  }

  /// Subprotocols to offer, in preference order.
  #[must_use]
  pub fn with_subprotocols<I>(mut self, subprotocols: I) -> Self
  where
    I: IntoIterator,
    I::Item: Into<SmolStr>,
  {
    self.subprotocols = subprotocols.into_iter().map(Into::into).collect();
    self
  }

  /// Appends one extra request header (auth, origin, cookies). Names and
  /// values are validated by the handshake builder at connect time.
  #[must_use]
  pub fn with_extra_header(mut self, name: impl Into<SmolStr>, value: impl Into<SmolStr>) -> Self {
    self.extra_headers.push((name.into(), value.into()));
    self
  }

  /// Keepalive ping interval (`None` disables; the default is disabled).
  #[must_use]
  pub fn with_keepalive(mut self, interval: Option<Duration>) -> Self {
    self.keepalive = interval;
    self
  }

  /// The close-handshake budget: it bounds flushing our Close, waiting
  /// for the peer's echo (counted from the flush), and the transport
  /// shutdown — each individually, so a close takes at most a small
  /// multiple of it. The default is the protocol's (10 s).
  #[must_use]
  pub fn with_close_timeout(mut self, timeout: Duration) -> Self {
    self.close_timeout = Some(timeout);
    self
  }

  /// Maximum assembled inbound message size in bytes.
  #[must_use]
  pub fn with_max_message_size(mut self, max: usize) -> Self {
    self.max_message_size = Some(max);
    self
  }

  /// Offer permessage-deflate.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  #[must_use]
  pub fn with_deflate(mut self, offer: websocket_proto::negotiation::DeflateOffer) -> Self {
    self.deflate = Some(offer);
    self
  }

  /// TLS connector for `wss://` (replaces the webpki-roots default).
  #[cfg(feature = "tls")]
  #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
  #[must_use]
  pub fn with_tls_connector(mut self, connector: compio_tls::TlsConnector) -> Self {
    self.tls = Some(connector);
    self
  }
}

/// Server options for [`accept`](crate::accept).
#[derive(Debug, Clone, Default)]
pub struct AcceptOptions {
  pub(crate) supported_subprotocols: Vec<SmolStr>,
  pub(crate) extra_headers: Vec<(SmolStr, SmolStr)>,
  pub(crate) keepalive: Option<Duration>,
  pub(crate) close_timeout: Option<Duration>,
  pub(crate) max_message_size: Option<usize>,
  #[cfg(feature = "deflate")]
  pub(crate) deflate: Option<websocket_proto::negotiation::ServerDeflateConfig>,
}

impl AcceptOptions {
  /// Options with every knob at its default.
  pub fn new() -> Self {
    Self::default()
  }

  /// Subprotocols this server supports; the first CLIENT offer that matches
  /// wins ([`select_subprotocol`](websocket_proto::negotiation::select_subprotocol)).
  #[must_use]
  pub fn with_supported_subprotocols<I>(mut self, subprotocols: I) -> Self
  where
    I: IntoIterator,
    I::Item: Into<SmolStr>,
  {
    self.supported_subprotocols = subprotocols.into_iter().map(Into::into).collect();
    self
  }

  /// Appends one extra response header.
  #[must_use]
  pub fn with_extra_header(mut self, name: impl Into<SmolStr>, value: impl Into<SmolStr>) -> Self {
    self.extra_headers.push((name.into(), value.into()));
    self
  }

  /// Keepalive ping interval (`None` disables; the default is disabled).
  #[must_use]
  pub fn with_keepalive(mut self, interval: Option<Duration>) -> Self {
    self.keepalive = interval;
    self
  }

  /// The close-handshake budget: it bounds flushing our Close, waiting
  /// for the peer's echo (counted from the flush), and the transport
  /// shutdown — each individually, so a close takes at most a small
  /// multiple of it. The default is the protocol's (10 s).
  #[must_use]
  pub fn with_close_timeout(mut self, timeout: Duration) -> Self {
    self.close_timeout = Some(timeout);
    self
  }

  /// Maximum assembled inbound message size in bytes.
  #[must_use]
  pub fn with_max_message_size(mut self, max: usize) -> Self {
    self.max_message_size = Some(max);
    self
  }

  /// Accept permessage-deflate offers under this policy.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  #[must_use]
  pub fn with_deflate(mut self, config: websocket_proto::negotiation::ServerDeflateConfig) -> Self {
    self.deflate = Some(config);
    self
  }
}
