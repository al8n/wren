//! Connection options for [`connect`](crate::connect) and
//! [`accept`](crate::accept).

use core::time::Duration;
use smol_str::SmolStr;

/// Client options for [`connect`](crate::connect) / [`client`](crate::client).
#[derive(Clone, Default)]
pub struct ClientOptions {
  pub(crate) subprotocols: Vec<SmolStr>,
  pub(crate) extra_headers: Vec<(SmolStr, SmolStr)>,
  pub(crate) keepalive: Option<Duration>,
  pub(crate) close_timeout: Option<Duration>,
  pub(crate) write_timeout: Option<Duration>,
  pub(crate) max_message_size: Option<usize>,
  #[cfg(feature = "deflate")]
  pub(crate) deflate: Option<websocket_proto::negotiation::DeflateOffer>,
  #[cfg(feature = "tls")]
  pub(crate) tls: Option<futures_rustls::TlsConnector>,
}

// Manual: `futures_rustls::TlsConnector` does not implement `Debug`.
impl core::fmt::Debug for ClientOptions {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    let mut d = f.debug_struct("ClientOptions");
    d.field("subprotocols", &self.subprotocols)
      .field("extra_headers", &self.extra_headers)
      .field("keepalive", &self.keepalive)
      .field("close_timeout", &self.close_timeout)
      .field("write_timeout", &self.write_timeout)
      .field("max_message_size", &self.max_message_size);
    #[cfg(feature = "deflate")]
    d.field("deflate", &self.deflate);
    #[cfg(feature = "tls")]
    d.field("tls", &self.tls.as_ref().map(|_| "<TlsConnector>"));
    d.finish()
  }
}

impl ClientOptions {
  /// Options with every knob at its default (no subprotocols, no extras, no
  /// keepalive, no write timeout, proto's default close timeout, 64 MiB cap).
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

  /// Keepalive ping interval. **Off by default** (tungstenite parity): when set,
  /// the connection sends periodic pings (the peer's pong is consumed internally);
  /// incoming pings are auto-ponged regardless. It imposes NO liveness timeout —
  /// detecting a dead or non-reading peer is the caller's job (`timeout(next())`,
  /// your own ping tracking, or OS TCP keepalive).
  #[must_use]
  pub fn with_keepalive(mut self, interval: Option<Duration>) -> Self {
    self.keepalive = interval;
    self
  }

  /// The close-handshake budget: it bounds flushing our Close, waiting for the
  /// peer's echo (counted from the flush), and the transport shutdown — so a close
  /// completes in a small multiple of it. It bounds ONLY the close handshake, never
  /// ordinary sends. The default is the protocol's (10 s).
  #[must_use]
  pub fn with_close_timeout(mut self, timeout: Duration) -> Self {
    self.close_timeout = Some(timeout);
    self
  }

  /// Per-frame deadline bounding an ordinary write/flush (the `poll_write`
  /// no-progress bound and flush completion). `None` (the default) means the
  /// library imposes NO write deadline — a stalled write/flush simply pends until
  /// you bound it with `timeout(send(..))` or drop the connection. Set it on a
  /// transport whose backpressure hides at `poll_flush` (buffered / TLS) where a
  /// peer may stall, accepting that a transport genuinely slower than this is then
  /// treated as stuck and the connection fails with `Io::TimedOut`. Liveness
  /// (detecting a dead peer) is separate and likewise the caller's job.
  #[must_use]
  pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
    self.write_timeout = Some(timeout);
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
  pub fn with_tls_connector(mut self, connector: futures_rustls::TlsConnector) -> Self {
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
  pub(crate) write_timeout: Option<Duration>,
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

  /// Keepalive ping interval. **Off by default** (tungstenite parity): when set,
  /// the connection sends periodic pings (the peer's pong is consumed internally);
  /// incoming pings are auto-ponged regardless. It imposes NO liveness timeout —
  /// detecting a dead or non-reading peer is the caller's job (`timeout(next())`,
  /// your own ping tracking, or OS TCP keepalive).
  #[must_use]
  pub fn with_keepalive(mut self, interval: Option<Duration>) -> Self {
    self.keepalive = interval;
    self
  }

  /// The close-handshake budget: it bounds flushing our Close, waiting for the
  /// peer's echo (counted from the flush), and the transport shutdown — so a close
  /// completes in a small multiple of it. It bounds ONLY the close handshake, never
  /// ordinary sends. The default is the protocol's (10 s).
  #[must_use]
  pub fn with_close_timeout(mut self, timeout: Duration) -> Self {
    self.close_timeout = Some(timeout);
    self
  }

  /// Per-frame deadline bounding an ordinary write/flush (the `poll_write`
  /// no-progress bound and flush completion). `None` (the default) means the
  /// library imposes NO write deadline — a stalled write/flush simply pends until
  /// you bound it with `timeout(send(..))` or drop the connection. Set it on a
  /// transport whose backpressure hides at `poll_flush` (buffered / TLS) where a
  /// peer may stall, accepting that a transport genuinely slower than this is then
  /// treated as stuck and the connection fails with `Io::TimedOut`. Liveness
  /// (detecting a dead peer) is separate and likewise the caller's job.
  #[must_use]
  pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
    self.write_timeout = Some(timeout);
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
