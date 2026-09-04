#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

mod conn;
mod error;
mod handshake;
mod into_duplex;
mod maybe_tls;
mod options;
mod url;

pub use conn::{ClientRole, ReadHalf, ServerRole, WebSocket, WriteHalf};
pub use into_duplex::{Duplex, IntoDuplex};
pub use maybe_tls::MaybeTls;
use websocket_proto::handshake::h1::ServerHandshake;
pub use websocket_proto::{Negotiated, connection::Closed, frame::CloseCode, message::Message};

/// The connection type [`connect`] returns.
pub type ClientWebSocket = WebSocket<ClientRole, MaybeTls>;

/// Connects to a `ws://` or `wss://` URL and completes the opening
/// handshake.
///
/// `wss://` needs the `tls` feature. The default trust anchors are the
/// webpki (Mozilla) roots — the platform certificate store is **not**
/// consulted, so corporate or otherwise custom CAs need a caller-built
/// connector via `ClientOptions::with_tls_connector` — named in plain code
/// rather than linked, because it exists only under `tls` and an intra-doc link
/// to a gated item is a rustdoc error in every build without it.
pub async fn connect(
  url: &str,
  options: ClientOptions,
) -> Result<(ClientWebSocket, ConnectResponse), ConnectError> {
  let parsed = url::WsUrl::parse(url)?;
  #[cfg(not(feature = "tls"))]
  if parsed.tls {
    return Err(ConnectError::UnsupportedScheme);
  }
  wren_trace::debug!(url, "connecting");
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
    MaybeTls::plain(tcp)
  };
  client(stream, parsed.authority, parsed.path_and_query, options).await
}

/// Completes the client handshake over a caller-provided transport (custom
/// dialers, proxies, pre-wrapped TLS) — see [`IntoDuplex`].
pub async fn client<S: IntoDuplex>(
  stream: S,
  host: &str,
  path_and_query: &str,
  options: ClientOptions,
) -> Result<(WebSocket<ClientRole, S::Duplex>, ConnectResponse), ConnectError> {
  let (stream, outcome) =
    handshake::drive_client(stream.into_duplex(), host, path_and_query, &options).await?;
  let ws = WebSocket::client(stream, &outcome.negotiated, &options, outcome.leftover);
  Ok((
    ws,
    ConnectResponse {
      negotiated: outcome.negotiated,
    },
  ))
}

/// Accepts one WebSocket upgrade on a caller-provided transport (accept
/// the TCP connection — and wrap TLS, if any — first) — see
/// [`IntoDuplex`].
///
/// This commits the 101 unconditionally. Servers that authorize requests
/// (Origin checks, auth headers, routing) before upgrading use
/// [`accept_pending`] and decide between [`PendingAccept::accept`] and
/// [`PendingAccept::reject`].
pub async fn accept<S: IntoDuplex>(
  stream: S,
  options: AcceptOptions,
) -> Result<(WebSocket<ServerRole, S::Duplex>, RequestSummary), AcceptError> {
  accept_pending(stream, options).await?.accept().await
}

/// Reads one upgrade request and stops BEFORE answering, so the caller
/// can authorize it — reject by Origin, Host, path, or auth — without
/// establishing the connection first.
pub async fn accept_pending<S: IntoDuplex>(
  stream: S,
  options: AcceptOptions,
) -> Result<PendingAccept<S::Duplex>, AcceptError> {
  let mut stream = stream.into_duplex();
  let pending = handshake::drive_server_request(&mut stream, &options).await?;
  Ok(PendingAccept {
    stream,
    handshake: pending.handshake,
    summary: pending.summary,
    buffered: pending.buffered,
    options,
  })
}

/// An upgrade request that has been read but not yet answered.
///
/// Inspect [`request`](Self::request), then [`accept`](Self::accept) or
/// [`reject`](Self::reject).
#[derive(Debug)]
pub struct PendingAccept<D> {
  stream: D,
  /// Classified, carrying RFC 6455 §4.2.2's request-bound answer — settled
  /// while the request was readable, and held by the one connection that can
  /// write it — and still owing the peer whichever answer the application
  /// chooses.
  handshake: ServerHandshake,
  summary: RequestSummary,
  /// Frames the client pipelined behind its request head; they belong to the
  /// connection machine, not to the handshake.
  buffered: Vec<u8>,
  options: AcceptOptions,
}

impl<D: Duplex> PendingAccept<D> {
  /// The upgrade request awaiting a decision.
  pub fn request(&self) -> &RequestSummary {
    &self.summary
  }

  /// Sends the 101 and establishes the connection.
  pub async fn accept(self) -> Result<(WebSocket<ServerRole, D>, RequestSummary), AcceptError> {
    let (stream, outcome) = handshake::finish_accept(
      self.stream,
      self.handshake,
      self.summary,
      self.buffered,
      &self.options,
    )
    .await?;
    let ws = WebSocket::server(stream, &outcome.negotiated, &self.options, outcome.leftover);
    Ok((ws, outcome.summary))
  }

  /// Answers with a non-101 rejection (status 300–599) and drops the
  /// transport.
  pub async fn reject(mut self, status: u16, reason: &str) -> Result<(), AcceptError> {
    handshake::finish_reject(&mut self.stream, self.handshake, status, reason).await
  }
}

/// rustls client config trusting the webpki (Mozilla) roots — deterministic
/// builds, no platform cert store reads. Callers needing custom CAs supply
/// their own connector through [`ClientOptions::with_tls_connector`].
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

/// The oracle for this crate's allocation bounds: a `#[global_allocator]` for
/// the unit-test binary that counts bytes allocated ON THE CALLING THREAD
/// while armed.
///
/// A bound written as "this loop must not allocate per pass" cannot be
/// asserted by reading a buffer's capacity — the buffer under test may be
/// dropped and freshly allocated on every pass, which is precisely the defect,
/// and its capacity then reads the same either way. Counting is the only
/// measurement that tells those apart, so this wraps `System` and the tests
/// arm it around the window they mean.
///
/// **Per THREAD, and const-initialised**, both deliberately. `cargo test` runs
/// tests in parallel threads, and a process-wide counter would attribute their
/// allocations to whichever test happened to be armed; a compio runtime and
/// the tasks it spawns live on the thread that created them, so a
/// thread-local counter sees exactly the driver under test and nothing else.
/// Const initialisation keeps the counter itself out of the allocator: a
/// lazily-initialised `thread_local!` would allocate on first touch, from
/// inside `alloc`.
#[cfg(test)]
pub(crate) mod counting_alloc {
  use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
  };

  thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static BYTES: Cell<u64> = const { Cell::new(0) };
  }

  /// `System`, plus the count.
  pub(crate) struct Counting;

  // SAFETY: every method forwards to `System` with the arguments it was given
  // and returns its pointer unchanged, so the safety contract is `System`'s.
  // The counter is a side effect on a const-initialised thread-local `Cell`,
  // which allocates nothing and so cannot re-enter.
  unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
      record(layout.size());
      unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
      record(layout.size());
      unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
      unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
      // Only the GROWTH counts: a `Vec` that doubles from 8 KiB to 16 KiB
      // acquired 8 KiB, and counting the whole new size would make one
      // grown buffer look like two fresh ones.
      record(new_size.saturating_sub(layout.size()));
      unsafe { System.realloc(ptr, layout, new_size) }
    }
  }

  fn record(bytes: usize) {
    // `try_with` rather than `with`: during thread teardown the thread-local
    // is gone, and an allocation there must not panic out of the allocator.
    let _ = ARMED.try_with(|armed| {
      if armed.get() {
        let _ = BYTES.try_with(|total| {
          total.set(
            total
              .get()
              .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX)),
          );
        });
      }
    });
  }

  /// Starts counting on this thread, from zero.
  pub(crate) fn arm() {
    BYTES.with(|total| total.set(0));
    ARMED.with(|armed| armed.set(true));
  }

  /// Stops counting and answers the bytes allocated since [`arm`].
  pub(crate) fn disarm() -> u64 {
    ARMED.with(|armed| armed.set(false));
    BYTES.with(Cell::get)
  }
}

#[cfg(test)]
#[global_allocator]
static COUNTING_ALLOCATOR: counting_alloc::Counting = counting_alloc::Counting;

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
