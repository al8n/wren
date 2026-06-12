//! Conversion from a transport into the poll-based duplex the driver runs
//! on.
//!
//! compio's native IO is completion-based: a read/write future *owns* the
//! submitted kernel operation, so dropping it (a lost `select!` arm, a
//! caller-side `timeout`) cancels the operation — and a cancelled read may
//! already have consumed bytes the kernel then discards. A WebSocket pump
//! that races reads against timers cannot be built safely on that contract.
//!
//! The driver therefore converts every transport into a **poll-based**
//! duplex up front. Poll-style futures are cancellation-atomic — `Pending`
//! means nothing was consumed — and in-flight completion operations live
//! *inside* the adapter ([`AsyncStream`](compio_io::compat::AsyncStream)), so they survive any dropped
//! caller future.

/// The poll-based duplex bound the connection drives (alias for
/// `futures_util::io` read + write + `Unpin` + `'static`).
///
/// Blanket-implemented; never implement it directly — implement the
/// `futures_util::io` traits and this follows.
pub trait Duplex: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin + 'static {}

impl<T: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin + 'static> Duplex for T {}

/// A transport that can be converted into the poll-based duplex the
/// connection pumps.
///
/// Implemented for compio's socket streams (adapted through
/// [`AsyncStream`](compio_io::compat::AsyncStream), whose internal
/// buffers carry in-flight operations
/// across cancelled futures), for `compio_tls::TlsStream` (already
/// poll-based internally; `tls` feature), and for
/// [`MaybeTls`](crate::MaybeTls), the transport [`connect`](crate::connect)
/// produces.
///
/// For your own transport: if it is poll-based (`futures_util::io` traits +
/// `Unpin`), implement with `Duplex = Self` and an identity `into_duplex`;
/// if it is a completion-based [`Splittable`](compio_io::util::Splittable)
/// stream, mirror the socket impls with
/// `Duplex = Pin<Box<AsyncStream<Self>>>` and
/// `Box::pin(AsyncStream::new(self))`.
pub trait IntoDuplex {
  /// The poll-based duplex the connection drives.
  type Duplex: Duplex;

  /// Performs the conversion.
  fn into_duplex(self) -> Self::Duplex;
}

/// Stamps the adapter impl for completion-based `Splittable` streams.
/// (A blanket impl over `Splittable` would conflict with the `TlsStream`
/// identity impl below under coherence.)
macro_rules! adapted_into_duplex {
  ($($(#[$meta:meta])* $ty:ty),* $(,)?) => {
    $(
      $(#[$meta])*
      impl $crate::IntoDuplex for $ty {
        type Duplex =
          ::std::pin::Pin<::std::boxed::Box<::compio_io::compat::AsyncStream<$ty>>>;

        fn into_duplex(self) -> Self::Duplex {
          ::std::boxed::Box::pin(::compio_io::compat::AsyncStream::new(self))
        }
      }
    )*
  };
}

adapted_into_duplex! {
  compio_net::TcpStream,
  #[cfg(unix)]
  compio_net::UnixStream,
}

#[cfg(test)]
pub(crate) use adapted_into_duplex;

#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
impl<S> IntoDuplex for compio_tls::TlsStream<S>
where
  S: compio_io::util::Splittable + 'static,
  S::ReadHalf: compio_io::AsyncRead + Unpin + 'static,
  S::WriteHalf: compio_io::AsyncWrite + Unpin + 'static,
{
  type Duplex = Self;

  fn into_duplex(self) -> Self::Duplex {
    self
  }
}
