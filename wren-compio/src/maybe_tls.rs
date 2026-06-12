//! The duplex behind [`connect`](crate::connect): plain TCP or TLS over
//! TCP, unified so the function's return type stays concrete.

use std::{
  io,
  pin::Pin,
  task::{Context, Poll},
};

use compio_io::compat::AsyncStream;
use compio_net::TcpStream;

use crate::IntoDuplex;

/// Plain TCP (`ws://`) or TLS over TCP (`wss://`, feature `tls`), already
/// in the driver's poll-based form (see [`IntoDuplex`]).
#[derive(Debug)]
pub enum MaybeTls {
  /// `ws://`.
  Plain(Pin<Box<AsyncStream<TcpStream>>>),
  /// `wss://`. Boxed: the TLS state dwarfs the plain variant.
  #[cfg(feature = "tls")]
  #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
  Tls(Box<compio_tls::TlsStream<TcpStream>>),
}

impl MaybeTls {
  pub(crate) fn plain(stream: TcpStream) -> Self {
    Self::Plain(stream.into_duplex())
  }
}

impl IntoDuplex for MaybeTls {
  type Duplex = Self;

  fn into_duplex(self) -> Self::Duplex {
    self
  }
}

impl futures_util::AsyncRead for MaybeTls {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
      #[cfg(feature = "tls")]
      Self::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
    }
  }
}

impl futures_util::AsyncWrite for MaybeTls {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
      #[cfg(feature = "tls")]
      Self::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
      #[cfg(feature = "tls")]
      Self::Tls(stream) => Pin::new(&mut **stream).poll_flush(cx),
    }
  }

  fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match self.get_mut() {
      Self::Plain(stream) => Pin::new(stream).poll_close(cx),
      #[cfg(feature = "tls")]
      Self::Tls(stream) => Pin::new(&mut **stream).poll_close(cx),
    }
  }
}
