//! The stream behind [`connect`](crate::connect): plain TCP or TLS over TCP,
//! unified so the function's return type stays concrete. The split into
//! read/write halves happens afterward, inside the connection.

use std::{
  io,
  pin::Pin,
  task::{Context, Poll},
};

/// Plain TCP (`ws://`) or TLS over TCP (`wss://`, feature `tls`).
#[derive(Debug)]
pub enum MaybeTls<S> {
  /// `ws://`.
  Plain(S),
  /// `wss://`. Boxed: the TLS state dwarfs the plain variant.
  #[cfg(feature = "tls")]
  #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
  Tls(Box<futures_rustls::client::TlsStream<S>>),
}

impl<S: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin> futures_util::AsyncRead for MaybeTls<S> {
  fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &mut [u8]) -> Poll<io::Result<usize>> {
    match self.get_mut() {
      Self::Plain(s) => Pin::new(s).poll_read(cx, b),
      #[cfg(feature = "tls")]
      Self::Tls(s) => Pin::new(&mut **s).poll_read(cx, b),
    }
  }
}

impl<S: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin> futures_util::AsyncWrite for MaybeTls<S> {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
    match self.get_mut() {
      Self::Plain(s) => Pin::new(s).poll_write(cx, b),
      #[cfg(feature = "tls")]
      Self::Tls(s) => Pin::new(&mut **s).poll_write(cx, b),
    }
  }
  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match self.get_mut() {
      Self::Plain(s) => Pin::new(s).poll_flush(cx),
      #[cfg(feature = "tls")]
      Self::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
    }
  }
  fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match self.get_mut() {
      Self::Plain(s) => Pin::new(s).poll_close(cx),
      #[cfg(feature = "tls")]
      Self::Tls(s) => Pin::new(&mut **s).poll_close(cx),
    }
  }
}
