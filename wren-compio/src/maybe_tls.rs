//! The stream behind [`connect`](crate::connect): plain TCP or TLS-wrapped
//! TCP, unified so the function's return type stays concrete.

use compio_buf::{BufResult, IoBuf, IoBufMut};
use compio_io::{AsyncRead, AsyncWrite};
use compio_net::TcpStream;

/// Plain TCP (`ws://`) or TLS over TCP (`wss://`, feature `tls`).
#[derive(Debug)]
pub enum MaybeTls {
  /// `ws://`.
  Plain(TcpStream),
  /// `wss://`. Boxed: the TLS state dwarfs the plain variant's handle.
  #[cfg(feature = "tls")]
  #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
  Tls(Box<compio_tls::TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTls {
  async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
    match self {
      Self::Plain(stream) => stream.read(buf).await,
      #[cfg(feature = "tls")]
      Self::Tls(stream) => stream.read(buf).await,
    }
  }
}

impl AsyncWrite for MaybeTls {
  async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
    match self {
      Self::Plain(stream) => stream.write(buf).await,
      #[cfg(feature = "tls")]
      Self::Tls(stream) => stream.write(buf).await,
    }
  }

  async fn flush(&mut self) -> std::io::Result<()> {
    match self {
      Self::Plain(stream) => stream.flush().await,
      #[cfg(feature = "tls")]
      Self::Tls(stream) => stream.flush().await,
    }
  }

  async fn shutdown(&mut self) -> std::io::Result<()> {
    match self {
      Self::Plain(stream) => stream.shutdown().await,
      #[cfg(feature = "tls")]
      Self::Tls(stream) => stream.shutdown().await,
    }
  }
}
