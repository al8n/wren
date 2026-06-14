//! The poll-based duplex bound the driver runs on (futures-io + `Send`).

/// A bidirectional byte stream the driver can split and pump. Blanket-
/// implemented; never implement it directly — implement the `futures_util::io`
/// traits and this follows. `Send` so the split halves cross worker threads.
pub trait Duplex:
  futures_util::AsyncRead + futures_util::AsyncWrite + Unpin + Send + 'static
{
}

impl<T: futures_util::AsyncRead + futures_util::AsyncWrite + Unpin + Send + 'static> Duplex for T {}
