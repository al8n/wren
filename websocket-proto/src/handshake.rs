//! Opening handshakes (RFC 6455 §4).
//!
//! Over HTTP/1.1 this crate owns the bytes: [`h1::ClientHandshake`] emits the
//! upgrade request and validates the response; [`h1::ServerHandshake`] parses
//! and validates the request and emits the response or a rejection. Both are
//! **stateless re-parsers**: feed the whole accumulated buffer each time
//! (heads are capped at 8 KiB), and on completion the `consumed` offset says
//! where the frame stream begins.
//!
//! Over HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220) the HTTP stack owns the
//! bytes; the `connect` module (plan 3b) expresses the same negotiation as
//! header data instead.

pub(crate) mod parser;

pub use parser::{HeadError, MalformedDetail};

pub mod h1;

use crate::{constants, error::BufferTooSmallDetail};
use sha1::{Digest, Sha1};

/// Derives the `Sec-WebSocket-Accept` value for a `Sec-WebSocket-Key`
/// (RFC 6455 §4.2.2): base64(SHA-1(key ++ GUID)).
pub(crate) fn accept_value(key: &[u8]) -> [u8; constants::SEC_WEBSOCKET_ACCEPT_LEN] {
  let mut hasher = Sha1::new();
  hasher.update(key);
  hasher.update(constants::WEBSOCKET_GUID);
  let digest = hasher.finalize();
  let mut out = [0u8; constants::SEC_WEBSOCKET_ACCEPT_LEN];
  // encoded_len(20) == 28 == the array length, so encode cannot fail; the
  // match is the lint-wall-compatible spelling.
  match crate::base64::encode(&digest, &mut out) {
    Some(_) => out,
    None => out,
  }
}

/// Bounded forward-only writer used by the handshake encoders.
pub(crate) struct WriteCursor<'a> {
  buf: &'a mut [u8],
  written: usize,
}

impl<'a> WriteCursor<'a> {
  pub(crate) fn new(buf: &'a mut [u8]) -> Self {
    Self { buf, written: 0 }
  }

  /// Bytes written so far.
  pub(crate) const fn written(&self) -> usize {
    self.written
  }

  /// Appends `bytes`, or reports the total bytes the buffer would have
  /// needed. A failed push writes nothing.
  pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), BufferTooSmallDetail> {
    let end = self.written.saturating_add(bytes.len());
    match self.buf.get_mut(self.written..end) {
      Some(dst) => {
        for (d, s) in dst.iter_mut().zip(bytes) {
          *d = *s;
        }
        self.written = end;
        Ok(())
      }
      None => Err(BufferTooSmallDetail::new(end, self.buf.len())),
    }
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  #[test]
  fn rfc6455_1_3_accept_vector() {
    assert_eq!(
      &accept_value(b"dGhlIHNhbXBsZSBub25jZQ=="),
      b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
  }

  #[test]
  fn write_cursor_tracks_and_rejects() {
    let mut buf = [0u8; 8];
    let mut w = WriteCursor::new(&mut buf);
    assert!(w.push(b"abc").is_ok());
    assert!(w.push(b"de").is_ok());
    assert_eq!(w.written(), 5);
    let err = w.push(b"toolong").unwrap_err();
    assert_eq!(err.needed(), 12);
    assert_eq!(err.have(), 8);
    // A failed push leaves prior content intact.
    assert_eq!(&buf[..5], b"abcde");
  }
}
