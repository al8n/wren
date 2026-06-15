//! The request-stream inbound FSM: parses one HEADERS frame then DATA frames
//! off the bidirectional request stream, handling split reads, enforcing frame
//! placement (RFC 9114 §7.1/§7.2), and yielding decoded headers + data chunks.
//! Read-side only; the connection builds the outbound frames.

use crate::{
  HeaderSet,
  error::H3Error,
  frame::{self, FrameError, FrameKind},
  qpack,
};

// The largest a frame header (type varint + length varint) can be on the wire:
// two 8-byte varints.
const MAX_HEADER_LEN: usize = 16;

/// Phase of the read side.
enum Phase {
  AwaitingHeaders,
  Tunnel,
}

/// The frame currently being consumed (after its header has been parsed).
enum Cur {
  /// At a frame boundary; the next bytes begin a frame header.
  None,
  /// Accumulating a HEADERS field section into `scratch[0..acc]`.
  Headers { remaining: u64, acc: usize },
  /// Streaming a DATA payload.
  Data { remaining: u64 },
  /// Discarding an unknown/`Other` frame's payload.
  Skip { remaining: u64 },
}

/// Parses inbound frames on the request stream. Feed bytes via [`handle`] and on
/// the QUIC stream FIN call [`fin`].
///
/// The read side begins expecting exactly one HEADERS frame (the CONNECT request
/// on a server, or the response on a client), then a sequence of DATA frames
/// carrying the tunnel payload. Unknown frame types are skipped (RFC 9114 §9);
/// DATA before HEADERS, a second HEADERS, or SETTINGS are protocol violations.
///
/// [`handle`]: RequestStream::handle
/// [`fin`]: RequestStream::fin
pub struct RequestStream {
  phase: Phase,
  cur: Cur,
  /// Partial frame-header bytes (type varint + length varint, `<= 16`).
  hdr_buf: [u8; MAX_HEADER_LEN],
  hdr_len: usize,
}

/// One parsed item, borrowed from the current [`RequestStream::handle`] call.
///
/// Valid only until the next [`Items::next`] call (lending iterator): a `Data`
/// chunk borrows the fed input and a `Headers` set borrows the scratch buffer.
#[derive(derive_more::IsVariant)]
#[non_exhaustive]
pub enum StreamItem<'a> {
  /// A decoded HEADERS field section (drain it before the next `next()`).
  Headers(HeaderSet<'a>),
  /// A chunk of DATA-frame payload (borrows the input).
  Data(&'a [u8]),
}

/// A lending iterator over the items produced by one [`RequestStream::handle`]
/// call. Drive it with [`Items::next`] until it returns `Ok(None)`.
pub struct Items<'a> {
  fsm: &'a mut RequestStream,
  input: &'a [u8],
  pos: usize,
  scratch: &'a mut [u8],
}

impl RequestStream {
  /// A fresh read FSM expecting a HEADERS frame first.
  #[inline]
  pub const fn new() -> Self {
    Self {
      phase: Phase::AwaitingHeaders,
      cur: Cur::None,
      hdr_buf: [0u8; MAX_HEADER_LEN],
      hdr_len: 0,
    }
  }

  /// Feed inbound stream bytes. Returns a lending iterator over the items they
  /// complete.
  ///
  /// `scratch` accumulates a HEADERS field section and backs its QPACK decode; it
  /// must outlive the returned [`Items`] and be large enough for one field
  /// section plus its Huffman expansion. Pass the SAME scratch across calls while
  /// a HEADERS frame is mid-accumulation.
  #[inline]
  pub fn handle<'a>(&'a mut self, bytes: &'a [u8], scratch: &'a mut [u8]) -> Items<'a> {
    Items {
      fsm: self,
      input: bytes,
      pos: 0,
      scratch,
    }
  }

  /// Signal the QUIC stream FIN. `Ok(())` if the stream ended cleanly at a frame
  /// boundary; `Err` (`H3_FRAME_ERROR`) if it ended mid-frame (RFC 9114 §7.1).
  #[inline]
  pub fn fin(&self) -> Result<(), H3Error> {
    match (self.hdr_len, &self.cur) {
      (0, Cur::None) => Ok(()),
      _ => Err(H3Error::FrameError),
    }
  }
}

impl Default for RequestStream {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl Items<'_> {
  /// The next item these bytes complete, or `Ok(None)` when they are exhausted.
  ///
  /// The returned [`StreamItem`] borrows the fed input (`Data`) or the scratch
  /// (`Headers`) and is invalidated by the next call.
  // This is a lending iterator: each item borrows `self` (a `Data` chunk borrows
  // the input, a `Headers` set borrows the scratch), so `std::iter::Iterator`
  // cannot be implemented.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Result<Option<StreamItem<'_>>, H3Error> {
    // Destructure into disjoint field borrows so the borrow checker can see that
    // the input and scratch are separate from the FSM's own state, mirroring the
    // technique in `qpack/decode.rs`.
    let Self {
      fsm,
      input,
      pos,
      scratch,
    } = self;
    loop {
      match fsm.cur {
        Cur::None => {
          // Assemble a frame header byte-by-byte into `fsm.hdr_buf` so a header
          // straddling two reads reassembles and we never over-consume the
          // payload that follows it.
          loop {
            let Some(&b) = input.get(*pos) else {
              return Ok(None); // need more bytes
            };
            *pos = pos.saturating_add(1);
            let slot = fsm
              .hdr_buf
              .get_mut(fsm.hdr_len)
              .ok_or(H3Error::FrameError)?;
            *slot = b;
            fsm.hdr_len = fsm.hdr_len.saturating_add(1);
            match frame::decode_header(fsm.hdr_buf.get(..fsm.hdr_len).unwrap_or(&[])) {
              // Need another byte to complete the type+length varints.
              Err(FrameError::Truncated(_)) => {
                if fsm.hdr_len >= MAX_HEADER_LEN {
                  // Two 8-byte varints already buffered yet still truncated: the
                  // header is malformed (a varint claims more than 8 bytes).
                  return Err(H3Error::FrameError);
                }
                continue;
              }
              // A malformed varint.
              Err(_) => return Err(H3Error::FrameError),
              Ok((_, hdr)) => {
                fsm.hdr_len = 0;
                match (&fsm.phase, hdr.kind()) {
                  (Phase::AwaitingHeaders, FrameKind::Headers) => {
                    fsm.cur = Cur::Headers {
                      remaining: hdr.length(),
                      acc: 0,
                    };
                  }
                  (Phase::Tunnel, FrameKind::Data) => {
                    fsm.cur = Cur::Data {
                      remaining: hdr.length(),
                    };
                  }
                  (_, FrameKind::Other) => {
                    fsm.cur = Cur::Skip {
                      remaining: hdr.length(),
                    };
                  }
                  // DATA before HEADERS (RFC 9114 §7.1).
                  (Phase::AwaitingHeaders, FrameKind::Data) => {
                    return Err(H3Error::FrameUnexpected);
                  }
                  // A second HEADERS frame (this tunnel carries exactly one).
                  (Phase::Tunnel, FrameKind::Headers) => {
                    return Err(H3Error::FrameUnexpected);
                  }
                  // SETTINGS is a control-stream-only frame (RFC 9114 §7.2.4).
                  (_, FrameKind::Settings) => {
                    return Err(H3Error::FrameUnexpected);
                  }
                }
                break; // proceed to process `cur`
              }
            }
          }
        }
        Cur::Headers { remaining, acc } => {
          let avail = input.len().saturating_sub(*pos);
          let take = usize::try_from(remaining).unwrap_or(usize::MAX).min(avail);
          let end = pos.checked_add(take).ok_or(H3Error::FrameError)?;
          let src = input.get(*pos..end).ok_or(H3Error::FrameError)?;
          let acc_end = acc.checked_add(take).ok_or(H3Error::FrameError)?;
          // The field section (plus its eventual Huffman expansion) must fit the
          // caller's scratch.
          let dst = scratch.get_mut(acc..acc_end).ok_or(H3Error::FrameError)?;
          dst.copy_from_slice(src);
          *pos = end;
          let taken = u64::try_from(take).unwrap_or(u64::MAX);
          let remaining = remaining.saturating_sub(taken);
          if remaining == 0 {
            // Decode the complete field section in `scratch[0..acc_end]`, using
            // `scratch[acc_end..]` as Huffman expansion scratch.
            let (fs, huff) = scratch
              .split_at_mut_checked(acc_end)
              .ok_or(H3Error::FrameError)?;
            let hs = qpack::decode_field_section_into(fs, huff).map_err(|e| e.to_h3())?;
            fsm.cur = Cur::None;
            fsm.phase = Phase::Tunnel;
            return Ok(Some(StreamItem::Headers(hs)));
          }
          fsm.cur = Cur::Headers {
            remaining,
            acc: acc_end,
          };
          return Ok(None); // need more
        }
        Cur::Data { remaining } => {
          // Zero-length (or just-completed) DATA frame: advance to next frame.
          // This must come first so a zero-length DATA on an empty buffer does
          // not leave the FSM stuck in `Cur::Data { remaining: 0 }`.
          if remaining == 0 {
            fsm.cur = Cur::None;
            continue;
          }
          let avail = input.len().saturating_sub(*pos);
          if avail == 0 {
            return Ok(None);
          }
          let take = usize::try_from(remaining).unwrap_or(usize::MAX).min(avail);
          let end = pos.checked_add(take).ok_or(H3Error::FrameError)?;
          let chunk = input.get(*pos..end).ok_or(H3Error::FrameError)?;
          *pos = end;
          let taken = u64::try_from(take).unwrap_or(u64::MAX);
          let remaining = remaining.saturating_sub(taken);
          fsm.cur = if remaining == 0 {
            Cur::None
          } else {
            Cur::Data { remaining }
          };
          return Ok(Some(StreamItem::Data(chunk)));
        }
        Cur::Skip { remaining } => {
          let avail = input.len().saturating_sub(*pos);
          let take = usize::try_from(remaining).unwrap_or(usize::MAX).min(avail);
          let end = pos.checked_add(take).ok_or(H3Error::FrameError)?;
          *pos = end;
          let taken = u64::try_from(take).unwrap_or(u64::MAX);
          let remaining = remaining.saturating_sub(taken);
          if remaining == 0 {
            fsm.cur = Cur::None; // loop to the next frame
          } else {
            fsm.cur = Cur::Skip { remaining };
            return Ok(None);
          }
        }
      }
    }
  }
}

#[cfg(all(test, feature = "alloc"))]
mod tests;
