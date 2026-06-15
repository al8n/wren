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

/// The largest HEADERS field section (QPACK-encoded, on the wire) this FSM will
/// accumulate. The in-progress field section is buffered into FSM-owned storage
/// of this size across split reads; a field section larger than this is rejected
/// with a graceful [`H3Error::FrameError`] (never a panic). This is purely an
/// internal *encoded*-payload memory bound; we do NOT advertise it as
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (that setting limits the *decoded*
/// field-section size, which our lazy decoder never accumulates — see
/// [`Settings::for_client`](crate::settings::Settings::for_client)). The CONNECT
/// request/response field sections are a handful of pseudo-header lines, far
/// below this.
pub(crate) const HDR_CAP: usize = 4096;

/// Phase of the read side.
enum Phase {
  AwaitingHeaders,
  Tunnel,
}

/// The frame currently being consumed (after its header has been parsed).
enum Cur {
  /// At a frame boundary; the next bytes begin a frame header.
  None,
  /// Accumulating a HEADERS field section into the FSM-owned `hdr_acc[0..acc]`.
  Headers { remaining: u64, acc: usize },
  /// Streaming a DATA payload.
  Data { remaining: u64 },
  /// Discarding an unknown (GREASE / extension) frame's payload.
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
/// A naturally-fragmented HEADERS frame is accumulated into FSM-owned storage
/// (`hdr_acc`), so the caller's `scratch` is needed only as transient
/// Huffman-decode space and may be a fresh buffer on every [`handle`] call.
///
/// [`handle`]: RequestStream::handle
/// [`fin`]: RequestStream::fin
pub struct RequestStream {
  phase: Phase,
  cur: Cur,
  /// Partial frame-header bytes (type varint + length varint, `<= 16`).
  hdr_buf: [u8; MAX_HEADER_LEN],
  hdr_len: usize,
  /// The in-progress HEADERS field section, accumulated across [`handle`] calls
  /// into FSM-owned storage so the caller's `scratch` need not be preserved
  /// between calls. The valid prefix is `hdr_acc[..acc]` where `acc` lives in the
  /// active [`Cur::Headers`]; bounded at [`HDR_CAP`] (oversize is a graceful
  /// [`H3Error::FrameError`]).
  ///
  /// [`handle`]: RequestStream::handle
  hdr_acc: [u8; HDR_CAP],
}

/// One parsed item, borrowed from the current [`RequestStream::handle`] call.
///
/// Valid only until the next [`Items::next`] call (lending iterator): a `Data`
/// chunk borrows the fed input and a `Headers` set borrows the FSM-owned field
/// accumulator plus the caller's Huffman scratch.
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

/// One advance of the FSM, described WITHOUT borrowing `self` — offsets into the
/// fed input (a DATA chunk) or the completed-section length (a HEADERS frame). This
/// is the borrow-free shape [`Items::advance`] returns so a caller can loop over the
/// items (e.g. to skip an established-but-empty DATA frame) without a returned-borrow
/// crossing the loop back-edge, then re-derive the actual borrow once it stops. The
/// FSM has already advanced past the described item when this is returned.
pub(crate) enum Advanced {
  /// A completed HEADERS field section now lives in the FSM-owned `hdr_acc[..acc_end]`
  /// (already validated by [`Items::advance`]); decode it with
  /// [`Items::decode_buffered_headers`].
  Headers { acc_end: usize },
  /// A DATA-frame payload chunk occupies `input[start..end]` (an empty `start == end`
  /// for a zero-length DATA frame). Re-slice it with [`Items::input`].
  Data { start: usize, end: usize },
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
      hdr_acc: [0u8; HDR_CAP],
    }
  }

  /// Feed inbound stream bytes. Returns a lending iterator over the items they
  /// complete.
  ///
  /// `scratch` is transient Huffman-decode space: when a HEADERS field section
  /// completes, its QPACK decode writes each Huffman-coded field line's
  /// name+value here. The in-progress field section itself is accumulated into
  /// FSM-owned storage, so `scratch` need NOT be preserved across calls — it MAY
  /// be a fresh (even zeroed) buffer on every call. It must outlive the returned
  /// [`Items`] and be large enough for the longest single field line's decoded
  /// name+value.
  #[inline]
  pub fn handle<'a>(&'a mut self, bytes: &'a [u8], scratch: &'a mut [u8]) -> Items<'a> {
    Items {
      fsm: self,
      input: bytes,
      pos: 0,
      scratch,
    }
  }

  /// Signal the QUIC stream FIN.
  ///
  /// - `Ok(())` — a clean half-close at a frame boundary *after* the mandatory
  ///   CONNECT HEADERS were decoded (the FSM reached the tunnel phase). The peer
  ///   ended its send side of an established tunnel (RFC 9114 §7.1).
  /// - `Err(`[`H3Error::RequestIncomplete`]`)` — a frame-boundary FIN while still
  ///   awaiting the first HEADERS: the request / response field section never
  ///   arrived, so the request is incomplete (the connection cannot proceed).
  /// - `Err(`[`H3Error::FrameError`]`)` — a FIN mid-frame (a header or payload was
  ///   cut off), which is malformed framing.
  #[inline]
  pub fn fin(&self) -> Result<(), H3Error> {
    match (self.hdr_len, &self.cur) {
      // A clean frame boundary: a half-close after the HEADERS is graceful, but a
      // FIN that arrives before the mandatory CONNECT HEADERS leaves the request
      // incomplete (RFC 9114 §8.1) — the tunnel never had its field section.
      (0, Cur::None) => match self.phase {
        Phase::Tunnel => Ok(()),
        Phase::AwaitingHeaders => Err(H3Error::RequestIncomplete),
      },
      // Mid-frame: a header or payload was truncated by the FIN (malformed).
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

impl<'a> Items<'a> {
  /// The next item these bytes complete, or `Ok(None)` when they are exhausted.
  ///
  /// The returned [`StreamItem`] borrows the fed input (`Data`) or the FSM-owned
  /// field accumulator plus the caller's Huffman scratch (`Headers`) and is
  /// invalidated by the next call.
  // This is a lending iterator: each item borrows `self` (a `Data` chunk borrows
  // the input, a `Headers` set borrows the field accumulator + scratch), so
  // `std::iter::Iterator` cannot be implemented. It is a thin shell over the
  // borrow-free `advance`, re-deriving the borrow for whichever kind `advance`
  // reports; the FSM logic lives once in `advance`.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Result<Option<StreamItem<'_>>, H3Error> {
    match self.advance()? {
      None => Ok(None),
      Some(Advanced::Headers { acc_end }) => Ok(Some(StreamItem::Headers(
        self.decode_buffered_headers(acc_end)?,
      ))),
      Some(Advanced::Data { start, end }) => {
        let chunk = self.input.get(start..end).ok_or(H3Error::FrameError)?;
        Ok(Some(StreamItem::Data(chunk)))
      }
    }
  }

  /// The fed input slice (input lifetime), so a caller that drove the FSM with
  /// [`advance`](Self::advance) can re-derive a DATA chunk's bytes from the reported
  /// offsets independently of any `&mut self` borrow.
  pub(crate) fn input(&self) -> &'a [u8] {
    self.input
  }

  /// Decodes the completed, already-validated HEADERS field section sitting in the
  /// FSM-owned `hdr_acc[..acc_end]` (the section [`advance`](Self::advance) reported as
  /// [`Advanced::Headers`]). This is the FRESH yield decode: [`advance`] has already
  /// run the throwaway validation pass that propagates any QPACK error up front, so
  /// this second decode over the same owned bytes is what the caller drains, using the
  /// caller's `scratch` purely as Huffman-output space. The `hdr_acc` (immutable) and
  /// `scratch` borrows are disjoint, so the yielded [`HeaderSet`] may tie to both.
  pub(crate) fn decode_buffered_headers(
    &mut self,
    acc_end: usize,
  ) -> Result<HeaderSet<'_>, H3Error> {
    let fs = self.fsm.hdr_acc.get(..acc_end).ok_or(H3Error::FrameError)?;
    qpack::decode_field_section_into(fs, self.scratch).map_err(|e| e.to_h3())
  }

  /// Advances the FSM by one item, returning a borrow-free [`Advanced`] (offsets /
  /// the completed-section length) rather than a borrowing [`StreamItem`]. The FSM
  /// state is left positioned PAST the returned item; `Ok(None)` means the fed bytes
  /// are exhausted. Skipped frames (a Huffman/GREASE payload, RFC 9114 §9) are
  /// consumed internally so the caller only ever sees a real HEADERS / DATA item.
  ///
  /// Returning offsets (not borrows) lets a caller loop over items — e.g. to skip an
  /// established-but-empty DATA frame while still passing every DATA frame through the
  /// connection's establishment gate — without a returned borrow crossing the loop
  /// back-edge (which stable NLL rejects); the caller re-derives the borrow via
  /// [`input`](Self::input) / [`decode_buffered_headers`](Self::decode_buffered_headers)
  /// once it stops. A completed HEADERS section is fully validated here (the throwaway
  /// QPACK pass), so a malformed section surfaces as `Err` from `advance` regardless of
  /// how the caller re-decodes.
  pub(crate) fn advance(&mut self) -> Result<Option<Advanced>, H3Error> {
    // Destructure into disjoint field borrows so the borrow checker can see that
    // the input and scratch are separate from the FSM's own state, mirroring the
    // technique in `qpack/decode.rs`.
    let Self {
      fsm,
      input,
      pos,
      scratch,
    } = self;
    let RequestStream {
      phase,
      cur,
      hdr_buf,
      hdr_len,
      hdr_acc,
    } = &mut **fsm;
    loop {
      match *cur {
        Cur::None => {
          // Assemble a frame header byte-by-byte into `hdr_buf` so a header
          // straddling two reads reassembles and we never over-consume the
          // payload that follows it.
          loop {
            let Some(&b) = input.get(*pos) else {
              return Ok(None); // need more bytes
            };
            *pos = pos.saturating_add(1);
            let slot = hdr_buf.get_mut(*hdr_len).ok_or(H3Error::FrameError)?;
            *slot = b;
            *hdr_len = hdr_len.saturating_add(1);
            match frame::decode_header(hdr_buf.get(..*hdr_len).unwrap_or(&[])) {
              // Need another byte to complete the type+length varints.
              Err(FrameError::Truncated(_)) => {
                if *hdr_len >= MAX_HEADER_LEN {
                  // Two 8-byte varints already buffered yet still truncated: the
                  // header is malformed (a varint claims more than 8 bytes).
                  return Err(H3Error::FrameError);
                }
                continue;
              }
              // A malformed varint.
              Err(_) => return Err(H3Error::FrameError),
              Ok((_, hdr)) => {
                *hdr_len = 0;
                match (&*phase, hdr.kind()) {
                  (Phase::AwaitingHeaders, FrameKind::Headers) => {
                    *cur = Cur::Headers {
                      remaining: hdr.length(),
                      acc: 0,
                    };
                  }
                  (Phase::Tunnel, FrameKind::Data) => {
                    *cur = Cur::Data {
                      remaining: hdr.length(),
                    };
                  }
                  // GREASE / unknown extension frames are ignored (RFC 9114 §9).
                  (_, FrameKind::Unknown) => {
                    *cur = Cur::Skip {
                      remaining: hdr.length(),
                    };
                  }
                  // PUSH_PROMISE carries a push id, but this crate never enables
                  // server push (it never sends MAX_PUSH_ID, so the max push id
                  // stays 0). A PUSH_PROMISE therefore references a push id the
                  // peer was never granted: H3_ID_ERROR (RFC 9114 §7.2.5 / §8.1),
                  // not a placement (FrameUnexpected) error.
                  (_, FrameKind::PushPromise) => return Err(H3Error::IdError),
                  // Every remaining type is forbidden on the request stream
                  // (RFC 9114 §7.2 frame placement): DATA before HEADERS or a
                  // second HEADERS (only one HEADERS exchange per tunnel);
                  // SETTINGS / CANCEL_PUSH / GOAWAY / MAX_PUSH_ID (control-stream
                  // frames); and the HTTP/2-reserved types (§7.2.8). All are
                  // H3_FRAME_UNEXPECTED.
                  (
                    _,
                    FrameKind::Data
                    | FrameKind::Headers
                    | FrameKind::Settings
                    | FrameKind::CancelPush
                    | FrameKind::GoAway
                    | FrameKind::MaxPushId
                    | FrameKind::Reserved,
                  ) => {
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
          // Accumulate the field section into FSM-owned storage (not the caller's
          // scratch, which may be fresh each call). A field section larger than
          // `HDR_CAP` is a graceful frame error, never a panic; `get_mut` rejects
          // `acc_end > HDR_CAP` for us.
          let dst = hdr_acc.get_mut(acc..acc_end).ok_or(H3Error::FrameError)?;
          dst.copy_from_slice(src);
          *pos = end;
          let taken = u64::try_from(take).unwrap_or(u64::MAX);
          let remaining = remaining.saturating_sub(taken);
          if remaining == 0 {
            // The complete field section lives in the owned `hdr_acc[..acc_end]`.
            let fs = hdr_acc.get(..acc_end).ok_or(H3Error::FrameError)?;
            // Validate the ENTIRE field section up front. The yielded `HeaderSet`
            // is a lazy lending iterator, so a QPACK error in a LATER field line
            // (e.g. a dynamic/post-base reference after a valid `:status`) would
            // otherwise surface only if the driver fully drains it — a driver that
            // reads one field and stops could enter tunnel mode on a malformed
            // section. So decode + drain a throwaway pass here, propagating any
            // error UNCONDITIONALLY. The caller re-decodes a fresh pass over the
            // same owned `hdr_acc` via `decode_buffered_headers`.
            {
              let mut probe =
                qpack::decode_field_section_into(fs, scratch).map_err(|e| e.to_h3())?;
              while probe.next().map_err(|e| e.to_h3())?.is_some() {}
            }
            // Validation fully succeeded: only now commit the phase transition and
            // report the completed section's length. The bytes stay in `hdr_acc`
            // (only one HEADERS frame ever arrives, so they are not overwritten),
            // so the caller's fresh decode reads them back.
            *cur = Cur::None;
            *phase = Phase::Tunnel;
            return Ok(Some(Advanced::Headers { acc_end }));
          }
          *cur = Cur::Headers {
            remaining,
            acc: acc_end,
          };
          return Ok(None); // need more
        }
        Cur::Data { remaining } => {
          // A zero-length DATA frame yields ONE empty occurrence, then advances.
          // The non-empty path sets `cur` to `Cur::None` directly once a payload
          // completes, so this branch is reached only for a length-0 DATA header.
          // Reporting an empty `Data { start == end }` here (rather than silently
          // skipping) makes every DATA frame — even an empty one — a real DATA
          // occurrence the connection's establishment gate sees exactly once;
          // advancing `cur` to `Cur::None` first means the next call resumes at a
          // frame boundary, so a zero-length DATA on an empty buffer never sticks at
          // `Cur::Data { remaining: 0 }`.
          if remaining == 0 {
            *cur = Cur::None;
            return Ok(Some(Advanced::Data {
              start: *pos,
              end: *pos,
            }));
          }
          let avail = input.len().saturating_sub(*pos);
          if avail == 0 {
            return Ok(None);
          }
          let take = usize::try_from(remaining).unwrap_or(usize::MAX).min(avail);
          let start = *pos;
          let end = pos.checked_add(take).ok_or(H3Error::FrameError)?;
          // Bounds-check the chunk range now so the caller's `input.get(start..end)`
          // re-slice cannot fail.
          let _ = input.get(start..end).ok_or(H3Error::FrameError)?;
          *pos = end;
          let taken = u64::try_from(take).unwrap_or(u64::MAX);
          let remaining = remaining.saturating_sub(taken);
          *cur = if remaining == 0 {
            Cur::None
          } else {
            Cur::Data { remaining }
          };
          return Ok(Some(Advanced::Data { start, end }));
        }
        Cur::Skip { remaining } => {
          let avail = input.len().saturating_sub(*pos);
          let take = usize::try_from(remaining).unwrap_or(usize::MAX).min(avail);
          let end = pos.checked_add(take).ok_or(H3Error::FrameError)?;
          *pos = end;
          let taken = u64::try_from(take).unwrap_or(u64::MAX);
          let remaining = remaining.saturating_sub(taken);
          if remaining == 0 {
            *cur = Cur::None; // loop to the next frame
          } else {
            *cur = Cur::Skip { remaining };
            return Ok(None);
          }
        }
      }
    }
  }
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod tests;
