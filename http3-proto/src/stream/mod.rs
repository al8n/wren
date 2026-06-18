//! The inbound stream FSM: parses the RFC 9114 §4.1 sequence
//! `HEADERS(interim)* HEADERS(final) DATA* HEADERS(trailers)?` off a bidirectional
//! request/response stream, handling split reads, enforcing frame placement
//! (RFC 9114 §7.1/§7.2), and yielding placement-tagged decoded headers + data
//! chunks. Read-side only; the connection builds the outbound frames.

use core::marker::PhantomData;

use derive_more::IsVariant;

use crate::{
  HeaderSet,
  error::H3Error,
  frame::{self, FrameError, FrameKind},
  qpack,
};

// The largest a frame header (type varint + length varint) can be on the wire:
// two 8-byte varints.
const MAX_HEADER_LEN: usize = 16;

/// The default HEADERS field-section accumulator size (QPACK-encoded, on the
/// wire) used by the alloc/std owned constructor and by the recommended borrowed
/// buffer size. A field section larger than the configured accumulator is
/// rejected with a graceful [`H3Error::FrameError`] (never a panic). This is
/// purely an internal *encoded*-payload memory bound; we do NOT advertise it as
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (that setting limits the *decoded*
/// field-section size, which our lazy decoder never accumulates — see
/// [`Settings::for_client`](crate::settings::Settings::for_client)). The CONNECT
/// request/response field sections are a handful of pseudo-header lines, far
/// below this.
pub const HDR_CAP: usize = 4096;

/// Default request HEADERS accumulator storage.
///
/// With `std` or `alloc`, the default read FSM stores this in a heap-backed
/// `Vec<u8>` so `RequestStream<'static>` and the default owned `Connection`
/// stay small.
#[cfg(any(feature = "std", feature = "alloc"))]
pub type DefaultReqBuf<'a> = std::vec::Vec<u8>;

/// Default request HEADERS accumulator storage.
///
/// With no allocator available, the default is borrowed caller-owned storage so
/// `RequestStream<'a>` and borrowed connections stay small. Construct it with
/// [`RequestStream::with_buffer`].
#[cfg(not(any(feature = "std", feature = "alloc")))]
pub type DefaultReqBuf<'a> = &'a mut [u8];

#[cfg(any(feature = "std", feature = "alloc"))]
pub(crate) fn default_req_buf() -> DefaultReqBuf<'static> {
  std::vec![0u8; HDR_CAP]
}

/// Which placement a decoded HEADERS section occupies in the RFC 9114 §4.1
/// request-stream sequence `HEADERS(interim)* HEADERS(final) DATA* HEADERS(trailers)?`.
///
/// The recv FSM classifies by *placement* only: the first HEADERS section(s) are
/// [`Initial`](Self::Initial) (the connection/validator decide interim-vs-final
/// by `:status`); a HEADERS section that arrives after any DATA frame is
/// [`Trailers`](Self::Trailers). The request/response direction is decided by the
/// connection from its role, not here.
#[derive(Debug, Clone, Copy, Eq, PartialEq, IsVariant)]
#[non_exhaustive]
pub enum HeadersKind {
  /// A leading HEADERS section (request, final response, or an interim 1xx —
  /// disambiguated by `:status` at a higher layer). Repeats are allowed (interim
  /// responses) until the first DATA frame.
  Initial,
  /// A trailing HEADERS section after the body (trailers). At most one; nothing
  /// may follow it.
  Trailers,
}

/// Phase of the read (recv) side, tracking the RFC 9114 §4.1 sequence.
enum Phase {
  /// Awaiting the first HEADERS; repeated leading HEADERS (interim 1xx) keep the
  /// FSM here until the first DATA frame.
  Headers,
  /// At least one HEADERS section seen and at least one DATA frame seen (or the
  /// body has begun): DATA frames and an optional trailing HEADERS are allowed.
  Body,
  /// A trailing HEADERS (trailers) section was seen: the recv message is complete;
  /// nothing further may arrive on the recv half.
  Trailers,
}

/// The frame currently being consumed (after its header has been parsed).
enum Cur {
  /// At a frame boundary; the next bytes begin a frame header.
  None,
  /// Accumulating a HEADERS field section into the FSM-owned `hdr_acc[0..acc]`.
  /// `trailers` records whether the placement match classified this section as a
  /// trailing (post-DATA) HEADERS, so the completion arm reports the right
  /// [`HeadersKind`] and enters the right [`Phase`].
  Headers {
    remaining: u64,
    acc: usize,
    trailers: bool,
  },
  /// Streaming a DATA payload.
  Data { remaining: u64 },
  /// Discarding an unknown (GREASE / extension) frame's payload.
  Skip { remaining: u64 },
}

/// Parses inbound frames on a bidirectional request/response stream. Feed bytes
/// via [`handle`] and on the QUIC stream FIN call [`fin`].
///
/// The read side models the RFC 9114 §4.1 sequence
/// `HEADERS(interim 1xx)* HEADERS(final) DATA* HEADERS(trailers)?`: one or more
/// leading HEADERS sections (the CONNECT request / response, plus any interim 1xx
/// responses), then a sequence of DATA frames, then an optional trailing HEADERS
/// (trailers). Each decoded section is tagged with a [`HeadersKind`] by placement
/// (leading vs post-DATA); interim-vs-final is decided at a higher layer by
/// `:status`. The CONNECT tunnel is the specialization: one leading HEADERS, then
/// DATA. Unknown frame types are skipped (RFC 9114 §9); DATA before any HEADERS, a
/// frame after trailers, PUSH_PROMISE, or control-stream frames are protocol
/// violations.
///
/// A naturally-fragmented HEADERS frame is accumulated into FSM-owned storage
/// (`hdr_acc`), so the caller's `scratch` is needed only as transient
/// Huffman-decode space and may be a fresh buffer on every [`handle`] call.
///
/// [`handle`]: Stream::handle
/// [`fin`]: Stream::fin
pub struct Stream<'a, B = DefaultReqBuf<'a>> {
  phase: Phase,
  cur: Cur,
  /// Whether at least one HEADERS section has completed. A clean FIN before the
  /// first HEADERS is [`H3Error::RequestIncomplete`]; once any HEADERS completed,
  /// a frame-boundary FIN is a clean half-close even before any DATA (a body-less
  /// response, or the CONNECT 2xx with no payload yet).
  headers_seen: bool,
  /// Partial frame-header bytes (type varint + length varint, `<= 16`).
  hdr_buf: [u8; MAX_HEADER_LEN],
  hdr_len: usize,
  /// The in-progress HEADERS field section, accumulated across [`handle`] calls
  /// into FSM-owned storage so the caller's `scratch` need not be preserved
  /// between calls. The valid prefix is `hdr_acc[..acc]` where `acc` lives in the
  /// active [`Cur::Headers`]; bounded by the configured accumulator length. The
  /// alloc/std owned constructor uses [`HDR_CAP`]; borrowed storage uses the
  /// caller-provided slice length. Oversize is a graceful [`H3Error::FrameError`].
  ///
  /// [`handle`]: Stream::handle
  hdr_acc: B,
  _storage: PhantomData<&'a mut ()>,
}

/// Back-compat alias: the CONNECT tunnel's single request stream is a [`Stream`].
pub type RequestStream<'a, B = DefaultReqBuf<'a>> = Stream<'a, B>;

/// One parsed item, borrowed from the current [`Stream::handle`] call.
///
/// Valid only until the next [`Items::next`] call (lending iterator): a `Data`
/// chunk borrows the fed input and a `Headers` set borrows the FSM-owned field
/// accumulator plus the caller's Huffman scratch.
///
// `Unwrap`/`TryUnwrap` are not derived: `derive_more` cannot generate them for a
// struct (anonymous-record) variant, and nothing in the crate unwraps a
// `StreamItem` — callers match it directly. `IsVariant` supports struct variants.
#[derive(IsVariant)]
#[non_exhaustive]
pub enum StreamItem<'a> {
  /// A decoded HEADERS field section, tagged by placement (drain it before the
  /// next `next()`).
  Headers {
    /// The placement (initial vs trailers).
    kind: HeadersKind,
    /// The decoded field lines (borrows the field accumulator + scratch).
    headers: HeaderSet<'a>,
  },
  /// A chunk of DATA-frame payload (borrows the input).
  Data(&'a [u8]),
}

/// A lending iterator over the items produced by one [`Stream::handle`]
/// call. Drive it with [`Items::next`] until it returns `Ok(None)`.
pub struct Items<'a, 'buf, B = DefaultReqBuf<'buf>> {
  fsm: &'a mut Stream<'buf, B>,
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
  /// (already validated by [`Items::advance`]), tagged by placement; decode it with
  /// [`Items::decode_buffered_headers`].
  Headers { acc_end: usize, kind: HeadersKind },
  /// A DATA-frame payload chunk occupies `input[start..end]` (an empty `start == end`
  /// for a zero-length DATA frame). Re-slice it with [`Items::input`].
  Data { start: usize, end: usize },
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl Stream<'static> {
  /// A fresh read FSM expecting a HEADERS frame first.
  ///
  /// No `Default` is implemented: in the bare no-alloc tier the default storage
  /// is borrowed slices, so there is no honest feature-independent default read
  /// FSM value.
  #[inline]
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    Self::with_buffer(default_req_buf())
  }
}

impl<'buf, B> Stream<'buf, B> {
  /// A fresh read FSM backed by caller-provided persistent HEADERS storage.
  #[inline]
  pub fn with_buffer(hdr_acc: B) -> Self {
    Self {
      phase: Phase::Headers,
      cur: Cur::None,
      headers_seen: false,
      hdr_buf: [0u8; MAX_HEADER_LEN],
      hdr_len: 0,
      hdr_acc,
      _storage: PhantomData,
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
  pub fn handle<'a>(&'a mut self, bytes: &'a [u8], scratch: &'a mut [u8]) -> Items<'a, 'buf, B> {
    Items {
      fsm: self,
      input: bytes,
      pos: 0,
      scratch,
    }
  }

  /// Signal the QUIC stream FIN.
  ///
  /// - `Ok(())` — a clean half-close at a frame boundary once at least one HEADERS
  ///   section has completed (the recv half of the message is well-formed): after
  ///   the body has begun, after a trailing section, or after a leading HEADERS even
  ///   before any DATA (a body-less response, or the CONNECT 2xx before any DATA).
  ///   The peer ended its send side (RFC 9114 §7.1).
  /// - `Err(`[`H3Error::RequestIncomplete`]`)` — a frame-boundary FIN while still
  ///   awaiting the first HEADERS: the request / response field section never
  ///   arrived, so the message is incomplete (RFC 9114 §8.1).
  /// - `Err(`[`H3Error::FrameError`]`)` — a FIN mid-frame (a header or payload was
  ///   cut off), which is malformed framing.
  #[inline]
  pub fn fin(&self) -> Result<(), H3Error> {
    match (self.hdr_len, &self.cur) {
      (0, Cur::None) => match self.phase {
        // Body / Trailers (or Headers AFTER at least one section) = clean half-close.
        Phase::Body | Phase::Trailers => Ok(()),
        // Still in the leading-HEADERS phase: clean once one section completed, but a
        // FIN before the first HEADERS leaves the message incomplete (RFC 9114 §8.1).
        Phase::Headers if self.headers_seen => Ok(()),
        Phase::Headers => Err(H3Error::RequestIncomplete),
      },
      // Mid-frame: a header or payload was truncated by the FIN (malformed).
      _ => Err(H3Error::FrameError),
    }
  }

  /// Whether at least one HEADERS section has completed on the recv half.
  ///
  /// The connection uses this to enforce the CONNECT-tunnel "exactly one HEADERS
  /// exchange" rule: a HEADERS that arrives once a prior section already completed
  /// is a frame-placement violation at the tunnel layer (the general per-stream
  /// interim/trailers acceptance is wired in a later task). The recv FSM itself
  /// allows repeated leading HEADERS (interim 1xx) and a trailing section.
  #[inline]
  pub(crate) fn headers_seen(&self) -> bool {
    self.headers_seen
  }
}

impl<'a, B> Items<'a, '_, B> {
  /// The fed input slice (input lifetime), so a caller that drove the FSM with
  /// [`advance`](Self::advance) can re-derive a DATA chunk's bytes from the reported
  /// offsets independently of any `&mut self` borrow.
  pub(crate) fn input(&self) -> &'a [u8] {
    self.input
  }
}

impl<B> Items<'_, '_, B>
where
  B: AsRef<[u8]> + AsMut<[u8]>,
{
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
      Some(Advanced::Headers { acc_end, kind }) => Ok(Some(StreamItem::Headers {
        kind,
        headers: self.decode_buffered_headers(acc_end)?,
      })),
      Some(Advanced::Data { start, end }) => {
        let chunk = self.input.get(start..end).ok_or(H3Error::FrameError)?;
        Ok(Some(StreamItem::Data(chunk)))
      }
    }
  }
}

impl<B> Items<'_, '_, B>
where
  B: AsRef<[u8]>,
{
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
    let fs = self
      .fsm
      .hdr_acc
      .as_ref()
      .get(..acc_end)
      .ok_or(H3Error::FrameError)?;
    qpack::decode_field_section_into(fs, self.scratch).map_err(|e| e.to_h3())
  }
}

impl<B> Items<'_, '_, B>
where
  B: AsMut<[u8]>,
{
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
    let Stream {
      phase,
      cur,
      headers_seen,
      hdr_buf,
      hdr_len,
      hdr_acc,
      _storage,
    } = &mut **fsm;
    let hdr_acc = hdr_acc.as_mut();
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
                  // A leading HEADERS section: stays in Headers (interim 1xx repeat)
                  // until the first DATA frame.
                  (Phase::Headers, FrameKind::Headers) => {
                    *cur = Cur::Headers {
                      remaining: hdr.length(),
                      acc: 0,
                      trailers: false,
                    };
                  }
                  // First DATA after a leading HEADERS: the body has begun. (DATA stays
                  // legal in Body for subsequent frames.) DATA before ANY HEADERS is
                  // illegal — guarded by `headers_seen`, since a completed leading
                  // HEADERS keeps the phase in `Headers` until this transition.
                  (Phase::Headers, FrameKind::Data) if *headers_seen => {
                    *phase = Phase::Body;
                    *cur = Cur::Data {
                      remaining: hdr.length(),
                    };
                  }
                  (Phase::Body, FrameKind::Data) => {
                    *cur = Cur::Data {
                      remaining: hdr.length(),
                    };
                  }
                  // A HEADERS section after the body has begun: trailers (at most one;
                  // the Body→Trailers transition on completion guards a second one).
                  (Phase::Body, FrameKind::Headers) => {
                    *cur = Cur::Headers {
                      remaining: hdr.length(),
                      acc: 0,
                      trailers: true,
                    };
                  }
                  // DATA before any HEADERS (RFC 9114 §4.1), and nothing may follow
                  // trailers: both are frame-placement violations.
                  (Phase::Headers, FrameKind::Data)
                  | (Phase::Trailers, FrameKind::Headers | FrameKind::Data) => {
                    return Err(H3Error::FrameUnexpected);
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
                  // (RFC 9114 §7.2 frame placement): SETTINGS / CANCEL_PUSH / GOAWAY
                  // / MAX_PUSH_ID (control-stream frames); and the HTTP/2-reserved
                  // types (§7.2.8). All are H3_FRAME_UNEXPECTED.
                  (
                    _,
                    FrameKind::Settings
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
        Cur::Headers {
          remaining,
          acc,
          trailers,
        } => {
          let avail = input.len().saturating_sub(*pos);
          let take = usize::try_from(remaining).unwrap_or(usize::MAX).min(avail);
          let end = pos.checked_add(take).ok_or(H3Error::FrameError)?;
          let src = input.get(*pos..end).ok_or(H3Error::FrameError)?;
          let acc_end = acc.checked_add(take).ok_or(H3Error::FrameError)?;
          // Accumulate the field section into FSM-owned storage (not the caller's
          // scratch, which may be fresh each call). A field section larger than
          // the configured accumulator is a graceful frame error, never a panic;
          // `get_mut` rejects an out-of-range `acc_end` for us.
          let dst = hdr_acc.get_mut(acc..acc_end).ok_or(H3Error::FrameError)?;
          dst.copy_from_slice(src);
          *pos = end;
          let taken = u64::try_from(take).unwrap_or(u64::MAX);
          let remaining = remaining.saturating_sub(taken);
          if remaining == 0 {
            // Eager-validate the FIRST field section up front: the yielded `HeaderSet`
            // is a lazy lending iterator, so a QPACK error in a LATER field line (e.g. a
            // dynamic/post-base reference after a valid `:status`) would otherwise
            // surface only if the driver fully drains it — a driver that reads one field
            // and stops could act on a malformed section. So decode + drain a throwaway
            // pass here, propagating any error UNCONDITIONALLY. The caller re-decodes a
            // fresh pass over the same owned `hdr_acc` via `decode_buffered_headers`.
            //
            // A NON-first section (a repeated leading / interim or a trailing HEADERS,
            // i.e. `headers_seen` already set) is NOT eager-validated here: it is
            // reported by placement first, so the caller can apply its own placement
            // policy (the CONNECT tunnel rejects any second HEADERS as
            // `FrameUnexpected`) BEFORE a body decode — matching the legacy
            // reject-on-frame-kind ordering. Such a caller decodes/validates the section
            // itself (via `decode_buffered_headers` / the validator) only if it accepts
            // the placement.
            if !*headers_seen {
              let fs = hdr_acc.get(..acc_end).ok_or(H3Error::FrameError)?;
              let mut probe =
                qpack::decode_field_section_into(fs, scratch).map_err(|e| e.to_h3())?;
              while probe.next().map_err(|e| e.to_h3())?.is_some() {}
            }
            // Validation passed (or was deferred): only now commit the phase transition
            // and report the completed section's length + placement. The bytes stay in
            // `hdr_acc` until the next HEADERS frame overwrites them (an initial /
            // trailers pair never overlap in time), so the caller's fresh decode reads
            // them back. A trailing section ends the recv message (Phase::Trailers);
            // a leading section keeps us in Phase::Headers (a later interim 1xx
            // repeats), and the first DATA frame is what moves us to Phase::Body.
            *cur = Cur::None;
            *headers_seen = true;
            let kind = if trailers {
              *phase = Phase::Trailers;
              HeadersKind::Trailers
            } else {
              HeadersKind::Initial
            };
            return Ok(Some(Advanced::Headers { acc_end, kind }));
          }
          *cur = Cur::Headers {
            remaining,
            acc: acc_end,
            trailers,
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
