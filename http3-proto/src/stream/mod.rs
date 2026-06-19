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

/// Mints a fresh, correctly-sized HEADERS accumulator for a NEWLY-registered request
/// stream (the connection holds one [`Stream`] FSM per concurrent stream, each needing
/// its own accumulator). Replaces a bare `Default` bound on the multi-stream registration
/// paths, because `Vec::<u8>::default()` is EMPTY (zero capacity) — an empty accumulator
/// rejects the first HEADERS section with [`H3Error::FrameError`], so a second concurrent
/// request stream could never decode its HEADERS.
///
/// - Heap accumulators ([`Vec<u8>`], the default owned buffer) allocate [`HDR_CAP`]
///   bytes, so every concurrent stream gets a usable buffer.
/// - A borrowed `&mut [u8]` accumulator cannot allocate, so `fresh` yields an empty
///   borrow: a borrowed-buffer connection (any tier) therefore supports only the single
///   tunnel stream seeded at construction (`req_seed`); bare multi-stream buffering is a
///   later task.
///
/// Crate-internal (a `pub(crate)` bound on the otherwise-public registration methods, via
/// `#[allow(private_bounds)]`), so it adds no public API surface.
pub(crate) trait ReqBufAlloc {
  /// A fresh accumulator for one new request stream (heap: sized [`HDR_CAP`]; borrowed:
  /// an empty slice).
  fn fresh() -> Self;
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl ReqBufAlloc for std::vec::Vec<u8> {
  fn fresh() -> Self {
    default_req_buf()
  }
}

impl ReqBufAlloc for &mut [u8] {
  fn fresh() -> Self {
    // Borrowed storage cannot allocate; an empty slice is the only honest value. Only
    // ever reached for an ADDITIONAL stream — the single tunnel stream takes the
    // construction-time `req_seed` — which a borrowed-buffer connection does not open.
    &mut []
  }
}

/// Which placement a decoded HEADERS section occupies in the RFC 9114 §4.1
/// request-stream sequence `HEADERS(interim)* HEADERS(final) DATA* HEADERS(trailers)?`.
///
/// The recv FSM classifies by *placement* only: the leading HEADERS section(s) are
/// [`Initial`](Self::Initial) (the connection/validator decide interim-vs-final by
/// `:status`); a HEADERS section that arrives after the leading message completed — after
/// any DATA frame, OR after the connection signals leading-complete via the FSM's
/// `complete_leading` with no DATA in between (bodyless trailers) — is
/// [`Trailers`](Self::Trailers). The request/response direction is decided by the
/// connection from its role, not here.
#[derive(Debug, Clone, Copy, Eq, PartialEq, IsVariant)]
#[non_exhaustive]
pub enum HeadersKind {
  /// A leading HEADERS section (request, final response, or an interim 1xx —
  /// disambiguated by `:status` at a higher layer). Repeats are allowed (interim
  /// responses) until the connection signals the leading message complete (the FSM's
  /// `complete_leading`) or the first DATA frame.
  Initial,
  /// A trailing HEADERS section after the leading message (trailers), whether after the
  /// body or directly after a bodyless leading message. At most one; nothing may follow
  /// it.
  Trailers,
}

/// Phase of the read (recv) side, tracking the RFC 9114 §4.1 sequence.
enum Phase {
  /// Awaiting the leading message: repeated leading HEADERS (interim 1xx) keep the
  /// FSM here. The FSM cannot decode `:status`, so it does NOT itself know when the
  /// leading message is complete (the server's single request, or the client's FINAL
  /// non-interim response); the connection signals that via `complete_leading`, which
  /// moves to [`LeadingDone`](Self::LeadingDone). The first DATA frame seen while still
  /// here (the connection has not signalled yet — e.g. DATA after only interims) moves
  /// to [`Body`](Self::Body) directly; the connection's premature-DATA gate rejects DATA
  /// that arrives before the leading message completed.
  Headers,
  /// The leading message is complete (signalled by the connection via
  /// `complete_leading`) but no DATA frame has arrived yet. The post-leading, pre-DATA
  /// state: a DATA frame moves to [`Body`](Self::Body); a HEADERS section here is the
  /// trailing section (bodyless trailers — trailers that follow the leading message with
  /// NO intervening DATA, RFC 9114 §4.1-legal) and moves to [`Trailers`](Self::Trailers).
  /// A frame-boundary FIN here is a clean half-close (a bodyless final response / request
  /// then FIN).
  LeadingDone,
  /// At least one HEADERS section seen and at least one DATA frame seen (the body has
  /// begun): DATA frames and an optional trailing HEADERS are allowed.
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
  /// trailing HEADERS (after the body, or after the leading message completed with no
  /// DATA — bodyless trailers), so the completion arm reports the right [`HeadersKind`]
  /// and enters the right [`Phase`].
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
/// (leading vs trailing); interim-vs-final is decided at a higher layer by `:status`.
/// The CONNECT tunnel is the specialization: one leading HEADERS, then DATA. Unknown
/// frame types are skipped (RFC 9114 §9); DATA before any HEADERS, a frame after
/// trailers, PUSH_PROMISE, or control-stream frames are protocol violations.
///
/// The FSM cannot decode `:status`, so it does not by itself know which leading
/// HEADERS section COMPLETES the leading message (the single request, or the FINAL
/// non-interim response — not an interim 1xx). The connection signals that via the
/// crate-internal `complete_leading`, moving the FSM from its leading phase to the
/// post-leading, pre-DATA `LeadingDone` phase. The next HEADERS section after that
/// signal is the trailing section EVEN IF no DATA arrived in between (bodyless
/// trailers — a bodyless final response / request then trailers, which is
/// RFC 9114-legal). Without the signal a further HEADERS is another leading section
/// (an interim 1xx repeat).
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
  /// Whether at least one HEADERS section has completed. Gates the leading-phase
  /// premature-DATA transition (a DATA frame is legal only once a leading HEADERS
  /// section exists, RFC 9114 §4.1) and the connection's "exactly one HEADERS
  /// exchange" tunnel rule via [`headers_seen`](Self::headers_seen). It does NOT by
  /// itself decide a clean FIN: an interim 1xx sets this yet leaves the leading
  /// message incomplete, so [`fin`](Self::fin) keys on the PHASE (the leading message
  /// completed) instead.
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
  /// - `Ok(())` — a clean half-close at a frame boundary once the LEADING MESSAGE has
  ///   COMPLETED (the recv half of the message is well-formed): after the body has
  ///   begun, after a trailing section, or after the leading message completed even
  ///   before any DATA (a body-less final response / request, or the CONNECT 2xx
  ///   before any DATA). The peer ended its send side (RFC 9114 §7.1).
  /// - `Err(`[`H3Error::RequestIncomplete`]`)` — a frame-boundary FIN while still in
  ///   the leading-HEADERS phase, i.e. the leading message never completed: either no
  ///   HEADERS at all, or ONLY interim 1xx leading sections (the final response /
  ///   request never arrived). The message is incomplete (RFC 9114 §8.1). Completion
  ///   is the FSM leaving `Phase::Headers` — which the connection signals via
  ///   `complete_leading` ONLY on the final response / request, NEVER on an interim —
  ///   not merely `headers_seen` (an interim 1xx completes a section but NOT the
  ///   message, so a `103`-then-FIN must NOT read as a clean half-close).
  /// - `Err(`[`H3Error::FrameError`]`)` — a FIN mid-frame (a header or payload was
  ///   cut off), which is malformed framing.
  #[inline]
  pub fn fin(&self) -> Result<(), H3Error> {
    match (self.hdr_len, &self.cur) {
      (0, Cur::None) => match self.phase {
        // The leading message completed (the FSM left `Phase::Headers`): a bodyless
        // final response / request (LeadingDone), the body began (Body), or trailers
        // arrived (Trailers) — all clean half-closes.
        Phase::LeadingDone | Phase::Body | Phase::Trailers => Ok(()),
        // Still in the leading-HEADERS phase: the leading message never completed — no
        // HEADERS, or only interim 1xx sections (`complete_leading` fires only on the
        // final response / request, so an interim leaves the FSM here). Either way the
        // message is incomplete (RFC 9114 §8.1); `headers_seen` (set by an interim too)
        // is NOT sufficient.
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

  /// Signal that the leading message is complete: the connection classified the
  /// just-completed leading HEADERS section as the SERVER's single request or the
  /// CLIENT's FINAL (non-interim) response — NOT an interim 1xx. The FSM cannot decode
  /// `:status`, so this is how it learns the leading message is over and the NEXT
  /// HEADERS section is the trailing section EVEN WITH no intervening DATA (bodyless
  /// trailers, RFC 9114 §4.1). Moves `Phase::Headers → Phase::LeadingDone` (the
  /// post-leading, pre-DATA state); from there a DATA frame begins the body and a
  /// HEADERS section is trailers.
  ///
  /// The connection MUST NOT call this for an interim 1xx leading section (several may
  /// precede the final response): leaving the FSM in `Phase::Headers` keeps a subsequent
  /// interim / the final classified as another leading section.
  ///
  /// Idempotent and frame-boundary-only in practice: the connection signals it right
  /// after a leading section completes, when `cur` is `Cur::None`. It is a no-op in any
  /// phase but `Headers` (a DATA frame may already have moved the FSM to `Body`, e.g.
  /// `[final response][DATA][late signal]` — though the connection signals before the
  /// DATA is processed; and after `LeadingDone` / `Trailers` there is nothing to do), so
  /// it can never reopen a trailing or body phase.
  #[inline]
  pub(crate) fn complete_leading(&mut self) {
    if matches!(self.phase, Phase::Headers) {
      self.phase = Phase::LeadingDone;
    }
  }
}

impl<'a, B> Items<'a, '_, B> {
  /// The fed input slice (input lifetime), so a caller that drove the FSM with
  /// [`advance`](Self::advance) can re-derive a DATA chunk's bytes from the reported
  /// offsets independently of any `&mut self` borrow.
  pub(crate) fn input(&self) -> &'a [u8] {
    self.input
  }

  /// Signal the driven FSM that the leading message is complete (see
  /// [`Stream::complete_leading`]). The connection calls this through the [`Items`] it
  /// already holds (the FSM is borrowed by it), after classifying a completed leading
  /// section as the request / FINAL response, so the next HEADERS section is the trailing
  /// section even with no intervening DATA. A no-op outside the FSM's leading phase.
  pub(crate) fn complete_leading(&mut self) {
    self.fsm.complete_leading();
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
                  // until the connection signals the leading message complete
                  // (`complete_leading` → LeadingDone) or the first DATA frame begins the
                  // body. The connection re-tags each completed leading section by
                  // `:status`, so the FSM keeps reporting `Initial` here.
                  (Phase::Headers, FrameKind::Headers) => {
                    *cur = Cur::Headers {
                      remaining: hdr.length(),
                      acc: 0,
                      trailers: false,
                    };
                  }
                  // First DATA while still in the leading phase (the connection has not
                  // signalled the leading message complete — e.g. DATA arriving after only
                  // interim 1xx responses): the body has begun. DATA before ANY HEADERS is
                  // illegal — guarded by `headers_seen`, since a completed leading HEADERS
                  // keeps the phase in `Headers` until this transition. The connection's
                  // premature-DATA gate separately rejects DATA before the leading message
                  // completed (it never established), so this only ever yields DATA the
                  // gate then judges.
                  (Phase::Headers, FrameKind::Data) if *headers_seen => {
                    *phase = Phase::Body;
                    *cur = Cur::Data {
                      remaining: hdr.length(),
                    };
                  }
                  // First DATA after the leading message completed (`complete_leading`):
                  // the body has begun.
                  (Phase::LeadingDone, FrameKind::Data) => {
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
                  // A HEADERS section after the leading message completed but before any
                  // DATA: BODYLESS trailers (RFC 9114 §4.1 — trailers may follow with no
                  // body). At most one; the LeadingDone→Trailers transition on completion
                  // guards a second one.
                  (Phase::LeadingDone, FrameKind::Headers)
                  // A HEADERS section after the body has begun: trailers (at most one;
                  // the Body→Trailers transition on completion guards a second one).
                  | (Phase::Body, FrameKind::Headers) => {
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
            // them back. A trailing section ends the recv message (Phase::Trailers); a
            // leading section keeps us in Phase::Headers (a later interim 1xx repeats)
            // until the connection signals the leading message complete
            // (`complete_leading` → LeadingDone) or the first DATA frame moves us to
            // Phase::Body.
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
