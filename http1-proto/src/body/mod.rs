//! The inbound message body: the octets that follow a head, handed out of
//! whatever slices the transport happened to deliver.
//!
//! `crate::validate` answers WHERE a body ends — the RFC 9112 §6.3 list, in
//! order of precedence — and `BodyDecoder` is where that answer becomes bytes:
//! which octets of a given read belong to this body, and which are already the
//! next message's. Recipients disagreeing about that boundary is exactly the
//! §11.2 request-smuggling primitive, so the decoder claims a byte only when
//! the framing it was built from says the body still owns it.
//!
//! Sans-I/O throughout. `feed` takes a slice, reports how much of it the body
//! claimed, and returns at most one item; it never buffers and never copies,
//! since `BodyItem::Data` borrows the caller's slice. The read loop, the
//! buffer, and the decision to call again all stay with the caller.
//!
//! Finishing is deliberately TWO-PHASE. `is_finished` turns true as soon as the
//! body's last octet has been consumed, while the `Finished` item is emitted by
//! the call after that. The two answer different questions — "may I stop
//! feeding this body?" against "has the item stream ended?" — and a caller that
//! needs the first before the item arrives (to hand the remaining bytes to the
//! next message, or to stop reading the transport) gets it without having to
//! pump a decoder it has no more input for.

use crate::{error::H1Error, validate::BodyFraming};

// `pub(crate)` only so `crate::__no_panic_internals` can reach the chunk-size
// leaf: nothing else outside this module names anything in here — a decoder is
// driven through `BodyDecoder` — and the module's items stay `pub(crate)` or
// private, so this widens where a crate-internal name can be reached, not what
// the crate publishes.
pub(crate) mod chunked;
// `pub(crate)` for the same reason the head's codecs are: the connection state
// machine, which lives outside this module, is what frames an outbound body.
pub(crate) mod encode;

/// Bytes of `chunk-ext` (RFC 9112 §7.1.1) a single chunk-size line may carry.
///
/// No recipient is required to understand any extension, so the whole budget is
/// spent on bytes the decoder parses and then discards; it exists to bound that
/// parse, not to leave room for a feature. It sits beside the framing decision
/// rather than inside the chunked sub-machine because it is one of this core's
/// declared limits, where the head's `MAX_HEAD_BYTES` and `MAX_HEADERS` sit.
///
/// PLACEMENT ONLY: those two are published and this one is deliberately not,
/// because it caps a SINGLE element so that need-more-input stays bounded, and
/// what a reader of a chunked body has to compute with is the cumulative,
/// per-body budget `Limits::max_chunk_framing_bytes`, which is public.
pub(crate) const MAX_CHUNK_EXT_BYTES: usize = 256;

/// RFC 9112 §6.3 item 6: when the connection closes before the indicated number
/// of octets has arrived, the recipient MUST consider the message incomplete.
const CLOSED_MID_BODY: &str = "connection closed before the Content-Length body ended";

/// RFC 9112 §7.1: a chunked body ends at the empty line that closes its trailer
/// section, so a close before that line leaves framing bytes the sender still
/// owed — the same incompleteness §6.3 item 6 makes a MUST for a counted body.
const CLOSED_MID_CHUNKED: &str = "connection closed before the chunked body ended";

/// Which of this end's two per-body budgets refused a message.
///
/// THE DISCRIMINANT, and it exists because two budgets share one refusal path:
/// the routine that takes the connection through a refusal has to read the
/// limit that refused and name it to the driver, and those are two different
/// numbers measuring two different things. Carried on the fault rather than
/// re-derived at the refusal, because only the site that ran the comparison
/// knows which one it ran.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Budget {
  /// The ceiling on the PAYLOAD octets one body may deliver — the content RFC
  /// 9110 §8.6 declines to bound, bounded here as local policy.
  Payload,
  /// The budget for the RFC 9112 §7.1 chunk-size lines one body may spend.
  /// Framing rather than content, and unbounded by any payload ceiling: a size
  /// line can announce one octet and spend hundreds.
  ChunkFraming,
}

/// What stopped a body decoder.
///
/// Two kinds, and the split is the point: a `Violation` is the wire breaking an
/// RFC 9110 / RFC 9112 rule and latches the connection; `TooLarge` is this
/// end's own limit refusing a message the peer framed correctly, and it does
/// not. RFC 9110 §8.6 declines to bound content — "there is no predefined limit
/// to the length of content" — so a ceiling is local policy, and nothing about
/// a message that breached one was malformed.
// `Clone` rather than `Copy`, because `H1Error` is `Clone`: the payload is what
// decides, and widening the public error type's derives is not this change's.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum BodyFault {
  /// The wire broke a rule. Terminal for the connection.
  Violation(H1Error),
  /// This end's limit refused a conformant message, and WHICH limit it was.
  TooLarge(Budget),
}

impl From<H1Error> for BodyFault {
  #[inline]
  fn from(error: H1Error) -> Self {
    Self::Violation(error)
  }
}

/// Whether a count the peer has DECLARED already exceeds the headroom left.
///
/// One comparison, and the ONE spelling of the early-exit test, so the sites
/// that apply it cannot come to phrase it several ways. Strict: a declaration
/// that fits the headroom exactly is permitted, since RFC 9110 §15.5.14's
/// refusal is for content larger than what this end will process, not for
/// content that meets the ceiling.
pub(crate) const fn overruns(declared: u64, headroom: u64) -> bool {
  declared > headroom
}

/// Adds `n` to `received` and refuses if the total passes `limit`. `None` IS
/// the refusal.
///
/// `checked_add` and one comparison. The check is what makes the bound hold,
/// and `clippy::arithmetic_side_effects` is what forbids the bare `+` that
/// would wrap a huge total into a small one the comparison then admitted.
pub(crate) const fn charge(received: u64, n: u64, limit: u64) -> Option<u64> {
  match received.checked_add(n) {
    Some(total) if total <= limit => Some(total),
    _ => None,
  }
}

/// A slice length in the budget's unit, saturating in the REFUSING direction.
///
/// A length no `u64` could hold answers `u64::MAX` rather than wrapping into an
/// under-count: the conversion may only ever make a refusal earlier, never
/// later, which is what keeps it out of the bound's soundness argument.
pub(crate) fn widen(n: usize) -> u64 {
  u64::try_from(n).unwrap_or(u64::MAX)
}

/// What is left of a limit after what has already been received.
///
/// The form a declared-count check needs: [`overruns`] compares a declaration
/// against the headroom rather than against the ceiling, so a body part-way
/// through is measured on what remains of its allowance. `received <= limit`
/// holds by [`charge`], so the saturation is defensive.
// Two callers, both sites that measure a declaration against a PARTLY-consumed
// allowance: `BodyDecoder::narrow`, and the step that hands the chunked coding
// what is left before it reads a size line. The four leaves are one set: they
// are the only spellings of this arithmetic in the crate, and the link proof
// covers them together.
pub(crate) const fn headroom(received: u64, limit: u64) -> u64 {
  limit.saturating_sub(received)
}

/// One item of a decoded body.
///
/// Every payload borrows the slice it was decoded from: an item is a view into
/// the caller's buffer, valid for as long as that buffer is.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum BodyItem<'a> {
  /// Payload octets, in the order they arrived, borrowed from the fed slice.
  /// Never empty: a call with nothing to hand over reports need-more-input
  /// instead of an empty payload.
  ///
  /// Content codings are NOT applied: `Content-Encoding` (RFC 9110 §8.4) is a
  /// property of the representation, above this core. For a chunked body a
  /// transfer coding beneath the chunked one may also survive into these bytes
  /// (see [`BodyFraming::Chunked`]).
  Data(&'a [u8]),
  /// The chunked body's last chunk has been read and the trailer section
  /// begins (RFC 9112 §7.1.2). Chunked bodies only.
  TrailersStart,
  /// One validated trailer field line.
  ///
  /// The name is a `token` (RFC 9110 §5.6.2), which is ASCII by construction
  /// and so is safe to surface as `&str`; the value is grammar-checked bytes,
  /// because a field value may carry `obs-text` that is not UTF-8 (§5.5).
  TrailerField {
    /// The field name, a validated token.
    name: &'a str,
    /// The field value, OWS-trimmed and grammar-checked.
    value: &'a [u8],
  },
  /// The body is over: no further octet of the input belongs to it.
  ///
  /// Emitted exactly once. For [`BodyFraming::ReadToClose`] it can only come
  /// from [`BodyDecoder::eof`], since nothing in the byte stream delimits such
  /// a body.
  Finished,
}

/// Incremental decoder for ONE message body, built from that message's RFC 9112
/// §6.3 framing decision.
///
/// One decoder per message: the framing is fixed at construction and the states
/// run forward only, so a decoder that has emitted `Finished` never decodes
/// again. That is what keeps two messages on a persistent connection from
/// sharing a countdown.
///
/// The chunked coding (RFC 9112 §7.1) has states of its own, which live in the
/// `chunked` sub-machine; the shell keeps the framing decision, the boundary
/// rule, and the two-phase finish that every framing here shares.
// Equality under `cfg(test)` alone. A mode-edge differential compares a whole
// `Connection` against the one its native path built, and a decoder reaches that
// comparison inside `RecvState::Body`; no product path asks whether two decoders
// are the same, so the impl is the tests' and stays there.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct BodyDecoder {
  state: State,
  /// Payload octets handed over as [`BodyItem::Data`] for THIS body.
  ///
  /// One writer — [`admit`](Self::admit) — which is what makes the bound a
  /// property of the type rather than of the paths through it.
  received: u64,
  /// The ceiling in force for THIS message, in payload octets.
  ///
  /// Written once, at construction, from the connection's own ceiling. RFC 9110
  /// §8.6 states there is "no predefined limit to the length of content", so a
  /// ceiling is local policy and never a rule of the protocol.
  limit: u64,
  /// The budget in force for THIS message, in RFC 9112 §7.1 chunk-size-line
  /// octets.
  ///
  /// Written once, at construction, and never narrowed: [`narrow`](Self::narrow)
  /// is a payload operation, so this budget belongs to the connection for the
  /// whole of every body it carries. It reaches the sub-machine that spends it
  /// BY VALUE on each call, which is what keeps the tally downstream of the
  /// ceiling rather than beside it.
  framing_limit: u64,
}

impl BodyDecoder {
  /// Builds the decoder for a body framed as `framing` says, bounded at `limit`
  /// payload octets and `framing_limit` chunk-framing octets.
  ///
  /// TWO budgets, because one of them cannot bound the other. `limit` bounds
  /// the content; `framing_limit` bounds the RFC 9112 §7.1 chunk-size lines,
  /// which are framing the peer chooses the length of and which a payload
  /// ceiling never sees — a 272-octet size line may announce a single octet.
  /// Only the chunked coding can spend the second one.
  ///
  /// A zero `Content-Length` and [`BodyFraming::None`] start in the same place:
  /// a body of no octets is complete before a byte is read, and neither is ever
  /// refused — RFC 9112 §6.3 items 1 and 7 make them messages with no content,
  /// so there is nothing a content limit could be about.
  ///
  /// RFC 9112 §6.3 item 6's early exit rides in the same expression as the
  /// framing decision: a `Content-Length` past `limit` produces a decoder
  /// already REFUSED, before the receive state is written and before an octet
  /// is read. Every octet such a body would deliver was declared by that
  /// number, so the declaration is a strictly earlier evaluation of what the
  /// cumulative charge would conclude — it can only make the refusal sooner,
  /// never lift the bound.
  pub(crate) const fn new(framing: BodyFraming, limit: u64, framing_limit: u64) -> Self {
    let state = match framing {
      BodyFraming::None | BodyFraming::ContentLength(0) => State::Complete,
      BodyFraming::ContentLength(expected) if overruns(expected, limit) => State::Refused,
      BodyFraming::ContentLength(expected) => State::Counting(expected),
      BodyFraming::Chunked => State::Chunked(chunked::Decoder::new()),
      BodyFraming::ReadToClose => State::ReadToClose,
    };
    Self {
      state,
      received: 0,
      limit,
      framing_limit,
    }
  }

  /// Payload octets this body has handed over.
  // Read by `Connection::body_progress`, which is what carries it to a driver;
  // the decoder's own tests read it to pin that a refusal charges nothing.
  pub(crate) const fn received(&self) -> u64 {
    self.received
  }

  /// The ceiling in force for this message.
  ///
  /// Read by the refusal routine, off the decoder still sitting in the receive
  /// state, so the refusal it builds names the limit that actually refused.
  pub(crate) const fn limit(&self) -> u64 {
    self.limit
  }

  /// The chunk-framing budget in force for this message.
  ///
  /// The twin of [`limit`](Self::limit), read by the same routine on the other
  /// branch of the same question: a refusal names the budget that refused it,
  /// and the two are told apart by the fault's own discriminant rather than by
  /// the reader guessing.
  pub(crate) const fn framing_limit(&self) -> u64 {
    self.framing_limit
  }

  /// Whether this body has already been refused, by whichever writer of
  /// `State::Refused` got there — the state is the fact, and the variant's own
  /// doc is where those writers are enumerated.
  ///
  /// True from CONSTRUCTION for a declaration past the ceiling, which is what
  /// lets the head that framed it decline to surface RFC 9110 §10.1.1's
  /// expectation: content this end has already refused must not be invited.
  /// True from [`narrow`](Self::narrow) for a per-exchange ceiling the message
  /// cannot meet, which the same call resolves.
  pub(crate) const fn is_refused(&self) -> bool {
    matches!(self.state, State::Refused)
  }

  /// Payload octets the framing has COMMITTED to and not yet handed over, or
  /// `None` where it has committed to nothing.
  ///
  /// What "committed" covers depends on the framing, and reading it is how the
  /// RFC 9112 §6.3 framings are told apart from the outside:
  ///
  /// - item 6's `Content-Length` states the whole body in the head, so this is
  ///   the remainder of the BODY from the moment that head was read;
  /// - §7.1's chunked coding states one chunk at a time, so this is the
  ///   remainder of THAT CHUNK and must never be read as a body total;
  /// - item 8's close-delimited framing states nothing, ever, and a body already
  ///   through — `Complete`, `Done` — or refused has nothing outstanding.
  ///
  /// ONE exhaustive match over the states, delegating to ONE exhaustive match
  /// over the chunked stages, so a framing or a stage added later is a compile
  /// error here rather than a case that silently answers "nothing declared".
  pub(crate) const fn announced(&self) -> Option<u64> {
    match self.state {
      State::Counting(remaining) => Some(remaining),
      State::Chunked(decoder) => decoder.announced(),
      State::Complete | State::ReadToClose | State::Refused | State::Done => None,
    }
  }

  /// Whether more transport octets could move this body forward.
  ///
  /// The question the READ half of the connection's readiness split actually
  /// asks, answered by the decoder rather than by the receive state that holds
  /// it — "a body is being received" and "this body needs another octet" are
  /// different facts, and reading the first for the second tells a driver to
  /// wait for input that will never change anything:
  ///
  /// - A body still owed octets — a `Content-Length` counting down (RFC 9112
  ///   §6.3 item 6), a chunked body mid-coding (§7.1), one delimited by the
  ///   close (§6.3 item 8) — wants input, and item 8's wants it until the
  ///   transport ends.
  /// - A body whose octets have ALL arrived does not. `Complete` still owes its
  ///   `Finished` item, but that item comes from the next call, not from the
  ///   wire; `Done` owes nothing at all.
  /// - A REFUSED body does not, and this is the sharp case: every further octet
  ///   is answered with the same refusal, so a driver told to read one is told
  ///   to wait for bytes that cannot help — and against a peer that is itself
  ///   waiting (RFC 9110 §10.1.1's `Expect: 100-continue`) both ends wait until
  ///   a timeout breaks the tie.
  ///
  /// EXHAUSTIVE, so a state added later has to say which of the two it is.
  pub(crate) const fn wants_input(&self) -> bool {
    match self.state {
      State::Counting(_) | State::Chunked(_) | State::ReadToClose => true,
      State::Complete | State::Done | State::Refused => false,
    }
  }

  /// Narrows this body's ceiling to `max` payload octets, answering whether the
  /// ceiling now in force can still be met.
  ///
  /// NARROWING ONLY: the ceiling becomes `min(limit, max)`, so a `max` above the
  /// one in force is a no-op. `min` is idempotent and commutative, so the answer
  /// does not depend on how often this is called or in what order — the
  /// operation has no increasing direction to be pointed in, which is what makes
  /// a ceiling impossible to LIFT rather than merely refused a lift.
  ///
  /// COMMITTED BEFORE THE CHECK, and that order is observable: the routine that
  /// builds the refusal reads [`limit`](Self::limit) off this decoder, so a
  /// check run first would report the ceiling this call replaced rather than the
  /// one that refused.
  ///
  /// `false` is unsatisfiable. RFC 9110 §15.5.14 refuses content "larger than
  /// the server is willing or able to process", and two counts of that are
  /// decidable before the rest of the body has arrived:
  ///
  /// - more octets have ALREADY been handed over than the new ceiling allows —
  ///   the bound is on the message's TOTAL, not on what is left; or
  /// - the framing has DECLARED more than the headroom left: a `Content-Length`
  ///   remainder (RFC 9112 §6.3 item 6) or the remainder of the chunk in flight
  ///   (§7.1), each read through [`announced`](Self::announced).
  ///
  /// Both counts are spelled with the leaves the cumulative charge itself uses,
  /// so a narrowing can only ever reach a conclusion [`feed`](Self::feed) would
  /// reach later: it is a strictly earlier evaluation of the same comparison and
  /// never a second rule.
  ///
  /// EVERY state answers, and the check above runs for all but ONE of them.
  ///
  /// `Refused` is the exemption, and the whole of it: the refusal already stands
  /// and a refusal is not undone, so there is no second answer to give.
  ///
  /// `Complete` and `Done` are MEASURED like any other. A body whose octets have
  /// all arrived has still DELIVERED them, and neither the countdown reaching
  /// zero nor the later call that hands over `Finished` gives them back — so a
  /// ceiling narrowed below that total was not met, and answering `true` would
  /// tell a route its bound had been applied to content that had already crossed
  /// it. What decides is what the body delivered, never how far a caller has got
  /// through pumping the items that report it: the two states differ only in
  /// whether `Finished` has been taken, and a rule that turned on that would
  /// make the answer a fact about the pump rather than about the message.
  ///
  /// The message with NO content stays `true`, and by the check rather than by
  /// exemption. RFC 9112 §6.3 items 1 and 7 put it in `Complete` before a byte
  /// is read, so `received` is zero, so neither count can fire — at any ceiling,
  /// nought included. A caller that narrows after every head is still never told
  /// that a conformant GET, HEAD response or 304 was an error, which is the
  /// reason that exemption was written for; the reason holds only while nothing
  /// has been delivered, and this is what says so.
  ///
  /// THE SECOND WRITER of `State::Refused`, the first being
  /// [`new`](Self::new)'s declaration gate. Both write it for one fact — this
  /// end's own ceiling cannot be met by the message being received — and both
  /// leave the identical state, so [`is_refused`](Self::is_refused) stays one
  /// question with one answer whichever of them wrote it.
  pub(crate) fn narrow(&mut self, max: u64) -> bool {
    if max < self.limit {
      self.limit = max;
    }
    // EXHAUSTIVE rather than a `matches!`, so a state added later has to say
    // whether this end's ceiling still applies to it instead of inheriting an
    // answer — and it decides only THAT, because the check itself is stated once
    // below. A copy of it per arm is what comes to be spelled two ways.
    match self.state {
      State::Refused => return true,
      State::Complete
      | State::Done
      | State::Counting(_)
      | State::Chunked(_)
      | State::ReadToClose => {}
    }
    // Nothing declared is nothing to measure: for a body already through, and
    // for a framing that has committed to no octets, only the already-delivered
    // count can refuse.
    let declared = self.announced().unwrap_or(0);
    if overruns(self.received, self.limit)
      || overruns(declared, headroom(self.received, self.limit))
    {
      self.state = State::Refused;
      return false;
    }
    true
  }

  /// Feeds the next slice of received bytes, returning how many of its leading
  /// octets the body claimed and at most one item.
  ///
  /// The consumed count is a prefix length: the caller keeps everything past it
  /// for the next message on the connection. Call again with the unconsumed
  /// remainder until the call reports `(0, None)`, which means no progress is
  /// possible from these bytes — either more input is needed
  /// ([`is_finished`](Self::is_finished) false) or the body has already ended
  /// and its `Finished` item has been taken (true). One call yields at most one
  /// item, so a fed slice that spans a boundary needs a second call.
  ///
  /// Never claims a byte past the body's end: on the call that finds the
  /// framing already satisfied, the answer is `(0, Some(Finished))`, so the
  /// bytes offered stay with the caller in full.
  ///
  /// THE BOUND. Every [`BodyItem::Data`] this decoder will ever produce leaves
  /// through here, whatever framing produced it, so a framing added later is
  /// bounded by construction rather than by its author remembering to charge.
  pub(crate) fn feed<'a>(
    &mut self,
    input: &'a [u8],
  ) -> Result<(usize, Option<BodyItem<'a>>), BodyFault> {
    // `State` is `Copy`, so this is the whole of the rollback: a refusal writes
    // it back and the decoder is where the caller's cursor still is.
    let before = self.state;
    let (claimed, produced) = self.step(input)?;
    self.admit(before, claimed, produced)
  }

  /// The ONE writer of `received`, and the only place a [`BodyItem::Data`] is
  /// let out of this type.
  ///
  /// INVARIANT — commit or nothing. A refusal restores `before`, so the decoder
  /// is never left advanced past octets the caller's cursor did not move over.
  /// Not a nicety: the pump returns the refusal BEFORE it moves its consumed
  /// count, so a decoder that kept its advance would be silently ahead of the
  /// driver's buffer and any later path built on it would skip octets — RFC
  /// 9112 §11.2, one change removed.
  ///
  /// WHICH FRAMINGS CAN STILL REACH THE REFUSAL is a shorter list than it was,
  /// and saying so is part of the invariant rather than a caveat to it. A
  /// framing that DECLARES before it delivers is refused at the declaration —
  /// a `Content-Length` at construction, a chunk-size line at the announcement
  /// gate — and each declaration bounds the very sum this charges, so an
  /// announced octet can no longer arrive over the ceiling. A ceiling that
  /// SHRINKS mid-body does not reopen it, and that is the third leg rather than
  /// a detail: [`narrow`](Self::narrow) re-measures whatever the framing still
  /// has outstanding — [`announced`](Self::announced), which is a
  /// `Content-Length` remainder or the chunk in flight — against the headroom
  /// the new ceiling leaves, and refuses in place, so `received + announced <=
  /// limit` survives the narrowing instead of being a fact the declaration gate
  /// established under a ceiling that no longer holds. What is left is RFC
  /// 9112 §6.3 item 8, which declares nothing ever and whose producer advances
  /// no state, so the restore it takes writes back what was already there. The
  /// line stands for the framing added LATER that hands over octets it never
  /// announced: the charge is the bound, the early exits only make it sooner,
  /// and this is what keeps the decoder in step on the call where the charge is
  /// the one that answers.
  ///
  /// `step`'s existing behaviour of KEEPING the advance on a wire violation is
  /// untouched, and deliberately so: a decoder that rejected a chunk does not
  /// quietly rewind to before it. A violation ends the connection; a refusal
  /// leaves it answerable, which is the whole difference.
  ///
  /// The match over `produced` is EXHAUSTIVE rather than an `if let`, so a
  /// [`BodyItem`] variant added later that carries octets is a compile error
  /// here — at the charge point — instead of a payload that quietly bypasses
  /// the bound.
  fn admit<'a>(
    &mut self,
    before: State,
    claimed: usize,
    produced: Option<BodyItem<'a>>,
  ) -> Result<(usize, Option<BodyItem<'a>>), BodyFault> {
    match produced {
      Some(BodyItem::Data(data)) => {
        let Some(received) = charge(self.received, widen(data.len()), self.limit) else {
          self.state = before;
          return Err(BodyFault::TooLarge(Budget::Payload));
        };
        self.received = received;
      }
      // Framing rather than content, in every case: RFC 9112 §7.1.2's trailer
      // section is a field section (RFC 9110 §6.5) and carries the head's own
      // caps, the two markers carry no octets at all, and `None` is progress
      // through framing or need-more-input.
      None | Some(BodyItem::TrailersStart | BodyItem::TrailerField { .. } | BodyItem::Finished) => {
      }
    }
    Ok((claimed, produced))
  }

  /// One decoding step, below the bound: the framing's own rule, with no charge.
  ///
  /// Private, and it must stay so — [`feed`](Self::feed) is what wraps it in
  /// the admission that charges, and a caller reaching this directly would be
  /// the bypass the single charge point exists to make impossible.
  fn step<'a>(&mut self, input: &'a [u8]) -> Result<(usize, Option<BodyItem<'a>>), BodyFault> {
    match self.state {
      // Phase two of the finish: the octets ran out on an earlier call, and
      // this one hands over the item without touching the input.
      State::Complete => {
        self.state = State::Done;
        Ok((0, Some(BodyItem::Finished)))
      }
      State::Counting(remaining) => Ok(self.count_down(remaining, input)),
      // RFC 9112 §6.3 item 8: nothing in the stream delimits this body, so
      // every byte offered is body and only `eof` ends it.
      State::ReadToClose if !input.is_empty() => Ok((input.len(), Some(BodyItem::Data(input)))),
      // Nothing to hand over, and — for `Done` — nothing left that could be.
      State::ReadToClose | State::Done => Ok((0, None)),
      // Already refused, and it stays refused: the same answer to the same
      // bytes however often they are offered, consuming nothing. Nothing is
      // parsed past a refusal, so no octet behind it can be mistaken for the
      // next message (RFC 9112 §11.2). `Payload` names it because both writers
      // of this state are payload gates — the variant's own doc is the list.
      State::Refused => Err(BodyFault::TooLarge(Budget::Payload)),
      // RFC 9112 §7.1: the chunked coding delimits itself, so the sub-machine
      // owns the boundary and this arm only carries its answer out.
      //
      // BOTH budgets reach it by value: what is left of the payload allowance,
      // which a size line's announcement is measured against, and the whole
      // chunk-framing budget, against which the sub-machine's own tally is. The
      // ceiling goes down and the tally stays down, so no step of the coding
      // can write either of this decoder's numbers.
      State::Chunked(mut decoder) => {
        let decoded = decoder.feed(
          headroom(self.received, self.limit),
          self.framing_limit,
          input,
        );
        // A chunked body that reached the end of its trailer section rejoins
        // the shell's two-phase finish, so its `Finished` comes from
        // `State::Complete` like every other framing's. The state is written
        // back even when the sub-machine reported a violation, so a decoder
        // that rejected a chunk does not quietly rewind to before it.
        //
        // And a REFUSAL needs no rollback, which is a property of where the
        // gates sit rather than of this write: both of them answer before the
        // sub-machine has written a stage or a tally, so the copy stored here
        // is the one the call was handed. `feed`'s own restore never sees it —
        // an `Err` leaves `step` before the admission runs.
        self.state = if decoder.is_complete() {
          State::Complete
        } else {
          State::Chunked(decoder)
        };
        decoded
      }
    }
  }

  /// Signals that the transport reached end of input.
  ///
  /// Three outcomes, and which one applies is a property of the framing rather
  /// than of the close:
  ///
  /// - A close-delimited body (RFC 9112 §6.3 item 8) is FINISHED by the close;
  ///   it is the only delimiter such a body has.
  /// - A body whose octets have all arrived is likewise finished, whether it
  ///   was a `Content-Length` that counted down to zero or a message that never
  ///   had a body (items 6-7). Item 6's "incomplete" is about octets that never
  ///   came, and here every one of them did — so the close ends a COMPLETE
  ///   message, and the `Finished` item still owed is handed over now instead
  ///   of by a `feed` the caller has no bytes for.
  /// - A body still owed octets is item 6's MUST: the message is incomplete,
  ///   which is an error and not a short body. A `Content-Length` still
  ///   counting down is the literal case; a chunked body (§7.1) that has not
  ///   reached the empty line closing its trailer section is the same fault,
  ///   since the octets it still owes are its own framing.
  ///
  /// A decoder that already emitted `Finished` answers `Ok(None)`: the close
  /// happened after a complete message, which is how a connection normally
  /// ends. Idempotent, so a caller may report the same EOF twice.
  ///
  /// Routed through the same admission [`feed`](Self::feed) uses, so a framing
  /// added later whose EOF arm hands over a final payload is bounded by the
  /// same line rather than by a second one. Nothing charges here today: the
  /// only item this path produces is `Finished`.
  pub(crate) fn eof(&mut self) -> Result<Option<BodyItem<'static>>, BodyFault> {
    let before = self.state;
    let produced = self.eof_step()?;
    let (_, produced) = self.admit(before, 0, produced)?;
    Ok(produced)
  }

  /// The EOF's own rule, below the bound. [`eof`](Self::eof) is what admits it.
  fn eof_step(&mut self) -> Result<Option<BodyItem<'static>>, BodyFault> {
    match self.state {
      State::ReadToClose | State::Complete => {
        self.state = State::Done;
        Ok(Some(BodyItem::Finished))
      }
      State::Done => Ok(None),
      State::Counting(_) => Err(BodyFault::Violation(H1Error::Framing(CLOSED_MID_BODY))),
      // A complete chunked body has already become `Complete` above, so
      // reaching this arm means the last chunk or its trailer section never
      // arrived.
      State::Chunked(_) => Err(BodyFault::Violation(H1Error::Framing(CLOSED_MID_CHUNKED))),
      // A refused body is refused whichever way it is asked. Compiler-forced by
      // the exhaustive match, and DEFENSIVE: the pump feeds a refused decoder
      // before any stop can route an EOF here, so `feed` answers first.
      State::Refused => Err(BodyFault::TooLarge(Budget::Payload)),
    }
  }

  /// Whether every octet of the body has been consumed.
  ///
  /// The BYTES half of the two-phase finish, and it turns true one call before
  /// the `Finished` item is emitted: a `Content-Length` that has just counted
  /// down to zero is finished here while its item is still owed. A caller
  /// deciding whether to keep reading the transport for this message wants this
  /// answer; a caller draining the item stream wants `Finished`.
  ///
  /// Always false for a close-delimited body until [`eof`](Self::eof) is
  /// signalled — no count can prove such a body over.
  // No consumer inside the crate, and the outbound path — the expected one — is
  // deliberately not it: RFC 9112 §9.3.2 gates keep-alive re-arm on both
  // directions being through in whichever order they finish, so a server may
  // answer a request whose body it has not read out and no send call has reason
  // to ask this. The receive path drives the ITEM half instead (it pumps until
  // `Finished` comes out, by which point a finished body has left this state).
  // What is left wanting the BYTES half is a driver-facing accessor — "do more
  // transport bytes belong to THIS message?" — which lands with the task that
  // needs one. `Connection::body_progress` is NOT it: it reports where a body
  // stands, and `announced` is `None` both once a body is through and between
  // two chunks of one that is not, so nothing there answers this question.
  #[cfg_attr(not(test), allow(dead_code))]
  pub(crate) const fn is_finished(&self) -> bool {
    matches!(self.state, State::Complete | State::Done)
  }

  /// One read against a `Content-Length` countdown (RFC 9112 §6.3 item 6).
  fn count_down<'a>(&mut self, remaining: u64, input: &'a [u8]) -> (usize, Option<BodyItem<'a>>) {
    let Some((claimed, left)) = claim(remaining, input) else {
      return (0, None);
    };
    self.state = match left {
      0 => State::Complete,
      left => State::Counting(left),
    };
    (claimed.len(), Some(BodyItem::Data(claimed)))
  }
}

/// Claims the leading octets of `input` that a countdown of `remaining` still
/// owes, returning them and what is left owed. `None` when there is nothing to
/// claim, which is need-more-input rather than a body that ended: nothing is
/// consumed and no state moves, so the next read decides.
///
/// Claiming `min(remaining, input.len())` is the whole of the boundary rule — a
/// read that overshoots hands back only the part the count covers, and the rest
/// stays with the caller — and this core runs that rule twice: over RFC 9112
/// §6.3 item 6's `Content-Length` and over §7.1's `chunk-data`. One
/// implementation, so the two cannot drift about where a body's octets end.
fn claim(remaining: u64, input: &[u8]) -> Option<(&[u8], u64)> {
  // The countdown is a u64 and slice math is usize. A `remaining` past
  // `usize::MAX` cannot be exhausted by any one read of an addressable slice,
  // so it saturates into the `min` rather than being converted into a length
  // this platform could not represent.
  let take = usize::try_from(remaining)
    .unwrap_or(usize::MAX)
    .min(input.len());
  // An empty read — and, defensively, a `take` the clamp above somehow left out
  // of range — claims nothing.
  let claimed = input.get(..take).filter(|c| !c.is_empty())?;
  // `take <= remaining` by the clamp above, so the conversion holds and the
  // subtraction cannot underflow. The fallback covers only a `take` too large
  // for a u64 — impossible under that clamp, and it would mean the read covered
  // the whole remainder anyway.
  Some((
    claimed,
    remaining.saturating_sub(u64::try_from(take).unwrap_or(remaining)),
  ))
}

/// Where a decoder stands in the body it was built for.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum State {
  /// Every octet of the body has been consumed and the `Finished` item is still
  /// owed. Three ways in: [`BodyFraming::None`] (a message with no body at
  /// all), a zero `Content-Length`, and a countdown that reached zero.
  Complete,
  /// RFC 9112 §6.3 item 6: this many octets of the body are still owed. Never
  /// zero — a countdown that reaches zero becomes `Complete`.
  Counting(u64),
  /// RFC 9112 §7.1: chunked, with the sub-machine that holds where inside the
  /// coding this body stands. It becomes `Complete` on the call that consumes
  /// the empty line closing the trailer section.
  Chunked(chunked::Decoder),
  /// RFC 9112 §6.3 item 8: the body runs until the transport closes.
  ReadToClose,
  /// This end's own limit refused the message. Terminal, and NOT a violation:
  /// the peer framed a conformant message and this end declined to read it, so
  /// the connection is closed rather than failed (RFC 9110 §15.5.14's second
  /// MAY — "otherwise, the server MAY close the connection").
  ///
  /// TWO writers, and they are the whole list. [`BodyDecoder::new`], for a
  /// `Content-Length` the head already declared past the ceiling; and
  /// [`BodyDecoder::narrow`], for a per-exchange ceiling the message in flight
  /// cannot meet. Both write it for the same fact and leave the identical state,
  /// so [`BodyDecoder::is_refused`] reads one answer whichever wrote it.
  ///
  /// A breach found MID-body does not land here — the charge restores the state
  /// it rolled back and the pump replaces the whole receive state in the same
  /// step, so there is no decoder left to mark.
  Refused,
  /// `Finished` has been emitted. The decoder is idle: it claims nothing
  /// further and produces no second item.
  Done,
}

#[cfg(test)]
mod tests;
