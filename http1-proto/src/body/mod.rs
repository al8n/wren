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
/// declared limits, next to `MAX_HEAD_BYTES` and `MAX_HEADERS`.
pub(crate) const MAX_CHUNK_EXT_BYTES: usize = 256;

/// RFC 9112 §6.3 item 6: when the connection closes before the indicated number
/// of octets has arrived, the recipient MUST consider the message incomplete.
const CLOSED_MID_BODY: &str = "connection closed before the Content-Length body ended";

/// RFC 9112 §7.1: a chunked body ends at the empty line that closes its trailer
/// section, so a close before that line leaves framing bytes the sender still
/// owed — the same incompleteness §6.3 item 6 makes a MUST for a counted body.
const CLOSED_MID_CHUNKED: &str = "connection closed before the chunked body ended";

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
}

impl BodyDecoder {
  /// Builds the decoder for a body framed as `framing` says.
  ///
  /// A zero `Content-Length` and [`BodyFraming::None`] start in the same place:
  /// a body of no octets is complete before a byte is read.
  pub(crate) const fn new(framing: BodyFraming) -> Self {
    let state = match framing {
      BodyFraming::None | BodyFraming::ContentLength(0) => State::Complete,
      BodyFraming::ContentLength(expected) => State::Counting(expected),
      BodyFraming::Chunked => State::Chunked(chunked::Decoder::new()),
      BodyFraming::ReadToClose => State::ReadToClose,
    };
    Self { state }
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
  pub(crate) fn feed<'a>(
    &mut self,
    input: &'a [u8],
  ) -> Result<(usize, Option<BodyItem<'a>>), H1Error> {
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
      // RFC 9112 §7.1: the chunked coding delimits itself, so the sub-machine
      // owns the boundary and this arm only carries its answer out.
      State::Chunked(mut decoder) => {
        let decoded = decoder.feed(input);
        // A chunked body that reached the end of its trailer section rejoins
        // the shell's two-phase finish, so its `Finished` comes from
        // `State::Complete` like every other framing's. The state is written
        // back even when the sub-machine reported a violation, so a decoder
        // that rejected a chunk does not quietly rewind to before it.
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
  pub(crate) fn eof(&mut self) -> Result<Option<BodyItem<'static>>, H1Error> {
    match self.state {
      State::ReadToClose | State::Complete => {
        self.state = State::Done;
        Ok(Some(BodyItem::Finished))
      }
      State::Done => Ok(None),
      State::Counting(_) => Err(H1Error::Framing(CLOSED_MID_BODY)),
      // A complete chunked body has already become `Complete` above, so
      // reaching this arm means the last chunk or its trailer section never
      // arrived.
      State::Chunked(_) => Err(H1Error::Framing(CLOSED_MID_CHUNKED)),
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
  // needs one.
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
  /// `Finished` has been emitted. The decoder is idle: it claims nothing
  /// further and produces no second item.
  Done,
}

#[cfg(test)]
mod tests;
