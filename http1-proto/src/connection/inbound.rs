//! The General-mode inbound pump: the state machine behind [`Items::next`].
//!
//! One rule shapes every step here, and it is what makes dropping the iterator
//! safe: a `next` call either produces an item and COMMITS the bytes that item
//! covers, or it produces nothing and commits nothing. Nothing observable moves
//! in between. A head is parsed and its exchange phase advanced in the same call
//! that hands the head over; a body chunk's octets are counted as the chunk goes
//! out. So a driver that pulls a head, drops the iterator, and re-offers the
//! unconsumed tail is answered with the body — not with the head again, and not
//! with the body's first octets missing.
//!
//! Three kinds of byte are exempt, and every one of them is a byte no item will
//! ever carry:
//!
//! - The internal scan watermark over a head that has not terminated. That is
//!   need-more bookkeeping rather than consumption — the head region's `consumed`
//!   stays at zero until the whole head is present.
//! - The chunked coding's own framing lines (RFC 9112 §7.1). The decoder has
//!   already moved past them internally, so leaving them unconsumed would put the
//!   decoder and the driver's buffer at different offsets — which is the
//!   recipient disagreement §11.2 is about, self-inflicted.
//! - The stray CRLFs a client discards when it has no outstanding request
//!   (§9.2). No head is coming that they could be folded into, so they are
//!   dropped where they are found; a server's leading empty lines are NOT in this
//!   list, because there the head they precede is what carries them out. Only
//!   whole PAIRS are discarded: a trailing lone CR is undecided (§2.2) and stays
//!   in the driver's buffer until the byte after it says what it was.
//!
//! The pump is ONE non-generic function rather than one per role. The role
//! reaches it as a `bool` off the type-state, so a client and a server share
//! every rule they actually share — head delimitation, body decoding, the
//! keep-alive gate — and differ only where the RFCs differ.

use crate::{
  body::{BodyDecoder, BodyFault, BodyItem, Budget},
  connection::{
    CLOSED_BEFORE_RESPONSE, CLOSED_MID_HEAD, CONNECT, Exchange, FAILED, Lifecycle, RecvState,
    SWITCHING_PROTOCOLS, SendState, abandon_send, head_digest, latch, mint, refuse, settle,
    signal_close, tunnel::names_a_protocol,
  },
  error::{Error, H1Error, Refusal},
  event::{ExchangeId, Item, Items, StartLine},
  head::{
    HeadView, Version, find_head_end, malformed, parse_request_line, parse_status_line,
    scan::MAX_LEADING_EMPTY_LINES, scan_head, skip_leading_empty_lines,
  },
  validate::{BodyFraming, HeadDirectives, validate_request, validate_response},
};

/// RFC 9110 §9.3.6: a 2xx to CONNECT turns the connection into a tunnel, so the
/// message framing this core applies stops applying after the head. A [`General`]
/// connection has nothing to become, so it refuses the request where it arrives
/// rather than accepting one it could not honour.
///
/// [`General`]: crate::connection::General
const CONNECT_NEEDS_TUNNEL: &str = "CONNECT requires a Tunnel-mode connection";

/// RFC 9110 §15.2.2: a 101 switches the connection to another protocol, and
/// everything after that head is that protocol's, not HTTP's. Refused in General
/// mode for the same reason CONNECT is.
const SWITCHING_NEEDS_TUNNEL: &str = "101 requires a Tunnel-mode connection";

/// RFC 9112 §9.2: a client that receives data on a connection with no outstanding
/// request "MUST NOT consider [it] a response" — message delimitation is
/// ambiguous from there on, so nothing about the connection can be trusted.
const RESPONSE_WITHOUT_REQUEST: &str = "response bytes with no outstanding request";

/// RFC 9110 §9.3.2, and the one method RFC 9112 §6.3 item 1 makes the response
/// to bodiless whatever that response's own fields say.
const HEAD: &str = "HEAD";

/// What one step of the pump produced.
///
/// The three answers the loop needs, and they are not the same as
/// `Option`: "nothing this time, ask me again" is progress that produced no item
/// (a chunk-size line read, a re-arm taken), while "nothing more" ends the call.
enum Step<'a> {
  /// An item, with the bytes it covers already committed.
  Yield(Item<'a>),
  /// Internal progress; the loop runs another step.
  Again,
  /// No further item can come out of these bytes.
  Stop,
}

/// The next inbound item, or `Ok(None)` when the fed bytes yield no more.
///
/// The body of [`Items::next`], which is where its contract is documented.
pub(crate) fn pump<'a>(it: &mut Items<'a, '_>) -> Result<Option<Item<'a>>, Error> {
  loop {
    match *it.lifecycle {
      // The violation was handed back by the call that found it; a connection
      // cannot report the same fault twice, and everything after it is misuse.
      Lifecycle::Failed => return Err(Error::InvalidState(FAILED)),
      // RFC 9112 §9.6: once the `close` connection option has been stated and
      // the exchange that was in flight is through, no further inbound byte is
      // processed at all: "The server MUST NOT process any further requests
      // received on that connection".
      Lifecycle::Draining => return Ok(None),
      // A closed READ side is not that rule and does not appear here at all: it
      // is a separate fact (`read_closed`), and §9.6 is explicit that it carries
      // no such meaning — "a TCP connection that is half-closed by the client
      // does not delimit a request message, nor does it imply that the client is
      // no longer interested in a response", and, generally, "transport signals
      // cannot be relied upon to signal edge cases". The bytes already in the
      // driver's buffer are requests §9.3.2 still owes ordered responses to, so
      // the pump goes on serving them; where the transport fact DOES matter is
      // `no_more_input`, when the offer runs out.
      Lifecycle::Open | Lifecycle::Closing => {}
    }

    // Exhaustive so a variant added to `RecvState` is named here rather than
    // falling into a catch-all: no arm binds a field, so this reads the
    // discriminant of `*it.recv` without holding a borrow across the call —
    // each step still takes `&mut Items` of its own.
    let step = match *it.recv {
      RecvState::AwaitingRearm => rearm(it),
      RecvState::Body { .. } => body(it)?,
      RecvState::Idle => head(it)?,
    };

    match step {
      Step::Yield(item) => return Ok(Some(item)),
      Step::Again => {}
      Step::Stop => return no_more_input(it),
    }
  }
}

/// Resolves a step that stopped for want of input, once it is known whether more
/// input can ever come.
///
/// **Every conclusion that depends on the absence of future bytes is drawn here,
/// and only here.** That is the point of the function. `handle_eof` observes one
/// thing — the transport's read side ended — and the connection cannot see the
/// DRIVER's buffer, so "the message was truncated" is not a fact `handle_eof`
/// holds: the octets that would complete it may be sitting unoffered, and
/// `Items` explicitly lets a driver stop pulling mid-stream. Here the buffer HAS
/// been re-offered and has run out, so the same question is finally answerable.
///
/// On a LIVE connection a stop means "these bytes are exhausted, ask again after
/// a read" and nothing is decided. With `read_closed` set the offer in hand is
/// everything the peer will ever say, and WHICH ending it is depends on where
/// the receive side had got to:
///
/// - **A reply is owed** ([`RecvState::AwaitingRearm`]). Not an ending at all:
///   the driver has something to write, `is_awaiting_send` says so, and the
///   requests buffered behind it are still to be served once it does.
/// - **Mid-head** (`watermark` past zero). RFC 9112 §2.1 makes a message begin
///   with a complete head, and this one never got one.
/// - **A client with an exchange outstanding and no final head.** RFC 9112 §9.5
///   with RFC 9110 §15.2: the request went out and no final response came back,
///   interim heads not counting as one.
/// - **Mid-body**, which the decoder decides: §6.3 item 6's MUST-incomplete for
///   a counted body, §7.1's for a chunked one whose trailer section never closed
///   — or, for §6.3 item 8's close-delimited body, that the close COMPLETED it,
///   which yields the exchange's last item rather than a fault.
/// - **At a message boundary with nothing left.** Every message the peer sent has
///   been handled, so the connection drains.
///
/// The three faults keep the constants, citations and latching they had when
/// `handle_eof` drew them; what changed is only WHERE they are provable.
fn no_more_input<'a>(it: &mut Items<'a, '_>) -> Result<Option<Item<'a>>, Error> {
  // The live case, and by far the common one: more bytes may still arrive, so a
  // stop decides nothing.
  if !*it.read_closed {
    return Ok(None);
  }
  // The reply to the message just read is still owed.
  if matches!(*it.recv, RecvState::AwaitingRearm) {
    return Ok(None);
  }
  // RFC 9112 §2.1: a head that never terminated is a message the peer stopped
  // mid-sentence. Checked before the client rule below, because it is the
  // sharper diagnosis — the peer did start a response.
  if matches!(*it.recv, RecvState::Idle) && *it.watermark > 0 {
    return Err(truncated(it, H1Error::Framing(CLOSED_MID_HEAD)));
  }
  // RFC 9112 §9.5 with RFC 9110 §15.2: a client between messages with an
  // exchange still outstanding sent a request and got no FINAL response — not
  // one byte of one, or interim heads only, which §15.2 makes informational and
  // never the answer.
  if it.is_client && matches!(*it.recv, RecvState::Idle) && it.exchange.is_some() {
    return Err(truncated(it, H1Error::Framing(CLOSED_BEFORE_RESPONSE)));
  }
  // §6.3 item 6 and §7.1, asked of the decoder that owns the rule rather than
  // re-derived here.
  let ended = match it.recv {
    RecvState::Body { decoder, .. } => decoder.eof(),
    RecvState::Idle | RecvState::AwaitingRearm => Ok(None),
  };
  match ended {
    Err(BodyFault::Violation(error)) => return Err(truncated(it, error)),
    // Compiler-forced by the fault split, and DEFENSIVE: `handle_eof` never
    // touches the decoder, and the pump feeds a `RecvState::Body` decoder
    // unconditionally — empty offer included — so a refused decoder answers in
    // `feed` before any stop can route here. Written because the alternative is
    // a `_` arm that would swallow a refusal if that ever stopped being true.
    Err(BodyFault::TooLarge(budget)) => {
      // Defensive twice over: a refusal names the exchange it refused, and a
      // receive state holding a decoder always has one. With no id there is
      // nothing to report, so the offer simply yields no further item.
      let Some(exchange) = *it.exchange else {
        return Ok(None);
      };
      return Err(Error::Refused(refused(it, exchange.id, budget)));
    }
    // RFC 9112 §6.3 item 8: the close IS the delimiter, so a body read to it is
    // COMPLETE here — and here is the only place that can be said. "This body is
    // all the octets that came" is a conclusion about the absence of further
    // bytes like any other, so it waits for the offer that runs out; drawing it
    // at the EOF instead would complete the message over octets still sitting
    // unoffered in the driver's buffer, and silently lose them.
    Ok(Some(_)) => {
      *it.recv = RecvState::AwaitingRearm;
      *it.tail_unresolved |= it.is_client;
      let completed = it.exchange.map(|exchange| exchange.id);
      settle(
        it.recv,
        it.exchange,
        it.watermark,
        it.send,
        it.lifecycle,
        it.pending_cr,
      );
      if let Some(exchange) = completed {
        return Ok(Some(Item::ExchangeComplete { exchange }));
      }
      return Ok(None);
    }
    Ok(None) => {}
  }
  // Nothing being received, nothing in flight, nothing part-scanned: the offer
  // is exhausted at a message boundary and the connection is genuinely over.
  if matches!(*it.recv, RecvState::Idle) && it.exchange.is_none() {
    *it.lifecycle = Lifecycle::Draining;
  }
  Ok(None)
}

/// Latches a message the peer abandoned when its write side ended.
///
/// `answerable = false`, matching `handle_eof`'s treatment of the same fault:
/// what was truncated is a message this end never fully received, so there is
/// nothing it could answer ABOUT. The write side may well still be open — that
/// is what a half-close means — but a 400 describing a request nobody finished
/// sending answers no message, and the single error response a failed server
/// still owes exists for requests that arrived whole and could not be framed.
fn truncated(it: &mut Items<'_, '_>, error: H1Error) -> Error {
  latch(
    it.send,
    it.lifecycle,
    *it.read_closed,
    it.is_client,
    false,
    it.exchange.is_some(),
    error,
  )
}

/// The inbound side of an exchange is through: re-arm if the outbound side is
/// too, and otherwise hold everything after it (RFC 9112 §9.3.2).
///
/// The gate is re-evaluated on entry rather than assumed. Both completion points
/// take the re-arm the moment they happen — the `Finished` item below, and the
/// send side's own completion — so this normally finds it unchanged and stops;
/// asking again costs nothing and keeps the pump self-correcting rather than
/// dependent on having been told.
fn rearm<'a>(it: &mut Items<'a, '_>) -> Step<'a> {
  settle(
    it.recv,
    it.exchange,
    it.watermark,
    it.send,
    it.lifecycle,
    it.pending_cr,
  );
  if matches!(*it.recv, RecvState::AwaitingRearm) {
    // Still owed: the next message's bytes stay the driver's until the reply is
    // written. Reading more cannot change that, which is what
    // `is_awaiting_send` tells the driver.
    Step::Stop
  } else {
    Step::Again
  }
}

/// Reads the head of the next message, or reports that it has not all arrived.
fn head<'a>(it: &mut Items<'a, '_>) -> Result<Step<'a>, Error> {
  let start = *it.consumed;
  let rest = it.input().get(start..).unwrap_or_default();
  if it.is_client {
    client_head(it, rest, start)
  } else {
    server_head(it, rest, start)
  }
}

/// Server: the RFC 9112 §3 request-line and the fields under it.
fn server_head<'a>(
  it: &mut Items<'a, '_>,
  rest: &'a [u8],
  start: usize,
) -> Result<Step<'a>, Error> {
  // RFC 9112 §2.2: a server "SHOULD ignore at least one empty line (CRLF)
  // received prior to the request-line" — an older client's trailing CRLF. The
  // allowance is bounded, and the bytes are NOT consumed here: they go out with
  // the head they precede, so an unterminated head leaves the whole prefix in
  // the driver's buffer and the bound stays cumulative over it rather than
  // resetting once per offer.
  let skip = match skip_leading_empty_lines(rest) {
    Ok(skip) => skip,
    Err(error) => return Err(fail(it, error)),
  };
  let region = rest.get(skip..).unwrap_or_default();

  let end = match find_head_end(region, *it.watermark) {
    Ok(Some(end)) => end,
    Ok(None) => {
      // Need-more: nothing is consumed, and the scan resumes here next time.
      // `max` rather than assignment: the watermark is progress through ONE
      // head, so it may never go backwards — and an offer SHORTER than the last
      // one (an empty re-offer is the easy way to produce one) would otherwise
      // clobber it and make the next scan restart from a byte already looked at,
      // which is the linearity property this field exists for.
      *it.watermark = (*it.watermark).max(region.len());
      return Ok(Step::Stop);
    }
    Err(error) => return Err(fail(it, error)),
  };

  let block = region.get(..end).unwrap_or_default();
  let parsed = match parse_request_head(block) {
    Ok(parsed) => parsed,
    Err(error) => return Err(fail(it, error)),
  };

  // RFC 9110 §7.8's two halves; `&&` short-circuits, so a request without
  // `Upgrade` never runs the protocol-list scan — nor the digest below it.
  let upgrade_offered = parsed.directives.has_upgrade && names_a_protocol(&parsed.view);

  // Commit: the id is minted, the bytes are counted, and the exchange enters its
  // body — all in the call that hands the head over.
  let id = mint(it.next_exchange);
  *it.exchange = Some(Exchange {
    id,
    // RFC 9112 §6.3 item 1, recorded for the RESPONSE this end will send: a
    // response to HEAD is bodiless whatever its own fields say, and the response
    // is not something that fact can be read from.
    method_head: parsed.method_head,
    // CONNECT never gets this far in General mode — `parse_request_head` refuses
    // it — so item 2 has no exchange here to apply to.
    connect: false,
    // RFC 9112 §6.1, recorded for the same reason: what this end may send in the
    // RESPONSE depends on the version the REQUEST stated, and the response is
    // not the message that stated it.
    version: parsed.version,
    // RFC 9110 §10.1.1's ask, kept durably because the answer to it can outlive
    // `RecvState::Body`'s own copy — see `Exchange::expect_unanswered`.
    expect_unanswered: parsed.directives.expect_continue,
    upgrade_offered,
    // WHICH request offered it, for the connection this exchange may later
    // transition into: `into_tunnel` carries the digest across, and the upgrade
    // layer refuses a head that does not match it. Hashed only behind the offer
    // — an ordinary request pays nothing for a mode transition it will never
    // take, and a dead value is what `Exchange::head_digest` is written to hold.
    head_digest: if upgrade_offered {
      head_digest(parsed.view.block())
    } else {
      0
    },
    // Nothing has been read of this message's body yet, so nothing can have
    // been refused. Set by `connection::refuse` and never cleared.
    body_refused: false,
  });
  *it.send = SendState::Owed;
  Ok(Step::Yield(commit_head(
    it,
    start.saturating_add(skip).saturating_add(end),
    id,
    parsed,
  )))
}

/// Client: the RFC 9112 §4 status-line and the fields under it, read against the
/// request it answers.
fn client_head<'a>(
  it: &mut Items<'a, '_>,
  rest: &'a [u8],
  start: usize,
) -> Result<Step<'a>, Error> {
  let Some(exchange) = *it.exchange else {
    return idle_client_bytes(it, rest, start);
  };

  // No leading-empty-line leniency here: RFC 9112 §2.2 scopes that to "a server
  // that is expecting to receive and parse a request-line", and §9.2 scopes the
  // client's CRLF discard to a connection with nothing outstanding. With a
  // request in flight, the next byte is the status-line's first.
  let end = match find_head_end(rest, *it.watermark) {
    Ok(Some(end)) => end,
    Ok(None) => {
      // `max` for the same reason as the server path above: a watermark belongs
      // to one head and only ever moves forward within it.
      *it.watermark = (*it.watermark).max(rest.len());
      return Ok(Step::Stop);
    }
    Err(error) => return Err(fail(it, error)),
  };

  let block = rest.get(..end).unwrap_or_default();
  let parsed = match parse_response_head(block, exchange) {
    Ok(parsed) => parsed,
    Err(error) => return Err(fail(it, error)),
  };

  // RFC 9110 §15.2.1: an interim response is a head the driver sees without the
  // exchange moving — the final head is still to come, on this same id — so
  // `commit_head` leaves the receive state exactly where it was.
  Ok(Step::Yield(commit_head(
    it,
    start.saturating_add(end),
    exchange.id,
    parsed,
  )))
}

/// RFC 9112 §9.2: bytes arriving at a client that has no outstanding request.
///
/// Only CRLFs are tolerable — the same stray empty lines §2.2 lets a server
/// ignore, discarded here rather than folded into a head, since there is no head
/// coming that they could belong to. Anything else is not a response to anything,
/// and a client that guessed otherwise would be attributing a message to a
/// request that was never made.
///
/// A trailing lone CR is neither. §2.2 makes a CR a terminator only once its LF
/// has arrived, and a CR at the end of a read proves nothing — its LF may be in
/// the next segment — so condemning it here would make the SAME bytes fatal or
/// harmless purely by where the transport split them, which is the one thing this
/// crate's line rule exists to prevent. It is left unconsumed and reported as
/// need-more; the next offer re-presents it, and the byte behind it decides:
/// `\r\n` is one more discarded pair, anything else is the §9.2 error at last
/// provable. At most one CR is ever pending, and the pairs before it are already
/// gone, so nothing accumulates.
///
/// The BOUND on those pairs is cumulative, and has to be. A server's leading
/// empty lines are counted afresh per offer only because they are never
/// consumed — they go out with the head they precede, so the region they sit in
/// keeps growing and `skip_leading_empty_lines`'s own limit stays a limit on the
/// whole prefix. These are DISCARDED, so a per-offer count would reset with
/// every read and leave a peer that dribbles one CRLF at a time an unbounded
/// keep-alive channel on a connection with nothing outstanding — the very thing
/// the bound exists to deny. The connection therefore carries the tally
/// (`idle_crlfs`), and `open_request` clears it: a new request is a new idle
/// period.
fn idle_client_bytes<'a>(
  it: &mut Items<'a, '_>,
  rest: &'a [u8],
  start: usize,
) -> Result<Step<'a>, Error> {
  let skip = match skip_leading_empty_lines(rest) {
    Ok(skip) => skip,
    Err(error) => return Err(fail(it, error)),
  };
  // `skip` counts whole CRLF pairs by construction, so halving it is the line
  // count and the division is exact. `checked_div` rather than `/`: the crate's
  // lint wall denies bare integer division, and a codec may not carry a panic
  // path a reader has to reason about — the saturations below are the same
  // discipline, and a count that saturated would only refuse EARLIER.
  let discarded = u8::try_from(skip.checked_div(2).unwrap_or(0)).unwrap_or(u8::MAX);
  *it.idle_crlfs = it.idle_crlfs.saturating_add(discarded);
  if usize::from(*it.idle_crlfs) > MAX_LEADING_EMPTY_LINES {
    return Err(fail(
      it,
      malformed(start, "too many empty lines before the start-line"),
    ));
  }
  *it.consumed = start.saturating_add(skip);
  let residue = rest.get(skip..).unwrap_or_default();
  // Undecided: hold it, and say the connection wants the deciding byte.
  *it.pending_cr = matches!(residue, [b'\r']);
  if residue.is_empty() {
    // The offer is read back to its end at the idle boundary, so whatever a
    // completed exchange left behind has now been accounted for: §9.2's barrier
    // lifts and the next request may be opened. This is the ONLY clean way out
    // of it — the other is the diagnosis below, which latches.
    *it.tail_unresolved = false;
    return Ok(Step::Stop);
  }
  if *it.pending_cr {
    return Ok(Step::Stop);
  }
  Err(fail(it, H1Error::Framing(RESPONSE_WITHOUT_REQUEST)))
}

/// Everything a head decides, computed over the borrowed block alone.
///
/// Separated from the connection on purpose: parsing touches no state, so a
/// violation can be latched by the caller in one place instead of at each of the
/// half-dozen points that can find one.
struct ParsedHead<'a> {
  /// The head itself, read lazily out of the block.
  view: HeadView<'a>,
  /// Where the body this head framed ends (RFC 9112 §6.3).
  framing: BodyFraming,
  /// The connection-delta directives the head carried.
  directives: HeadDirectives,
  /// Whether this is an interim (1xx) response. Always false on a request.
  interim: bool,
  /// Whether the REQUEST used HEAD, so that RFC 9112 §6.3 item 1 makes the
  /// response to it bodiless. Always false on a response, which is not the
  /// message the method belongs to.
  method_head: bool,
  /// The start line itself, for the driver.
  ///
  /// Kept from the parse the framing decision needed rather than re-derived:
  /// the codecs run exactly once per head, here, and what they produced travels
  /// out on the item.
  line: StartLine<'a>,
  /// The version this head's start line stated (RFC 9112 §2.3).
  ///
  /// Read by the server path alone, which records it on the exchange it opens:
  /// §6.1 makes a `Transfer-Encoding` in the RESPONSE conditional on the
  /// REQUEST's version. A response's own version answers no question this core
  /// asks — validation already applied §6.1's receive-side half to it — so it is
  /// carried and ignored rather than being a second field.
  version: Version,
}

/// Scans, parses, and validates a REQUEST head.
fn parse_request_head(block: &[u8]) -> Result<ParsedHead<'_>, H1Error> {
  let view = scan_head(block)?;
  let request_line = parse_request_line(view.start_line_bytes())?;
  let (framing, directives) = validate_request(&request_line, &view)?;
  // Refused after validation, so that a CONNECT which is ALSO malformed is
  // diagnosed by what is wrong with it. A well-formed one is refused for the
  // mode it needs and does not have; the fault is on the wire rather than in the
  // caller's API use, so it is an `H1Error` (400 — the request cannot be framed
  // here) rather than a caller-side `InvalidState`.
  if request_line.method == CONNECT {
    return Err(H1Error::Framing(CONNECT_NEEDS_TUNNEL));
  }
  Ok(ParsedHead {
    view,
    framing,
    directives,
    interim: false,
    // RFC 9110 §9.1 makes a method a case-SENSITIVE token, so this is exact
    // equality — `head` is not HEAD.
    method_head: request_line.method == HEAD,
    version: request_line.version,
    line: StartLine::Request(request_line),
  })
}

/// Scans, parses, and validates a RESPONSE head against the request it answers.
fn parse_response_head(block: &[u8], exchange: Exchange) -> Result<ParsedHead<'_>, H1Error> {
  let view = scan_head(block)?;
  let status_line = parse_status_line(view.start_line_bytes())?;
  // Refused ahead of validation, which is written to rely on it: a 101 is not a
  // response whose body needs framing, it is the end of HTTP framing on this
  // connection.
  if status_line.code == SWITCHING_PROTOCOLS {
    return Err(H1Error::Framing(SWITCHING_NEEDS_TUNNEL));
  }
  let (framing, directives) =
    validate_response(&status_line, &view, exchange.method_head, exchange.connect)?;
  Ok(ParsedHead {
    view,
    framing,
    directives,
    // RFC 9110 §15.2: every 1xx is informational, and any number of them may
    // precede the final response.
    interim: matches!(status_line.code, 100..=199),
    // The method is the REQUEST's; the exchange recorded it when it opened.
    method_head: false,
    version: status_line.version,
    line: StartLine::Status(status_line),
  })
}

/// Commits a parsed head: counts its bytes, applies its connection directives,
/// enters its body, and builds the item that carries it.
///
/// The single place the head phase advances, so the commit and the yield cannot
/// drift apart — `consumed`, the receive state, and the returned item all move
/// together or not at all.
fn commit_head<'a>(
  it: &mut Items<'a, '_>,
  consumed: usize,
  exchange: ExchangeId,
  parsed: ParsedHead<'a>,
) -> Item<'a> {
  *it.consumed = consumed;
  // The watermark belonged to THIS head; the next one is scanned from its own
  // first byte.
  *it.watermark = 0;
  // The PEER said it will close, by either of the two things that say so: RFC
  // 9112 §9.6's `close` connection option, and §6.3 item 8's close-delimited
  // framing, which §9.3 makes non-persistent by construction ("all messages on a
  // connection need to have a self-defined message length").
  //
  // ACCUMULATED, not read per head. RFC 9110 §15.2 lets any number of interim
  // responses precede the final one and the option may ride on any of them, so a
  // head that does not repeat it is not a head that withdrew it.
  //
  // Recorded APART from the lifecycle, because the lifecycle cannot answer the
  // question this fact is for: `Lifecycle::Closing` means "no further exchange
  // begins", which either end may decide, while this means "the peer will stop
  // reading", which only the peer can.
  //
  // And ACTED ON in one place — see `peer_close_effects`. The consequences are
  // not enumerated here, because enumerating them at each site is what let them
  // drift apart twice.
  *it.peer_close |= parsed.directives.close || matches!(parsed.framing, BodyFraming::ReadToClose);
  if *it.peer_close {
    peer_close_effects(it, parsed.interim);
  }
  if !parsed.interim {
    // RFC 9112 §6.3's framing decision and the ceiling in force, in one
    // expression: a `Content-Length` past the ceiling produces a decoder that
    // is already refused, before the receive state below is written.
    let decoder = BodyDecoder::new(parsed.framing, it.max_body, it.max_chunk_framing);
    *it.recv = RecvState::Body {
      // RFC 9110 §10.1.1: the expectation asks "shall I send the content?", and
      // this end has already answered no. Not surfacing the ask is what makes
      // it impossible to invite a `100 (Continue)` for content that is refused,
      // and it discharges §10.1.1's first MUST-alternative — "an immediate
      // response with a final status code, if that status can be determined by
      // examining just the method, target URI, and header fields" — with no
      // special case anywhere. `Expect` is a request field, and validation
      // already dropped an expectation an HTTP/1.0 request could not state.
      expect_owed: parsed.directives.expect_continue && !decoder.is_refused(),
      decoder,
    };
  }
  Item::Head {
    exchange,
    view: parsed.view,
    line: parsed.line,
    interim: parsed.interim,
  }
}

/// Everything that follows from "this connection received a close".
///
/// ONE routine, invoked wherever `peer_close` holds, so that a consequence added
/// to the list below is applied at EVERY trigger — the final head, the interim
/// head, and §6.3 item 8's close-delimited framing alike. The last two rounds
/// were both this: a consequence enumerated at one call site and forgotten at
/// another, so the fact and its effects drifted apart. The list lives here
/// instead.
///
/// Idempotent in every part, because it runs again on each head the option rides
/// on and on each head after one: `signal_close` fires only on the edge out of
/// `Lifecycle::Open`, `abandon_send` only acts on a body still in flight, and a
/// connection that has already terminated is draining, so no later head reaches
/// this at all.
///
/// `head_is_the_whole_message` says whether the message carrying the option is
/// COMPLETE at its head, which is what decides when the exchange can end. RFC
/// 9112 §9.6 makes the peer close "after completion of the response" containing
/// the option, so:
///
/// - An INTERIM response is bodiless (§6.3 item 1), so its message is complete
///   the moment its head is read: nothing more will arrive and the exchange ends
///   here.
/// - A FINAL response ends where its body does. The body path already settles the
///   exchange there and yields the `ExchangeComplete` item that says so, and
///   short-circuiting it here would swallow that item.
///
/// TUNNEL mode does not come through here, and that is not an omission: it has no
/// exchange, no receive FSM and no request body, so none of the state below
/// exists to move. Its terminal is `TunnelPhase::Refused`, set where it reads the
/// option.
fn peer_close_effects(it: &mut Items<'_, '_>, head_is_the_whole_message: bool) {
  // 1. RFC 9112 §9.6: keep-alive is over. The notice is once per connection,
  //    which `signal_close` is what guarantees — and it is given from an interim
  //    head as well, since `close` is a statement about the CONNECTION rather
  //    than about the message carrying it.
  signal_close(it.lifecycle, it.event, *it.read_closed);

  // 2. §9.6's "cease sending": a client still writing its request body is
  //    released from the rest of it, because the peer has said it will stop
  //    reading. Server-side there is nothing to release — a response is owed to a
  //    request already held in full, and no inbound event withdraws that.
  if it.is_client {
    abandon_send(it.send);
  }

  // 3. §9.6 again: the peer closes after the response carrying the option is
  //    complete, so no message follows it. When that response IS its head, the
  //    exchange is over now — the receive side terminates and settles, which
  //    drains the connection (`Closing` was set in 1). `wants_read` then answers
  //    false, and a later response is not parsed at all: it can no longer
  //    complete an exchange, which is the whole point.
  //
  //    `consumed` is deliberately untouched, and the caller still returns the
  //    head item: a 1xx is a real response and §15.2 entitles the driver to see
  //    the one that carried the option.
  //
  // 4. …and that head is NOT an answer to the exchange it ends. §15.2 makes a
  //    1xx informational, so this exchange is over WITHOUT its final response,
  //    and `Event::ExchangeAborted` is what names it. The connection-scoped close
  //    notice cannot: it names no exchange, so a driver tracking messages would
  //    never learn that this one died and would wait, or fail to retry.
  //
  //    Queued before the settle below, which is what clears the exchange the
  //    notice has to name. Every other way an exchange ends produces something
  //    else — a completion item, or an `Err` — see `Event::ExchangeAborted`.
  if head_is_the_whole_message {
    *it.aborted = it.exchange.map(|exchange| exchange.id);
    *it.recv = RecvState::AwaitingRearm;
    settle(
      it.recv,
      it.exchange,
      it.watermark,
      it.send,
      it.lifecycle,
      it.pending_cr,
    );
  }
}

/// Feeds the body decoder and turns its answer into an item.
fn body<'a>(it: &mut Items<'a, '_>) -> Result<Step<'a>, Error> {
  // The exchange is set before the body state is ever entered; without one there
  // is no id to name items with, so there is nothing to hand out.
  let Some(exchange) = *it.exchange else {
    return Ok(Step::Stop);
  };
  let start = *it.consumed;
  let rest = it.input().get(start..).unwrap_or_default();

  // The decoder is borrowed for the call alone: what it hands back borrows the
  // INPUT, so the borrow of the receive state ends here and the state can move
  // below.
  let fed = match it.recv {
    RecvState::Body {
      expect_owed: owed, ..
    } if *owed => {
      // RFC 9110 §10.1.1: stated before any body octet, because the point of the
      // expectation is that the body has not been sent yet.
      *owed = false;
      return Ok(Step::Yield(Item::ExpectContinue {
        exchange: exchange.id,
      }));
    }
    RecvState::Body { decoder, .. } => decoder.feed(rest),
    RecvState::Idle | RecvState::AwaitingRearm => return Ok(Step::Stop),
  };
  let (claimed, produced) = match fed {
    Ok(fed) => fed,
    Err(BodyFault::Violation(error)) => return Err(fail(it, error)),
    // `*it.consumed` is deliberately untouched: a refusal consumes zero, and
    // the decoder — restored by the charge that refused — stays in step with
    // the driver's cursor.
    Err(BodyFault::TooLarge(budget)) => {
      return Err(Error::Refused(refused(it, exchange.id, budget)));
    }
  };

  // The decoder claims a byte only when the framing says the body owns it, and
  // it moved past every byte it claimed, so the count moves with it. For the
  // items below that is the same call that yields them; for the chunked coding's
  // own framing lines there is no item and never will be.
  *it.consumed = start.saturating_add(claimed);
  Ok(match produced {
    Some(BodyItem::Data(data)) => Step::Yield(Item::BodyChunk {
      exchange: exchange.id,
      data,
    }),
    Some(BodyItem::TrailerField { name, value }) => Step::Yield(Item::Trailer {
      exchange: exchange.id,
      name,
      value,
    }),
    Some(BodyItem::Finished) => {
      *it.recv = RecvState::AwaitingRearm;
      // RFC 9112 §9.2's barrier: this offer completed an exchange and may still
      // hold bytes behind it. Until the pump has read them back, a client may
      // not open a request they could be adopted by — see `tail_unresolved`.
      *it.tail_unresolved |= it.is_client;
      settle(
        it.recv,
        it.exchange,
        it.watermark,
        it.send,
        it.lifecycle,
        it.pending_cr,
      );
      Step::Yield(Item::ExchangeComplete {
        exchange: exchange.id,
      })
    }
    // RFC 9112 §7.1.2: the start of the trailer section is a stage the decoder
    // enters, not something a driver acts on — the trailer FIELDS that follow
    // are, and they come next.
    Some(BodyItem::TrailersStart) => Step::Again,
    // Framing consumed with nothing to show for it (a chunk-size line, a chunk's
    // trailing CRLF) is progress; nothing consumed is need-more-input.
    None if claimed > 0 => Step::Again,
    None => Step::Stop,
  })
}

/// Takes the connection through a body refusal and returns the refusal to hand
/// back.
///
/// The `Items` half of `connection::refuse`: it holds the borrows disjointly, so
/// the argument list is assembled here rather than at each of the three sites
/// that refuse — the body pump, the EOF path, and `Items::limit_body`, which is
/// the one a ROUTE reaches rather than the wire.
///
/// `budget` travels from the comparison that failed. The two wire sites forward
/// the decoder's own answer; `limit_body` states [`Budget::Payload`], because
/// narrowing is a payload operation and the framing budget belongs to the
/// connection.
pub(crate) fn refused(it: &mut Items<'_, '_>, exchange: ExchangeId, budget: Budget) -> Refusal {
  refuse(
    it.recv,
    it.exchange,
    it.watermark,
    it.send,
    it.lifecycle,
    it.event,
    it.pending_cr,
    *it.read_closed,
    it.is_client,
    exchange,
    budget,
  )
}

/// Latches the connection and turns a wire violation into the error handed back.
///
/// The bytes were read from a live connection, so the TRANSPORT can still carry
/// an answer — whether the EXCHANGE can is `latch`'s question, and one it answers
/// no to once this end's own response has started going out.
fn fail(it: &mut Items<'_, '_>, error: H1Error) -> Error {
  latch(
    it.send,
    it.lifecycle,
    *it.read_closed,
    it.is_client,
    true,
    it.exchange.is_some(),
    error,
  )
}
