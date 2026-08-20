//! Body-decoder tests: the RFC 9112 §6.3 framings this decoder resolves
//! (`Content-Length`, the bodiless message, and close-delimited), the
//! two-phase finish they share, and the transport-EOF table.
//!
//! Every case is a byte-string literal fed through the real decoder, so the
//! whole file runs on the bare tier, where no heap exists.

use super::*;

// RFC 9112 §6.3 item 6: a valid Content-Length is the expected body length in
// octets, so the countdown spans reads and the octets past it belong to the
// next message rather than to this body.
#[test]
fn content_length_counts_down_across_splits() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(5), u64::MAX, u64::MAX);
  assert_eq!(d.feed(b"he").unwrap(), (2, Some(BodyItem::Data(b"he"))));
  assert_eq!(
    d.feed(b"llo REST").unwrap(),
    (3, Some(BodyItem::Data(b"llo")))
  );
  assert!(d.is_finished());
  assert_eq!(d.feed(b"REST").unwrap(), (0, Some(BodyItem::Finished)));
}

// RFC 9112 §6.3 items 6-7: a zero Content-Length frames a body of no octets,
// and a message carrying no framing field at all has no body (item 7) — in
// both cases the first byte offered is already the next message's.
#[test]
fn zero_length_finishes_immediately() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(0), u64::MAX, u64::MAX);
  assert_eq!(d.feed(b"x").unwrap(), (0, Some(BodyItem::Finished)));
  let mut n = BodyDecoder::new(BodyFraming::None, u64::MAX, u64::MAX);
  assert_eq!(n.feed(b"x").unwrap(), (0, Some(BodyItem::Finished)));
}

// RFC 9112 §6.3 item 8: a response framed by neither field ends when the
// connection closes, so every byte read is body and only the transport's EOF
// can finish it.
#[test]
fn read_to_close_consumes_everything_until_eof() {
  let mut d = BodyDecoder::new(BodyFraming::ReadToClose, u64::MAX, u64::MAX);
  assert_eq!(d.feed(b"abc").unwrap(), (3, Some(BodyItem::Data(b"abc"))));
  assert!(!d.is_finished());
  assert_eq!(d.eof().unwrap(), Some(BodyItem::Finished));
  assert!(d.is_finished());
}

// RFC 9112 §6.3 item 6: a connection that closes before the indicated octets
// have arrived makes the message incomplete — a MUST, so the short body is an
// error and never a body that merely ended early.
#[test]
fn eof_mid_content_length_is_error() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(5), u64::MAX, u64::MAX);
  d.feed(b"ab").unwrap();
  assert!(d.eof().is_err());
}

// RFC 9112 §6.3: the body ends where its framing says, and §9.3 makes whatever
// follows on the connection the NEXT message. Once `Finished` has been emitted
// the decoder is idle: it claims no further byte, repeats no item, and an EOF
// reaching it is the close of a message already complete.
#[test]
fn nothing_is_claimed_after_finished() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(2), u64::MAX, u64::MAX);
  assert_eq!(d.feed(b"ab").unwrap(), (2, Some(BodyItem::Data(b"ab"))));
  assert_eq!(d.feed(b"NEXT").unwrap(), (0, Some(BodyItem::Finished)));
  assert_eq!(d.feed(b"NEXT").unwrap(), (0, None));
  assert_eq!(d.eof().unwrap(), None);
  assert!(d.is_finished());

  let mut r = BodyDecoder::new(BodyFraming::ReadToClose, u64::MAX, u64::MAX);
  assert_eq!(r.eof().unwrap(), Some(BodyItem::Finished));
  assert_eq!(r.feed(b"NEXT").unwrap(), (0, None));
  assert_eq!(r.eof().unwrap(), None);
}

// RFC 9112 §6.3 item 6: "incomplete" is about octets that never arrived, so a
// close AFTER the full Content-Length was received ends a COMPLETE message —
// including when the caller never pumped the feed that would have emitted
// `Finished`. Item 7's bodiless message is in that same position from the
// start: it owes no octet, so an EOF there truncates nothing.
#[test]
fn eof_at_a_complete_body_finishes_it() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(3), u64::MAX, u64::MAX);
  assert_eq!(d.feed(b"abc").unwrap(), (3, Some(BodyItem::Data(b"abc"))));
  assert!(d.is_finished());
  assert_eq!(d.eof().unwrap(), Some(BodyItem::Finished));
  assert!(d.is_finished());

  let mut n = BodyDecoder::new(BodyFraming::None, u64::MAX, u64::MAX);
  assert!(n.is_finished());
  assert_eq!(n.eof().unwrap(), Some(BodyItem::Finished));
}

// RFC 9112 §6.3 item 6: an empty read proves nothing about where a body ends,
// so the incremental decoder asks for more input rather than finishing a body
// whose octets have not arrived.
#[test]
fn an_empty_feed_makes_no_progress() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(5), u64::MAX, u64::MAX);
  assert_eq!(d.feed(b"").unwrap(), (0, None));
  assert!(!d.is_finished());

  let mut r = BodyDecoder::new(BodyFraming::ReadToClose, u64::MAX, u64::MAX);
  assert_eq!(r.feed(b"").unwrap(), (0, None));
  assert!(!r.is_finished());
}

// RFC 9110 §8.6 leaves Content-Length's decimal unbounded and this core frames
// it as a u64; RFC 9112 §6.3 item 6 then counts it down octet by octet. A
// length past anything a read can deliver must count down by the read's size
// and must not wrap, saturate early, or overflow the usize the slice math runs
// in.
#[test]
fn a_huge_content_length_counts_down_by_the_read() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(u64::MAX), u64::MAX, u64::MAX);
  assert_eq!(d.feed(b"abc").unwrap(), (3, Some(BodyItem::Data(b"abc"))));
  assert!(!d.is_finished());
  assert!(d.eof().is_err());
}

// RFC 9112 §7.1: the chunked coding delimits its own body, so this framing is
// carried by a sub-machine (`super::chunked`) rather than by a countdown. What
// the shell owes is the seam: the sub-machine's items come out of `feed`
// unchanged, the end of its trailer section rejoins the two-phase finish every
// other framing uses, and a close before that end is a truncated message. The
// coding's own grammar is pinned where it is implemented.
#[test]
fn chunked_is_decoded_by_the_sub_machine() {
  let mut d = BodyDecoder::new(BodyFraming::Chunked, u64::MAX, u64::MAX);
  assert!(!d.is_finished());
  assert_eq!(d.feed(b"3\r\nabc\r\n0\r\n\r\n").unwrap(), (3, None));
  assert_eq!(
    d.feed(b"abc\r\n0\r\n\r\n").unwrap(),
    (3, Some(BodyItem::Data(b"abc")))
  );
  assert_eq!(d.feed(b"\r\n0\r\n\r\n").unwrap(), (2, None));
  assert_eq!(
    d.feed(b"0\r\n\r\n").unwrap(),
    (3, Some(BodyItem::TrailersStart))
  );
  assert!(!d.is_finished());
  assert_eq!(d.feed(b"\r\n").unwrap(), (2, None));
  assert!(d.is_finished());
  assert_eq!(d.feed(b"NEXT").unwrap(), (0, Some(BodyItem::Finished)));
  assert_eq!(d.feed(b"NEXT").unwrap(), (0, None));
  assert_eq!(d.eof().unwrap(), None);
}

// RFC 9112 §6.3 item 6 over §7.1: a chunked body's remaining octets are its own
// framing, so a close before the trailer section's empty line is the same
// incomplete message a short `Content-Length` is — an error, not a body that
// ended early.
#[test]
fn eof_mid_chunked_is_error() {
  let mut d = BodyDecoder::new(BodyFraming::Chunked, u64::MAX, u64::MAX);
  assert!(d.eof().is_err());

  let mut started = BodyDecoder::new(BodyFraming::Chunked, u64::MAX, u64::MAX);
  assert_eq!(started.feed(b"3\r\nabc\r\n").unwrap(), (3, None));
  assert!(started.eof().is_err());
}

// RFC 9112 §7.1.2: a chunked body may be followed by a trailer section, whose
// field lines reach the connection layer as items of this stream. The variants
// are defined here and produced by the chunked decoder; this pins the shape
// they carry — a token name as `&str`, a grammar-checked value as bytes — and
// the by-value copying the rest of the core relies on.
#[test]
fn trailer_items_carry_a_name_and_a_value() {
  let field = BodyItem::TrailerField {
    name: "expires",
    value: b"0",
  };
  // `Copy`: the original stays usable, which is what lets an item be handed on
  // without borrowing the decoder that produced it.
  let handed_on = field;
  assert_eq!(handed_on, field);
  assert_ne!(BodyItem::TrailersStart, field);
  assert_ne!(
    field,
    BodyItem::TrailerField {
      name: "expires",
      value: b"1",
    }
  );
}

// The bound's arithmetic, at the two edges that decide whether it holds: the
// total that lands exactly ON the limit is admitted, the one past it is not,
// and a sum no `u64` can hold refuses instead of wrapping into a small total
// that would pass. `None` IS the refusal.
#[test]
fn charge_refuses_at_the_limit_and_on_overflow() {
  assert_eq!(charge(0, 10, 10), Some(10));
  assert_eq!(charge(10, 1, 10), None);
  assert_eq!(charge(u64::MAX, 1, u64::MAX), None); // checked_add, not wrapping
}

// A slice length that no `u64` could hold saturates UPWARDS, so the conversion
// can only ever make a refusal earlier. An under-count would let a body past
// the ceiling.
#[test]
fn widen_saturates_in_the_refusing_direction() {
  assert_eq!(widen(0), 0);
  assert_eq!(widen(usize::MAX), u64::MAX);
}

// The early-exit test is `>`, not `>=`: a declaration that fits the headroom
// EXACTLY is a message the limit permits, and RFC 9110 §15.5.14's refusal is
// for content "larger than" what this end will process.
#[test]
fn overruns_is_strict() {
  assert!(!overruns(10, 10)); // exactly the limit is allowed
  assert!(overruns(11, 10));
}

// What is left of a ceiling after what has been received, which is the form the
// declared-count checks need: `overruns` compares a declaration against the
// headroom rather than against the ceiling, so a body part-way through is
// measured on what remains. Saturating because `received <= limit` is
// `charge`'s postcondition and this must not underflow if it ever stops being.
#[test]
fn headroom_is_what_is_left_and_never_underflows() {
  assert_eq!(headroom(4, 10), 6);
  assert_eq!(headroom(10, 10), 0);
  assert_eq!(headroom(11, 10), 0);
}

// RFC 9112 §6.3 item 6 read against a local ceiling: a `Content-Length` states
// the whole body's size in the head, so a declaration past the limit is
// decidable before one octet of content is read. RFC 9110 §15.5.14 is the
// answer to it, and refusing at the head is what makes that answer cheap —
// nothing is buffered, nothing is charged, and the decoder never counts.
#[test]
fn a_declaration_past_the_limit_is_refused_before_any_octet() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(11), 10, u64::MAX);
  assert!(d.is_refused());
  assert!(matches!(
    d.feed(b"hello"),
    Err(BodyFault::TooLarge(Budget::Payload))
  ));
  assert_eq!(d.received(), 0);
}

// RFC 9112 §6.3 item 8 declares nothing, ever, so no early exit can exist for
// it and the cumulative charge is the only gate it has. Its producer hands the
// whole offered slice over without going through `claim`, which is exactly why
// the charge sits below the fork rather than inside the counted path.
#[test]
fn read_to_close_is_charged_even_though_it_bypasses_claim() {
  let mut d = BodyDecoder::new(BodyFraming::ReadToClose, 4, u64::MAX);
  assert!(matches!(
    d.feed(b"abcd"),
    Ok((4, Some(BodyItem::Data(b"abcd"))))
  ));
  assert!(matches!(
    d.feed(b"e"),
    Err(BodyFault::TooLarge(Budget::Payload))
  ));
}

// THE DECLARATION GATE, and what it leaves behind. RFC 9112 §6.3 item 6's
// number is decided at construction, so this decoder is refused before `feed`
// is ever called: it charges nothing, consumes nothing, and answers the same
// way however often it is asked — which is what keeps it from drifting ahead of
// the driver's cursor, since the pump returns the refusal before it moves
// `consumed` (RFC 9112 §11.2, one change removed).
//
// It does NOT reach the charge's restore: `feed` errors in the framing step,
// above the charge. The case where the restore itself is what makes the answer
// stable is the chunked one below, since only a framing with no advance
// declaration reaches the charge with a stage to roll back.
#[test]
fn a_declaration_refused_at_the_head_charges_nothing_and_is_stable() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(10), 4, u64::MAX);
  let before = d.received();
  assert!(matches!(
    d.feed(b"abcde"),
    Err(BodyFault::TooLarge(Budget::Payload))
  ));
  assert_eq!(d.received(), before, "a refusal charges nothing");
  assert!(
    matches!(d.feed(b"abcde"), Err(BodyFault::TooLarge(Budget::Payload))),
    "and is stable"
  );
}

// THE ANNOUNCEMENT GATE. RFC 9112 §7.1 declares one chunk at a time, so a
// chunk-size line is the whole of what the peer has committed to — and a
// commitment past what is left of the allowance is decidable where it is read,
// one chunk ahead of the octets. The refusal is a strictly earlier evaluation of
// what the cumulative charge would conclude on the next call, never a second
// rule: it compares the same declaration against the same headroom.
//
// Nothing is consumed and nothing is written, which the second feed is what
// proves: a decoder that had advanced to `Stage::Data` would answer these very
// bytes by handing four of them over.
#[test]
fn an_announced_chunk_past_the_headroom_refuses_before_its_data() {
  let mut d = BodyDecoder::new(BodyFraming::Chunked, 4, u64::MAX);
  const LINE: &[u8] = b"5\r\nhello\r\n";
  assert!(matches!(
    d.feed(LINE),
    Err(BodyFault::TooLarge(Budget::Payload))
  ));
  assert_eq!(d.received(), 0, "a refusal charges nothing");
  assert!(
    matches!(d.feed(LINE), Err(BodyFault::TooLarge(Budget::Payload))),
    "and consumed nothing, so the same bytes are answered the same way"
  );
  // The gate is on the ANNOUNCEMENT, not on the body: four octets in four
  // one-octet chunks are four announcements of one, and every one of them fits.
  let mut fits = BodyDecoder::new(BodyFraming::Chunked, 4, u64::MAX);
  for _ in 0..4 {
    assert_eq!(fits.feed(b"1\r\na\r\n").unwrap(), (3, None));
    assert!(matches!(
      fits.feed(b"a\r\n").unwrap(),
      (1, Some(BodyItem::Data(b"a")))
    ));
    assert_eq!(fits.feed(b"\r\n").unwrap(), (2, None));
  }
  assert_eq!(fits.received(), 4);
}

// AND THE HEADROOM IS THE CUMULATIVE TALLY, which no case above can tell: each
// of them announces against a FRESH decoder, where what is left of the
// allowance and the whole ceiling are the same number. A body part-way through
// is the only place the two separate, and it is where the gate's identity with
// the charge is decided — the announcement is measured against what the earlier
// chunks already spent, which is exactly the comparison the shell's charge
// would run one chunk later.
//
// A gate spelled against the CEILING instead still holds `delivered <= limit`,
// because the charge is what enforces the bound. What it loses is the promise
// this gate makes: a peer announcing a chunk past the remainder and then
// sending nothing would never be refused at all, parked in `Stage::Data`
// awaiting a refusal it was owed at the size line.
#[test]
fn a_later_chunk_overrunning_the_remainder_is_refused_at_its_size_line() {
  let mut d = BodyDecoder::new(BodyFraming::Chunked, 4, u64::MAX);
  assert_eq!(d.feed(b"2\r\n").unwrap(), (3, None));
  assert!(matches!(
    d.feed(b"ab").unwrap(),
    (2, Some(BodyItem::Data(b"ab")))
  ));
  assert_eq!(d.feed(b"\r\n").unwrap(), (2, None));
  // Three fits the ceiling (3 < 4) and not the headroom (3 > 4 - 2), so the
  // size line ALONE is refused, before any data exists to charge.
  assert!(matches!(
    d.feed(b"3\r\n"),
    Err(BodyFault::TooLarge(Budget::Payload))
  ));
  assert_eq!(d.received(), 2, "a refusal charges nothing");
}

// THE ATTACK THE BUDGET EXISTS FOR, and the reason it is charged over the whole
// LINE rather than over the extension RFC 9112 §7.1.1 names. `chunk-size =
// 1*HEXDIG` admits unlimited leading zeros, so 271 of them and a `1` is a
// 272-octet line that parses cleanly, announces ONE octet and spends 274
// framing octets — with no `chunk-ext` in it at all, which is what an
// extension-only budget would have been measuring.
#[test]
fn zero_padding_a_size_line_spends_the_framing_budget() {
  // 271 zeros, a `1`, and the CRLF that ends the line: 274 octets on the wire
  // for one octet of content.
  let mut padded = [b'0'; 274];
  padded[271] = b'1';
  padded[272] = b'\r';
  padded[273] = b'\n';
  assert!(
    !padded.contains(&b';'),
    "not one extension octet, so an extension budget never sees this line"
  );

  let mut d = BodyDecoder::new(BodyFraming::Chunked, u64::MAX, 274);
  // The whole line is consumed and the whole budget is spent on it.
  assert_eq!(d.feed(&padded).unwrap(), (274, None));
  assert!(matches!(
    d.feed(b"X\r\n").unwrap(),
    (1, Some(BodyItem::Data(b"X")))
  ));
  assert_eq!(d.feed(b"\r\n").unwrap(), (2, None));

  // The second line of the same shape has nothing left to spend. The payload
  // ceiling is unbounded here: nothing about this attack is about content.
  assert!(matches!(
    d.feed(&padded),
    Err(BodyFault::TooLarge(Budget::ChunkFraming))
  ));
  assert_eq!(d.received(), 1, "277 wire octets bought one payload octet");
}

// THE EXTENSION OCTETS ARE CHARGED, and no other test here proves it: every
// other budget case above is spelled with lines that carry no `chunk-ext` at
// all, so a gate that counted the digits and the CRLF and skipped the extension
// would pass all of them. RFC 9112 §7.1.1's extension is precisely the part of
// a line a peer may grow WITHOUT changing the length it announces — the part
// §7.1.1 asks a server to limit — and this core's per-line allowance for it is
// `MAX_CHUNK_EXT_BYTES` against three octets of minimum line, so a gate that
// skipped it would under-count by up to 86× and the wire bound the budget
// exists to state would be false.
#[test]
fn chunk_extension_octets_are_charged_against_the_framing_budget() {
  // The same announcement, spelled twice: seven octets with an extension, three
  // without. Thirteen admits ONE of the first and all three of the second.
  const EXTENDED: &[u8] = b"1;a=b\r\n";
  const BARE: &[u8] = b"1\r\n";
  const BUDGET: u64 = 13;

  let mut d = BodyDecoder::new(BodyFraming::Chunked, u64::MAX, BUDGET);
  assert_eq!(
    d.feed(EXTENDED).unwrap(),
    (7, None),
    "the extension is part of the line the peer made this end read"
  );
  assert!(matches!(
    d.feed(b"X\r\n").unwrap(),
    (1, Some(BodyItem::Data(b"X")))
  ));
  assert_eq!(d.feed(b"\r\n").unwrap(), (2, None));
  // 7 + 7 is past 13, and only the extension octets put it there.
  assert!(matches!(
    d.feed(EXTENDED),
    Err(BodyFault::TooLarge(Budget::ChunkFraming))
  ));
  assert_eq!(d.received(), 1);

  // THE CONTROL, and it is what makes those octets load-bearing rather than the
  // budget merely small: the same two chunks and the last chunk, announced
  // without extensions, spend nine of the same thirteen and the body completes.
  let mut bare = BodyDecoder::new(BodyFraming::Chunked, u64::MAX, BUDGET);
  for _ in 0..2 {
    assert_eq!(bare.feed(BARE).unwrap(), (3, None));
    assert!(matches!(
      bare.feed(b"X\r\n").unwrap(),
      (1, Some(BodyItem::Data(b"X")))
    ));
    assert_eq!(bare.feed(b"\r\n").unwrap(), (2, None));
  }
  assert!(matches!(
    bare.feed(b"0\r\n\r\n").unwrap(),
    (3, Some(BodyItem::TrailersStart))
  ));
  assert_eq!(bare.feed(b"\r\n").unwrap(), (2, None));
  assert!(matches!(
    bare.feed(b"").unwrap(),
    (0, Some(BodyItem::Finished))
  ));
  assert_eq!(bare.received(), 2);
}

// THE OTHER END OF THE SAME BUDGET, at the server's own defaults. Three charged
// octets is the cheapest a chunk can be — `1`, CR, LF — so 64 KiB of framing
// buys 21,845 of them and the next size line is refused, with 21,845 payload
// octets delivered against a ceiling of a megabyte: a forty-eighth of it, so
// the content ceiling is nowhere near what stopped this.
#[test]
fn one_octet_chunks_are_refused_at_the_framing_budget_not_the_payload_one() {
  const PAYLOAD: u64 = 1 << 20;
  const FRAMING: u64 = 1 << 16;
  let mut d = BodyDecoder::new(BodyFraming::Chunked, PAYLOAD, FRAMING);
  for _ in 0..21_845 {
    assert_eq!(d.feed(b"1\r\nX\r\n").unwrap(), (3, None));
    assert!(matches!(
      d.feed(b"X\r\n").unwrap(),
      (1, Some(BodyItem::Data(b"X")))
    ));
    assert_eq!(d.feed(b"\r\n").unwrap(), (2, None));
  }
  assert!(matches!(
    d.feed(b"1\r\nX\r\n"),
    Err(BodyFault::TooLarge(Budget::ChunkFraming))
  ));
  assert_eq!(d.received(), 21_845);
  assert!(
    d.received() < PAYLOAD,
    "the content ceiling was nowhere near reached"
  );
}

// SYNTAX BEFORE POLICY, on the framing budget this time. A cumulative cap
// refuses elements that PARSED, so a line that is not `1*HEXDIG` at all is
// diagnosed as malformed however far past the budget it also was — and the
// budget is proven live on the very next decoder by the same bytes made valid.
#[test]
fn a_malformed_and_over_budget_size_line_latches_rather_than_refusing() {
  let mut malformed = BodyDecoder::new(BodyFraming::Chunked, u64::MAX, 2);
  assert!(matches!(
    malformed.feed(b"zz\r\n"),
    Err(BodyFault::Violation(H1Error::Malformed(_)))
  ));
  // Same budget, same four octets of line, but this one is a chunk-size: the
  // gate the malformed line never reached refuses it.
  let mut valid = BodyDecoder::new(BodyFraming::Chunked, u64::MAX, 2);
  assert!(matches!(
    valid.feed(b"1a\r\n"),
    Err(BodyFault::TooLarge(Budget::ChunkFraming))
  ));
}

// The order between the two gates, which decides what a line breaching BOTH is
// refused as. Framing runs first, so the answer is deterministic — and it is
// the right one to be deterministic about: a driver told "content too large"
// about a body whose content it never received would look for the wrong bug.
#[test]
fn a_size_line_breaching_both_budgets_is_refused_as_framing() {
  // `5\r\n` is three framing octets against two, and announces five payload
  // octets against a headroom of one.
  let mut both = BodyDecoder::new(BodyFraming::Chunked, 1, 2);
  assert!(matches!(
    both.feed(b"5\r\n"),
    Err(BodyFault::TooLarge(Budget::ChunkFraming))
  ));
  // The same line, with the framing budget out of the way, is the payload
  // refusal — so the pairing shows the framing gate ran FIRST rather than that
  // the payload gate is missing.
  let mut payload = BodyDecoder::new(BodyFraming::Chunked, 1, u64::MAX);
  assert!(matches!(
    payload.feed(b"5\r\n"),
    Err(BodyFault::TooLarge(Budget::Payload))
  ));
}

// THE BOUNDARY, worked rather than discovered. At the server defaults a 1 MiB
// body in exactly-64-octet chunks writes 16,384 `40\r\n` lines, which is
// 65,536 octets — the whole budget, to the byte. The last-chunk line is charged
// like any other, so the body is refused at its terminating `0\r\n` with every
// payload octet already delivered. 64 octets is therefore one below the
// sustainable granularity, and 65 is the smallest chunk size a full body can be
// sent in.
#[test]
fn sixty_four_octet_chunks_spend_the_whole_budget_and_are_refused_at_the_last_chunk() {
  const CHUNK: &[u8] =
    b"40\r\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n";
  let mut d = BodyDecoder::new(BodyFraming::Chunked, 1 << 20, 1 << 16);
  for _ in 0..16_384 {
    assert_eq!(d.feed(CHUNK).unwrap(), (4, None));
    let (claimed, item) = d.feed(CHUNK.get(4..).unwrap()).unwrap();
    assert_eq!(claimed, 64);
    assert!(matches!(item, Some(BodyItem::Data(data)) if data.len() == 64));
    assert_eq!(d.feed(CHUNK.get(68..).unwrap()).unwrap(), (2, None));
  }
  assert_eq!(d.received(), 1 << 20, "every payload octet was handed over");
  assert!(matches!(
    d.feed(b"0\r\n\r\n"),
    Err(BodyFault::TooLarge(Budget::ChunkFraming))
  ));
}

// THE RATCHET. `min` is idempotent and commutative, so the narrowed ceiling
// does not depend on how often the call is made or in what order: a `max` above
// the ceiling in force is a no-op, which is what makes a routing bug unable to
// LIFT a ceiling — the operation has no increasing direction to be pointed in.
#[test]
fn narrowing_only_tightens_and_is_idempotent() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(100), 1000, u64::MAX);
  assert!(d.narrow(500));
  assert_eq!(d.limit(), 500);
  assert!(d.narrow(800));
  assert_eq!(d.limit(), 500, "min only — a widen is a no-op");
  assert!(d.narrow(500));
  assert_eq!(d.limit(), 500);
}

// RFC 9112 §6.3 item 6 states the whole body's length in the head, so a ceiling
// narrowed below what that number already declared is decidable at once and
// without reading an octet — the same early exit the declaration gate makes at
// construction, applied to the ceiling a route replaced it with.
#[test]
fn narrowing_below_what_the_framing_declared_refuses_in_place() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(100), 1000, u64::MAX);
  assert!(!d.narrow(50));
  assert!(d.is_refused());
}

// RFC 9112 §6.3 items 1 and 7: a message with no content at all is COMPLETE
// before a byte is read, so there is nothing a ceiling could be about and the
// answer is vacuously yes. A driver that narrows after every head is the
// natural shape, and it must not be told that every conformant GET, HEAD
// response or 304 was an error.
#[test]
fn narrowing_on_a_bodiless_message_succeeds_vacuously() {
  let mut d = BodyDecoder::new(BodyFraming::None, 1000, u64::MAX);
  assert!(
    d.narrow(1),
    "a uniform narrow-after-every-head driver must not error on a GET"
  );
}

// The OTHER count a narrowing can be unsatisfiable on, and the only framing
// that isolates it: RFC 9112 §6.3 item 8 declares nothing, ever, so no
// declaration can be over the headroom and what refuses here is purely that
// more octets have already been handed over than the new ceiling allows. The
// bound is on the message's TOTAL, not on what is left.
#[test]
fn narrowing_below_what_has_already_been_delivered_refuses() {
  let mut d = BodyDecoder::new(BodyFraming::ReadToClose, 1000, u64::MAX);
  assert_eq!(
    d.feed(b"abcdef").unwrap(),
    (6, Some(BodyItem::Data(b"abcdef")))
  );
  assert!(!d.narrow(4));
  assert!(d.is_refused());
  assert_eq!(
    d.limit(),
    4,
    "committed before the check, so the refusal names the ceiling that refused"
  );
}

// What each RFC 9112 §6.3 framing has COMMITTED to at the moment its head has
// been read, which is the one moment the three separate cleanly: item 6 states
// the whole body, §7.1 states nothing until a size line has been read, and item
// 8 can state nothing at all.
#[test]
fn announced_separates_the_three_framings_right_after_the_head() {
  assert_eq!(
    BodyDecoder::new(BodyFraming::ContentLength(42), 1 << 20, u64::MAX).announced(),
    Some(42)
  );
  assert_eq!(
    BodyDecoder::new(BodyFraming::Chunked, 1 << 20, u64::MAX).announced(),
    None
  );
  assert_eq!(
    BodyDecoder::new(BodyFraming::ReadToClose, 1 << 20, u64::MAX).announced(),
    None
  );
}

// RFC 9112 §7.1 announces ONE chunk at a time and never a body total, so this
// tracks the chunk in flight and falls back to `None` the moment that chunk's
// octets are through. A reader that took it for a body length would be reading
// a number §7.1 never states.
#[test]
fn announced_follows_the_chunk_in_flight_rather_than_the_body() {
  let mut d = BodyDecoder::new(BodyFraming::Chunked, u64::MAX, u64::MAX);
  assert_eq!(d.announced(), None, "no size line has been read yet");
  assert_eq!(d.feed(b"5\r\n").unwrap(), (3, None));
  assert_eq!(d.announced(), Some(5), "the remainder of THIS chunk");
  assert_eq!(d.feed(b"he").unwrap(), (2, Some(BodyItem::Data(b"he"))));
  assert_eq!(d.announced(), Some(3));
  assert_eq!(d.feed(b"llo").unwrap(), (3, Some(BodyItem::Data(b"llo"))));
  assert_eq!(d.announced(), None, "between chunks nothing is declared");
}
