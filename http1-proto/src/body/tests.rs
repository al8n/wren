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
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(5));
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
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(0));
  assert_eq!(d.feed(b"x").unwrap(), (0, Some(BodyItem::Finished)));
  let mut n = BodyDecoder::new(BodyFraming::None);
  assert_eq!(n.feed(b"x").unwrap(), (0, Some(BodyItem::Finished)));
}

// RFC 9112 §6.3 item 8: a response framed by neither field ends when the
// connection closes, so every byte read is body and only the transport's EOF
// can finish it.
#[test]
fn read_to_close_consumes_everything_until_eof() {
  let mut d = BodyDecoder::new(BodyFraming::ReadToClose);
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
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(5));
  d.feed(b"ab").unwrap();
  assert!(d.eof().is_err());
}

// RFC 9112 §6.3: the body ends where its framing says, and §9.3 makes whatever
// follows on the connection the NEXT message. Once `Finished` has been emitted
// the decoder is idle: it claims no further byte, repeats no item, and an EOF
// reaching it is the close of a message already complete.
#[test]
fn nothing_is_claimed_after_finished() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(2));
  assert_eq!(d.feed(b"ab").unwrap(), (2, Some(BodyItem::Data(b"ab"))));
  assert_eq!(d.feed(b"NEXT").unwrap(), (0, Some(BodyItem::Finished)));
  assert_eq!(d.feed(b"NEXT").unwrap(), (0, None));
  assert_eq!(d.eof().unwrap(), None);
  assert!(d.is_finished());

  let mut r = BodyDecoder::new(BodyFraming::ReadToClose);
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
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(3));
  assert_eq!(d.feed(b"abc").unwrap(), (3, Some(BodyItem::Data(b"abc"))));
  assert!(d.is_finished());
  assert_eq!(d.eof().unwrap(), Some(BodyItem::Finished));
  assert!(d.is_finished());

  let mut n = BodyDecoder::new(BodyFraming::None);
  assert!(n.is_finished());
  assert_eq!(n.eof().unwrap(), Some(BodyItem::Finished));
}

// RFC 9112 §6.3 item 6: an empty read proves nothing about where a body ends,
// so the incremental decoder asks for more input rather than finishing a body
// whose octets have not arrived.
#[test]
fn an_empty_feed_makes_no_progress() {
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(5));
  assert_eq!(d.feed(b"").unwrap(), (0, None));
  assert!(!d.is_finished());

  let mut r = BodyDecoder::new(BodyFraming::ReadToClose);
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
  let mut d = BodyDecoder::new(BodyFraming::ContentLength(u64::MAX));
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
  let mut d = BodyDecoder::new(BodyFraming::Chunked);
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
  let mut d = BodyDecoder::new(BodyFraming::Chunked);
  assert!(d.eof().is_err());

  let mut started = BodyDecoder::new(BodyFraming::Chunked);
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
