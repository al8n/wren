//! Driver-vocabulary tests: the identity that correlates a keep-alive
//! connection's messages, the shape of the borrowed items a connection hands
//! out, the owned notices it queues, and the lifetime contract the `Items`
//! signature freezes for the pump.
//!
//! Almost all of it is value and shape assertions over borrowed slices, so it
//! runs on the bare tier; only the `Debug` renderings need a heap to format
//! into, and those live in the gated submodule at the bottom.

use super::*;
use crate::{
  connection::{Connection, General, Server},
  head::{request_line::parse_request_line, scan::scan_head, status_line::parse_status_line},
};

const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\n\r\n";
const INTERIM: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

// RFC 9112 §9.3: a connection carries requests in order and a server "MUST send
// responses ... in the same order that the requests were received", so the
// number that names an exchange is ORDERED, not merely distinct — comparing two
// ids answers which exchange came first on a connection carrying many.
#[test]
fn exchange_ids_are_ordered_and_expose_their_number() {
  let first = ExchangeId::new(1);
  let second = ExchangeId::new(2);

  assert_eq!(first.get(), 1);
  assert_eq!(second.get(), 2);
  assert_eq!(first, ExchangeId::new(1));
  assert_ne!(first, second);
  assert!(first < second);
  assert_eq!(first.cmp(&second), core::cmp::Ordering::Less);
  assert_eq!(first.max(second), second);
  assert_eq!(first.min(second), first);
}

// The driver keys its own per-exchange state (a pending response, a deadline) by
// this id, so it hashes; `Hash` and `Eq` are derived together, which is what
// makes equal ids hash equally.
#[test]
fn exchange_ids_hash_in_agreement_with_equality() {
  struct Fnv(u64);
  impl core::hash::Hasher for Fnv {
    fn finish(&self) -> u64 {
      self.0
    }
    fn write(&mut self, bytes: &[u8]) {
      for b in bytes {
        self.0 = (self.0 ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
      }
    }
  }
  fn hash_of(id: ExchangeId) -> u64 {
    let mut h = Fnv(0xcbf2_9ce4_8422_2325);
    core::hash::Hash::hash(&id, &mut h);
    core::hash::Hasher::finish(&h)
  }

  assert_eq!(hash_of(ExchangeId::new(5)), hash_of(ExchangeId::new(5)));
  assert_ne!(hash_of(ExchangeId::new(5)), hash_of(ExchangeId::new(6)));
}

// RFC 9112 §2.1 (`HTTP-message = start-line CRLF *( field-line CRLF ) CRLF
// [ message-body ]`) with §7.1.2 (a chunked body may close with a trailer
// section): the inbound units a driver is handed are exactly those parts, and
// every one of them names the exchange it belongs to, because §9.3 lets one
// connection carry many messages in sequence.
#[test]
fn items_name_their_exchange_and_borrow_the_input() {
  let exchange = ExchangeId::new(1);
  let view = scan_head(REQUEST).unwrap();
  let request = parse_request_line(view.start_line_bytes()).unwrap();

  let Item::Head {
    exchange: at,
    view,
    line,
    interim,
  } = (Item::Head {
    exchange,
    view,
    line: StartLine::Request(request),
    interim: false,
  })
  else {
    panic!("constructed a Head")
  };
  assert_eq!(at, exchange);
  assert!(!interim);
  assert_eq!(view.header("host"), Some(b"example.com".as_slice()));
  // RFC 9112 §2.1: the start line is part of the head a driver was handed, not
  // something it has to go back to the bytes for.
  let StartLine::Request(request) = line else {
    panic!("a server head carries a request-line")
  };
  assert_eq!(request.method, "GET");

  // The payload items point into the driver's slice rather than owning a copy
  // of it: `data` and `value` are the fed bytes themselves.
  let Item::BodyChunk { exchange: at, data } = (Item::BodyChunk {
    exchange,
    data: REQUEST,
  }) else {
    panic!("constructed a BodyChunk")
  };
  assert_eq!(at, exchange);
  assert!(core::ptr::eq(data, REQUEST));

  let Item::Trailer {
    exchange: at,
    name,
    value,
  } = (Item::Trailer {
    exchange,
    name: "X-Sum",
    value: b"1",
  })
  else {
    panic!("constructed a Trailer")
  };
  assert_eq!(at, exchange);
  assert_eq!(name, "X-Sum");
  assert_eq!(value, b"1".as_slice());

  let Item::ExchangeComplete { exchange: at } = (Item::ExchangeComplete { exchange }) else {
    panic!("constructed an ExchangeComplete")
  };
  assert_eq!(at, exchange);
}

// RFC 9110 §15.2 / §15.2.1: any number of 1xx informational responses may
// precede the final one, and a client "MUST be able to parse" them, so an
// interim head is a head the driver sees WITHOUT the exchange ending — the flag
// is the only thing that distinguishes it from the final head.
#[test]
fn interim_heads_are_flagged_and_carry_the_same_exchange() {
  let exchange = ExchangeId::new(4);
  let view = scan_head(INTERIM).unwrap();
  let interim = Item::Head {
    exchange,
    view,
    line: StartLine::Status(parse_status_line(view.start_line_bytes()).unwrap()),
    interim: true,
  };
  let Item::Head {
    exchange: at,
    line,
    interim: flag,
    ..
  } = interim
  else {
    panic!("constructed an interim Head")
  };
  assert!(flag);
  // The flag and the code agree: a 1xx is what makes a head interim.
  let StartLine::Status(status) = line else {
    panic!("a client head carries a status-line")
  };
  assert_eq!(status.code, 100);
  // Same exchange as the final head that follows it: an interim mints nothing.
  assert_eq!(at, exchange);
}

// RFC 9110 §10.1.1: a request carrying `Expect: 100-continue` asks the server to
// approve the head before the body arrives. The core surfaces the ask and
// nothing more — whether to answer `100` is the driver's policy — so the item
// carries only the exchange it belongs to.
#[test]
fn expect_continue_names_only_its_exchange() {
  let exchange = ExchangeId::new(2);
  let Item::ExpectContinue { exchange: at } = (Item::ExpectContinue { exchange }) else {
    panic!("constructed an ExpectContinue")
  };
  assert_eq!(at, exchange);
}

// RFC 9112 §9.6: a peer signalling close ends keep-alive, which is a
// connection-scoped fact with nothing to borrow from the input — so an `Event` is
// a small owned value a driver can copy out and compare.
//
// ONE variant, and that is the whole of this vocabulary: everything about a
// MESSAGE reaches the driver as an `Item`, and everything a call could not do
// reaches it as that call's `Error`. (There is deliberately no `ExchangeAborted`
// variant: `handle_eof` completes a close-delimited message with
// `Item::ExchangeComplete`, so nothing would ever produce one. `Event` is
// `#[non_exhaustive]`, so re-adding a variant is free.)
#[test]
fn events_are_owned_copyable_values_compared_by_content() {
  let aborted = Event::ExchangeAborted {
    exchange: ExchangeId::new(7),
  };
  let copied = aborted;
  assert_eq!(aborted, copied);
  assert_eq!(
    copied,
    Event::ExchangeAborted {
      exchange: ExchangeId::new(7)
    }
  );
}

// `Ok(None)` is "these bytes are exhausted", not "this connection is done": a
// head the peer has not finished sending yields nothing, repeatably, and leaves
// the whole offer in the driver's buffer (RFC 9112 §2.2 — a head ends at its
// empty line and nowhere earlier).
#[test]
fn an_incomplete_head_yields_nothing_and_consumes_nothing() {
  let mut connection = Connection::<Server, General>::new();
  let mut items = connection.handle(REQUEST.get(..10).unwrap());

  assert!(items.next().unwrap().is_none());
  assert!(items.next().unwrap().is_none());
  assert_eq!(items.consumed(), 0);
}

// The consumed counter LIVES IN the connection and `consumed`
// READS it through the borrow — it is not a tally the iterator keeps for itself.
// That is what makes dropping the iterator mid-iteration safe: what was consumed
// stays consumed, so re-offering the remainder continues the exchange instead of
// re-emitting the head, which is the recipient disagreement §11.2 is about.
#[test]
fn consumed_reads_the_connections_counter_and_survives_the_iterator() {
  let mut connection = Connection::<Server, General>::new();
  let mut items = connection.handle(REQUEST);
  assert_eq!(items.consumed(), 0);
  assert!(matches!(items.next().unwrap(), Some(Item::Head { .. })));
  // The count moved with the item that was handed over — and it moved in the
  // CONNECTION, which is why dropping the iterator here loses nothing.
  assert_eq!(items.consumed(), REQUEST.len());

  // The iterator's last use is above, so the connection is free again — and
  // what it kept is the count, not a tally that went with the iterator.
  let mut rest = connection.handle(b"");
  assert!(matches!(
    rest.next().unwrap(),
    Some(Item::ExchangeComplete { .. })
  ));
}

// The property this task exists to freeze: what `Items` hands back is tied to
// the INPUT lifetime `'a`, never to `&mut self`. `drive` proves it structurally
// — it returns a slice that OUTLIVES the `Items` it came from, after taking a
// `&mut` borrow of that same `Items` in between, which a `&self`-elided
// `input()` could not satisfy. The pump needs exactly this to re-slice from
// borrow-free offsets while still holding `&mut self`.
#[test]
fn the_input_slice_outlives_the_iterator_it_came_from() {
  fn drive<'a>(mut items: Items<'a, '_>) -> &'a [u8] {
    while items.next().unwrap().is_some() {}
    items.input()
  }

  let mut connection = Connection::<Server, General>::new();
  let held = drive(connection.handle(REQUEST));
  assert!(core::ptr::eq(held, REQUEST));
}

// The same property for a YIELDED item, which is what the connection's own tests
// depend on: they hold a `view` across later `next()` calls, so `next` must
// return `Item<'a>` and not a lending `Item<'_>`. `hold` is the proof — the item
// survives further `&mut items` borrows AND outlives `items` itself, and its
// borrowed head is still readable afterwards.
#[test]
fn a_yielded_item_survives_later_next_calls_and_the_iterator() {
  fn hold<'a>(mut items: Items<'a, '_>) -> Option<Item<'a>> {
    let held = items.next().unwrap();
    while items.next().unwrap().is_some() {}
    held
  }

  let mut connection = Connection::<Server, General>::new();
  let Some(Item::Head { view, .. }) = hold(connection.handle(REQUEST)) else {
    panic!("expected the request head")
  };
  assert_eq!(view.header("host"), Some(b"example.com".as_slice()));
}

/// Renderings that format into a `String`: gated to the tiers that have a heap,
/// since the bare `no_std` tier has neither an allocator nor the
/// `alloc as std` alias.
#[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
mod heap {
  use crate::{
    event::*,
    head::{scan::scan_head, status_line::parse_status_line},
  };

  // A driver's trace line has to say WHICH exchange an item belongs to and what
  // kind it is, so both survive `Debug`. The RFC 9110 §15.2.1 interim flag is
  // part of that: in a trace it is the only thing separating a 1xx head from the
  // final one.
  #[test]
  fn items_and_events_render_their_exchange_and_kind() {
    let exchange = ExchangeId::new(9);
    assert_eq!(std::format!("{exchange:?}"), "ExchangeId(9)");

    let view = scan_head(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
    let head = std::format!(
      "{:?}",
      Item::Head {
        exchange,
        view,
        line: StartLine::Status(parse_status_line(view.start_line_bytes()).unwrap()),
        interim: true,
      }
    );
    assert!(head.starts_with("Head {"), "{head}");
    assert!(head.contains("ExchangeId(9)"), "{head}");
    assert!(head.contains("interim: true"), "{head}");
    // A trace line has to say WHICH message, not only which exchange.
    assert!(head.contains("code: 100"), "{head}");

    assert_eq!(
      std::format!("{:?}", Item::ExchangeComplete { exchange }),
      "ExchangeComplete { exchange: ExchangeId(9) }"
    );
    assert_eq!(
      std::format!(
        "{:?}",
        Item::Trailer {
          exchange,
          name: "X-Sum",
          value: b"1",
        }
      ),
      "Trailer { exchange: ExchangeId(9), name: \"X-Sum\", value: [49] }"
    );
  }
}
