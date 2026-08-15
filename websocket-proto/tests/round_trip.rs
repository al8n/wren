//! Self-interop round-trip properties: **everything this crate can emit, its
//! own strict parsers must accept.**
//!
//! The failure class these close is the emitters and the validators drifting
//! apart: a response suppressing the `server_max_window_bits=15` echo the
//! client parser demands; extra-header and managed field values carrying
//! control bytes the inbound parser screens. Stated as properties rather than
//! as the examples that exposed them, so any generator/validator divergence on
//! a representable configuration fails here rather than waiting to be sampled.
//!
//! Two properties reach one step further, to what a CONFORMING PEER may write
//! that this crate does not: a `Sec-WebSocket-Extensions` list split over field
//! lines (RFC 6455 §9.1, RFC 9110 §5.2) and interim responses ahead of the
//! switch (RFC 9110 §15.2). Neither is reachable from this crate's own
//! encoders, so each builds that half of the exchange by hand and drives the
//! other half — the peer's message is still answered by real machinery, never
//! compared against expected bytes.

#![cfg(feature = "std")]

use proptest::{prelude::*, test_runner::TestCaseError};
use websocket_proto::{
  Negotiated,
  handshake::{
    ExtraHeaders,
    connect::{
      ConnectAccept, ConnectRequest, Scheme, validate_connect_request, validate_connect_response,
    },
    h1::{
      Accept, ClientHandshake, ClientOptions, ClientProgress, Rejection, ServerHandshake,
      ServerProgress,
    },
  },
};

/// Deterministic seeded RNG (xorshift mix) — `TryRng<Error = Infallible>`
/// picks up the blanket infallible `Rng` impl the handshake requires.
struct TestRng(u64);

impl rand_core::TryRng for TestRng {
  type Error = core::convert::Infallible;
  fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
    let mut b = [0u8; 4];
    self.try_fill_bytes(&mut b)?;
    Ok(u32::from_le_bytes(b))
  }
  fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
    let mut b = [0u8; 8];
    self.try_fill_bytes(&mut b)?;
    Ok(u64::from_le_bytes(b))
  }
  fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
    for d in dest {
      self.0 ^= self.0 << 13;
      self.0 ^= self.0 >> 7;
      self.0 ^= self.0 << 17;
      *d = (self.0 & 0xFF) as u8;
    }
    Ok(())
  }
}

/// A minimal conforming upgrade request (RFC 6455 §4.1), for the properties
/// that exercise an answer rather than the request that provoked it.
const UPGRADE_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\r\n";

fn host_strategy() -> impl Strategy<Value = String> {
  proptest::string::string_regex("[a-z0-9.-]{1,20}(:[0-9]{1,5})?").unwrap()
}

fn path_strategy() -> impl Strategy<Value = String> {
  // Origin-form path + optional query, all bytes inside the RFC 3986
  // grammar (no `%` so we need no escape pairing; `%XX` is covered by a
  // dedicated case in the unit tests).
  proptest::string::string_regex(
    "/[a-zA-Z0-9._~!$&'()*+,;=:@/-]{0,24}(\\?[a-zA-Z0-9=&._~-]{0,16})?",
  )
  .unwrap()
}

fn token_strategy() -> impl Strategy<Value = String> {
  proptest::string::string_regex("[a-zA-Z0-9!#$%&'*+._`|~^-]{1,12}").unwrap()
}

fn subprotocols_strategy() -> impl Strategy<Value = Vec<String>> {
  proptest::collection::vec(token_strategy(), 0..3).prop_map(|mut v| {
    v.sort();
    v.dedup(); // the builders enforce RFC 6455 §4.1 uniqueness
    v
  })
}

/// Extra-header lists every property must be able to encode.
///
/// A repeated draw is kept rather than deduplicated: `ExtraHeaders::validate`
/// refuses a repeat only for the names this crate resolves as singletons, and an
/// `x-` name is none of them — so a repeated draw is still an option set that
/// must encode, and the properties carry one end to end. The refusals are
/// asserted by name in `an_extra_header_may_not_repeat_a_singleton_field_name`
/// and enumerated by `what_the_client_emits_our_own_server_accepts`.
fn extras_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
  proptest::collection::vec(
    (
      // `x-` prefix can never collide with a managed header name.
      proptest::string::string_regex("x-[a-z0-9-]{1,10}").unwrap(),
      // Field-value grammar: printable ASCII + SP/HTAB.
      proptest::string::string_regex("[ -~\t]{0,16}").unwrap(),
    ),
    0..3,
  )
}

#[cfg(feature = "deflate")]
fn offer_strategy() -> impl Strategy<Value = websocket_proto::negotiation::DeflateOffer> {
  use websocket_proto::negotiation::DeflateOffer;
  // DELIBERATELY includes out-of-range bits (0..=20): the property asserts
  // the public emitter REFUSES those configs — an in-range-only strategy
  // would never sample the unvalidated write path.
  (
    any::<bool>(),
    any::<bool>(),
    proptest::option::of(0u8..=20),
    proptest::option::of(0u8..=20),
    any::<bool>(),
  )
    .prop_map(|(snct, cnct, server_bits, client_bits, offer_cmwb)| {
      let mut offer = DeflateOffer::new()
        .with_server_no_context_takeover(snct)
        .with_client_no_context_takeover(cnct)
        .with_server_max_window_bits(server_bits);
      offer = match client_bits {
        // A client hint implies offering the parameter.
        Some(bits) => offer.with_client_max_window_bits(Some(bits)),
        None if offer_cmwb => offer,
        None => offer.without_client_max_window_bits(),
      };
      offer
    })
}

/// One whole h1 handshake — our request, our server's answer, our client
/// reading it — with `interims` interim responses wedged in front of the 101,
/// answering with what the client negotiated.
///
/// The interim heads are prepended to the SAME buffer the switch arrives in,
/// because that is how they reach a real driver: one read can carry every
/// interim response and the final answer behind them.
fn handshake_behind_interims<'a>(
  host: &'a str,
  offered: &'a [&'a str],
  chosen: Option<&'a str>,
  seed: u64,
  interims: usize,
) -> Result<Negotiated, TestCaseError> {
  let options = ClientOptions::new(host, "/chat").with_subprotocols(offered);
  let mut client = ClientHandshake::new(options, &mut TestRng(seed | 1))
    .expect("every generated option set is valid to emit");
  let mut request = [0u8; 2048];
  let n = client
    .encode_request(&mut request)
    .expect("request encodes");

  let mut server = ServerHandshake::new();
  {
    let progress = server
      .handle(&request[..n])
      .expect("our request passes our gate");
    let ServerProgress::Upgrade(mut pending) = progress else {
      panic!("complete head")
    };
    pending
      .validate_accept(&Accept::new().with_subprotocol(chosen))
      .expect("our acceptance answers our own request");
  }
  let mut response = [0u8; 2048];
  let (n, _) = server
    .encode_response(&ExtraHeaders::new(), &mut response)
    .expect("our acceptance encodes");

  let mut buffer = Vec::new();
  for _ in 0..interims {
    buffer.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
  }
  buffer.extend_from_slice(&response[..n]);

  let mut offset = 0;
  // One turn per interim head plus one for the switch. The bound is what makes
  // a client that does not advance past an interim response a FAILURE here
  // rather than a hang: re-offering the same bytes is the read-it-forever loop
  // `ClientProgress::Interim`'s offset exists to prevent.
  for _ in 0..=interims {
    match client
      .handle(&buffer[offset..])
      .expect("an interim response is not a fault")
    {
      ClientProgress::Interim { status, consumed } => {
        prop_assert_eq!(status, 100);
        prop_assert!(consumed > 0, "an interim that consumes nothing is re-read");
        offset += consumed;
      }
      ClientProgress::Complete(complete) => {
        prop_assert_eq!(
          offset + complete.consumed(),
          buffer.len(),
          "the switch ends the last head in the buffer"
        );
        return Ok(complete.into_negotiated());
      }
      other => panic!("neither an interim nor the switch: {other:?}"),
    }
  }
  Err(TestCaseError::fail(
    "the switch never arrived behind the interim responses",
  ))
}

proptest! {
  #![proptest_config(ProptestConfig::with_cases(64))]

  /// The full h1 handshake, both directions: our request through our server
  /// gate, our acceptance through our client validation.
  #[test]
  fn h1_handshake_round_trips(
    host in host_strategy(),
    path in path_strategy(),
    subprotocols in subprotocols_strategy(),
    extras in extras_strategy(),
    seed in any::<u64>(),
    pick in any::<prop::sample::Index>(),
  ) {
    let offered: Vec<&str> = subprotocols.iter().map(String::as_str).collect();
    let extra_pairs: Vec<(&str, &str)> =
      extras.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();

    let options = ClientOptions::new(&host, &path)
      .with_subprotocols(&offered)
      .with_extra_headers(extra_pairs.as_slice());
    let mut client = ClientHandshake::new(options, &mut TestRng(seed | 1))
      .expect("every generated option set is valid to emit");

    let mut request = [0u8; 4096];
    let n = client.encode_request(&mut request).expect("request encodes");

    let mut server = ServerHandshake::new();
    // Everything the answer depends on is settled WHILE the request is
    // borrowed: the pending upgrade does not survive this block, and what it
    // settled — held inside the handshake, where no other handshake can reach
    // it — does.
    let chosen = (!offered.is_empty()).then(|| offered[pick.index(offered.len())]);
    {
      let progress = server.handle(&request[..n]).expect("our request passes our gate");
      let ServerProgress::Upgrade(mut pending) = progress else {
        panic!("complete head")
      };
      prop_assert_eq!(pending.request().host(), host.as_str());
      prop_assert!(
        pending.leftover().is_empty(),
        "the request head is the whole message"
      );

      // Accept with one of the client's own offers (when any).
      let accept = Accept::new().with_subprotocol(chosen);
      pending
        .validate_accept(&accept)
        .expect("our acceptance answers our own request");
    }

    // The server's own extras are NOT request-bound, so they join the answer
    // here rather than at validation — the `x-` names the strategy draws can
    // never collide with a managed field, so every draw must encode.
    let mut response = [0u8; 2048];
    let (n, negotiated) = server
      .encode_response(&ExtraHeaders::from(extra_pairs.as_slice()), &mut response)
      .expect("our acceptance encodes");
    prop_assert_eq!(negotiated.subprotocol(), chosen);
    let head = core::str::from_utf8(&response[..n]).expect("the head is ASCII");
    for (name, value) in &extra_pairs {
      prop_assert!(head.contains(&format!("\r\n{name}: {value}\r\n")), "{head}");
    }

    match client.handle(&response[..n]).expect("our response passes our client") {
      ClientProgress::Complete(complete) => {
        prop_assert_eq!(complete.negotiated().subprotocol(), chosen);
      }
      _ => panic!("complete response head"),
    }
  }

  /// Every encodable rejection parses back as an HTTP head.
  #[test]
  fn rejections_round_trip(
    status in 300u16..=599,
    reason in proptest::string::string_regex("[ -~\t]{0,24}").unwrap(),
    extras in extras_strategy(),
  ) {
    let extra_pairs: Vec<(&str, &str)> =
      extras.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    let rejection = Rejection::new(status, &reason).with_extra_headers(extra_pairs.as_slice());

    // A rejection ANSWERS a request, so one has to have arrived: the tunnel
    // connection has nothing to refuse before it has classified something.
    let mut server = ServerHandshake::new();
    let progress = server.handle(UPGRADE_REQUEST).expect("the fixture classifies");
    let classified = matches!(progress, ServerProgress::Upgrade { .. });
    prop_assert!(classified, "the fixture is an upgrade request");

    let mut out = [0u8; 2048];
    let n = server
      .encode_rejection(&rejection, &mut out)
      .expect("our rejection encodes");

    // A client must at least parse the head and see the status we set. Its own
    // request has to go out first: the tunnel connection reads a response only
    // for a handshake it opened.
    let options = ClientOptions::new("h", "/");
    let mut client = ClientHandshake::new(options, &mut TestRng(7)).unwrap();
    let mut request = [0u8; 1024];
    client.encode_request(&mut request).expect("request encodes");
    let progress = client.handle(&out[..n]).expect("a refusal is an answer, not a fault");
    let ClientProgress::Refused { status: seen, consumed } = progress else {
      panic!("a non-101 answer is a refusal")
    };
    prop_assert_eq!(seen, status);
    // RFC 6455 §4.1 sends the caller back to "HTTP procedures", which read the
    // refusal's FIELDS: the offset has to delimit the head we wrote, so every
    // extra header on it is still there to be found.
    prop_assert_eq!(consumed, n, "the refusal head is the whole message");
    let head = &out[..consumed];
    for (name, _) in &extra_pairs {
      prop_assert!(
        head.windows(name.len()).any(|w| w.eq_ignore_ascii_case(name.as_bytes())),
        "{name} is missing from the head the client handed back"
      );
    }
  }

  /// Extended CONNECT, both directions: our request headers through our
  /// gate, our acceptance headers through our response validation.
  #[test]
  fn connect_round_trips(
    https in any::<bool>(),
    authority in host_strategy(),
    path in path_strategy(),
    subprotocols in subprotocols_strategy(),
    pick in any::<prop::sample::Index>(),
  ) {
    let offered: Vec<&str> = subprotocols.iter().map(String::as_str).collect();
    let scheme = if https { Scheme::Https } else { Scheme::Http };
    let request = ConnectRequest::new(scheme, &authority, &path).with_subprotocols(&offered);

    let headers = request.headers().expect("every generated request is valid to emit");
    let pairs: Vec<(&str, &str)> = headers.iter().collect();
    let view = validate_connect_request(&pairs).expect("our request passes our gate");
    let got: Vec<&str> = view.subprotocols().collect();
    prop_assert_eq!(&got, &offered);

    let chosen = (!offered.is_empty()).then(|| offered[pick.index(offered.len())]);
    let accept = ConnectAccept::new().with_subprotocol(chosen);
    let (accept_headers, server_negotiated) =
      accept.headers_for(&view).expect("our acceptance encodes");
    let accept_pairs: Vec<(&str, &str)> = accept_headers.iter().collect();

    let negotiated =
      validate_connect_response(&accept_pairs, &request).expect("our response validates");
    prop_assert_eq!(negotiated.subprotocol(), chosen);
    prop_assert_eq!(server_negotiated.subprotocol(), chosen);
  }

  /// RFC 9110 §15.2 lets ANY number of interim responses precede the final one,
  /// and RFC 6455 puts no bound of its own on them: a handshake behind `n` of
  /// them must negotiate exactly what the same handshake behind none did.
  ///
  /// The count is generated rather than fixed because the failure modes differ
  /// by arity — none at all, one, and a run of them each exercise a different
  /// path through the client's advance.
  #[test]
  fn interim_responses_before_the_switch_do_not_disturb_the_handshake(
    interims in 0usize..4,
    host in host_strategy(),
    subprotocols in subprotocols_strategy(),
    seed in any::<u64>(),
    pick in any::<prop::sample::Index>(),
  ) {
    let offered: Vec<&str> = subprotocols.iter().map(String::as_str).collect();
    let chosen = (!offered.is_empty()).then(|| offered[pick.index(offered.len())]);

    let baseline = handshake_behind_interims(&host, &offered, chosen, seed, 0)?;
    let behind = handshake_behind_interims(&host, &offered, chosen, seed, interims)?;

    prop_assert_eq!(baseline.subprotocol(), chosen);
    prop_assert_eq!(behind, baseline, "{} interim responses changed the answer", interims);
  }
}

#[cfg(feature = "deflate")]
proptest! {
  #![proptest_config(ProptestConfig::with_cases(128))]

  /// The pure negotiation loop (the explicit-15 echo class): any offer we
  /// can write, accepted by our server, must produce a response our client
  /// parser agrees with — and both sides must agree on the parameters.
  #[test]
  fn deflate_negotiation_round_trips(
    offer in offer_strategy(),
    require_cnct in any::<bool>(),
    server_snct in any::<bool>(),
  ) {
    use websocket_proto::negotiation::{
      ServerDeflateConfig, accept_deflate_offer, extension_list_conforms, parse_deflate_response,
    };

    let mut offer_buf = [0u8; 160];
    // An invalid config must be an ERROR at the emitter, never wire bytes.
    if offer.validate().is_err() {
      prop_assert!(offer.write(&mut offer_buf).is_err());
      return Ok(());
    }
    let n = offer.write(&mut offer_buf).expect("offer renders");
    let offer_value = core::str::from_utf8(&offer_buf[..n]).unwrap();
    // The RFC 6455 §9.1 gate stands in front of every read of this field, so a
    // value this crate EMITS that the gate refuses would be a handshake it
    // fails against itself.
    prop_assert!(
      extension_list_conforms([offer_value.as_bytes()]),
      "{offer_value}"
    );

    let config = ServerDeflateConfig::new()
      .with_require_client_no_context_takeover(require_cnct)
      .with_server_no_context_takeover(server_snct);
    let accepted = accept_deflate_offer([offer_value.as_bytes()], &config);
    // A sub-15 server-window demand is DECLINED (miniz cannot bound its
    // compressor, so granting would break every compressed send) — the
    // handshake then proceeds without the extension.
    if offer_value.contains("server_max_window_bits=")
      && !offer_value.contains("server_max_window_bits=15")
    {
      prop_assert!(accepted.is_none(), "{offer_value}");
      return Ok(());
    }
    let (server_params, response) =
      accepted.expect("our server accepts every honorable offer we can render");

    let mut resp_buf = [0u8; 160];
    let n = response.write(&mut resp_buf).expect("response renders");
    let resp_value = core::str::from_utf8(&resp_buf[..n]).unwrap();
    prop_assert!(
      extension_list_conforms([resp_value.as_bytes()]),
      "{resp_value}"
    );

    let client_params = parse_deflate_response([resp_value.as_bytes()], &offer)
      .expect("our client accepts our server's response");
    prop_assert_eq!(client_params, server_params);
  }

  /// RFC 6455 §9.1 permits a client to split `Sec-WebSocket-Extensions` over
  /// several field lines, and RFC 9110 §5.2 makes those lines one comma-joined
  /// value. A server that read only the first line would silently drop every
  /// offer behind it — and answer without the extension the client asked for.
  ///
  /// The request is written by hand because OUR client encoder emits a single
  /// line: the peer that splits is a conforming peer this crate is not, so the
  /// round trip is its request through our server, and our server's grant back
  /// through our client. The key is our client's own, which is what lets the
  /// second half run.
  #[test]
  fn an_extension_list_split_across_field_lines_is_read_as_one(
    lead in token_strategy(),
    host in host_strategy(),
    path in path_strategy(),
    seed in any::<u64>(),
  ) {
    use websocket_proto::negotiation::{DeflateOffer, ServerDeflateConfig, accept_deflate_offer};

    let offer = DeflateOffer::new();
    let options = ClientOptions::new(&host, &path).with_deflate(offer);
    let mut client = ClientHandshake::new(options, &mut TestRng(seed | 1))
      .expect("every generated option set is valid to emit");
    // Opens the handshake the answer is read against; the bytes go unused
    // because the request on the wire is the hand-written split one below.
    let mut unsent = [0u8; 2048];
    client.encode_request(&mut unsent).expect("request encodes");

    // The second line carries exactly what our own client would have offered,
    // so the grant it provokes is one our client must accept.
    let mut offer_buf = [0u8; 160];
    let n = offer.write(&mut offer_buf).expect("the default offer renders");
    let offer_value = core::str::from_utf8(&offer_buf[..n]).expect("the offer is ASCII");
    let key = core::str::from_utf8(client.key()).expect("base64 is ASCII");
    // `lead` is a token of at most 12 bytes, so the first line can never be the
    // 18-byte `permessage-deflate` the second one carries.
    let split = format!(
      "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n\
       Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n\
       Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: {lead}\r\n\
       Sec-WebSocket-Extensions: {offer_value}\r\n\r\n"
    );

    let mut server = ServerHandshake::new();
    let server_params = {
      let progress = server.handle(split.as_bytes()).expect("a split section is one request");
      let ServerProgress::Upgrade(mut pending) = progress else {
        panic!("complete head")
      };
      prop_assert!(
        pending.leftover().is_empty(),
        "the request head is the whole message"
      );
      let (params, response) =
        accept_deflate_offer(pending.request().extensions(), &ServerDeflateConfig::new())
          .expect("the offer on the SECOND field line is still an offer");
      pending
        .validate_accept(&Accept::new().with_deflate(Some(response)))
        .expect("granting the request's own offer");
      params
    };

    let mut response = [0u8; 2048];
    let (n, negotiated) = server
      .encode_response(&ExtraHeaders::new(), &mut response)
      .expect("our grant encodes");
    prop_assert_eq!(negotiated.deflate(), Some(server_params));
    match client.handle(&response[..n]).expect("our response passes our client") {
      ClientProgress::Complete(complete) => {
        prop_assert_eq!(complete.negotiated().deflate(), Some(server_params));
      }
      other => panic!("complete response head: {other:?}"),
    }
  }
}

/// **The class, mechanically: an extra header this client ENCODES is one this
/// crate's own server ACCEPTS.**
///
/// The escape hatch that extras are is exactly where the two sides can drift:
/// the names are the caller's, so nothing about them is request-bound and
/// nothing in the machine reads them back. A repeated `Origin` was the instance
/// — the client wrote two, and this crate's own server refused the request as a
/// duplicated singleton (RFC 6454 §7 gives `Origin` one `origin-list-or-null`,
/// so RFC 9110 §5.3 forbids repeating it).
///
/// The table below is the enumeration behind that fix rather than a sample: for
/// each candidate it records WHICH layer refuses it, and asserts the implication
/// `emitted ⟹ accepted`. `Content-Length: 5` and `Transfer-Encoding` are refused
/// by the HTTP layer beneath this crate (a handshake message carries no content,
/// so they never reach the wire); a repeated `Origin` by `ExtraHeaders::validate`;
/// everything else is emitted and read back.
///
/// The `EMITTED` rows carry the other half of the implication, and the reason the
/// screen is stated over the singletons instead of over every name: RFC 9110
/// §5.3 lets a sender repeat any field with a comma-list alternative, so
/// `Cache-Control` and `Via` — and any field this crate neither writes nor reads
/// — must stay writable twice. A screen that refused them would fail here rather
/// than satisfy the implication vacuously.
#[test]
fn what_the_client_emits_our_own_server_accepts() {
  /// Every candidate a caller could plausibly inject, with WHICH layer refuses
  /// it — pinned, so an over-broad screen that stopped emitting everything would
  /// fail here instead of satisfying the implication vacuously.
  const EMITTED: &str = "emitted, and our own server accepted it";
  const REPEATED: &str = "refused by the extras screen (a repeated singleton)";
  const NO_CONTENT: &str = "refused by the HTTP layer (a handshake carries no content)";
  /// What the case is called, the extras it injects, and the expected verdict.
  type Candidate = (
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static str,
  );
  const CANDIDATES: &[Candidate] = &[
    ("one Origin", &[("Origin", "http://a.example")], EMITTED),
    (
      "two Origins",
      &[
        ("Origin", "http://a.example"),
        ("Origin", "http://evil.example"),
      ],
      REPEATED,
    ),
    (
      "two Origins, mixed case",
      &[("origin", "http://a.example"), ("ORIGIN", "http://evil")],
      REPEATED,
    ),
    ("Content-Length: 0", &[("Content-Length", "0")], EMITTED),
    ("Content-Length: 5", &[("Content-Length", "5")], NO_CONTENT),
    (
      // The second line is content the handshake message has no room for, so
      // the framing layer refuses it — not the name screen, which does not own
      // `Content-Length` and does not decide its cardinality.
      "two Content-Lengths",
      &[("Content-Length", "0"), ("Content-Length", "1")],
      NO_CONTENT,
    ),
    (
      "Transfer-Encoding",
      &[("Transfer-Encoding", "chunked")],
      NO_CONTENT,
    ),
    ("Expect", &[("Expect", "100-continue")], NO_CONTENT),
    (
      "two Authorizations",
      &[("Authorization", "Bearer a"), ("Authorization", "Bearer b")],
      EMITTED,
    ),
    (
      "two Cookies",
      &[("Cookie", "a=1"), ("Cookie", "b=2")],
      EMITTED,
    ),
    (
      "two Content-Types",
      &[
        ("Content-Type", "text/plain"),
        ("Content-Type", "text/html"),
      ],
      EMITTED,
    ),
    ("two Dates", &[("Date", "a"), ("Date", "b")], EMITTED),
    (
      "two Referers",
      &[("Referer", "http://a"), ("Referer", "http://b")],
      EMITTED,
    ),
    (
      "two Max-Forwards",
      &[("Max-Forwards", "1"), ("Max-Forwards", "2")],
      EMITTED,
    ),
    (
      // RFC 9111 §5.2: `Cache-Control = #cache-directive`, so §5.3's comma-list
      // exception is this field's, and a screen that refused it would be wrong.
      "two Cache-Controls",
      &[("Cache-Control", "no-store"), ("Cache-Control", "no-cache")],
      EMITTED,
    ),
    (
      // RFC 9110 §7.6.3: `Via = #( received-protocol RWS received-by …)`, and a
      // request that crossed two proxies carries exactly this.
      "two Vias",
      &[("Via", "1.1 alpha"), ("Via", "1.1 beta")],
      EMITTED,
    ),
    (
      "two X-Traces",
      &[("X-Trace", "a"), ("X-Trace", "b")],
      EMITTED,
    ),
    ("TE: trailers", &[("TE", "trailers")], EMITTED),
    ("Trailer", &[("Trailer", "X-Late")], EMITTED),
    (
      "Cookie and Authorization",
      &[("Cookie", "a=1"), ("Authorization", "Bearer t")],
      EMITTED,
    ),
    (
      "two WWW-Authenticates (repeatable by §11.6.1)",
      &[
        ("WWW-Authenticate", "Basic realm=\"a\""),
        ("WWW-Authenticate", "Newauth realm=\"b\""),
      ],
      EMITTED,
    ),
  ];

  for (what, extras, expected) in CANDIDATES {
    let options = ClientOptions::new("h", "/chat").with_extra_headers(*extras);
    let verdict = match ClientHandshake::new(options, &mut TestRng(0xA11CE)) {
      Err(_) => REPEATED,
      Ok(mut client) => {
        let mut request = [0u8; 4096];
        match client.encode_request(&mut request) {
          Err(_) => NO_CONTENT,
          Ok(n) => {
            let mut server = ServerHandshake::new();
            let progress = server.handle(&request[..n]);
            // The property itself: emitted implies accepted.
            assert!(
              matches!(progress, Ok(ServerProgress::Upgrade(_))),
              "our client emitted {what:?} and our own server refused it: {progress:?}"
            );
            EMITTED
          }
        }
      }
    };
    assert_eq!(verdict, *expected, "{what}");
  }
}

/// The offer-count bound is the same number on both sides of both transports,
/// so no configuration this crate can emit is one it refuses to read.
#[test]
fn the_offer_count_bound_is_symmetric_on_both_transports() {
  use websocket_proto::negotiation::MAX_SUBPROTOCOL_OFFERS;

  let names: Vec<String> = (0..=MAX_SUBPROTOCOL_OFFERS)
    .map(|i| format!("p{i}"))
    .collect();
  let all: Vec<&str> = names.iter().map(String::as_str).collect();
  let at_cap = all.get(..MAX_SUBPROTOCOL_OFFERS).unwrap();

  // h1: the cap encodes and reads back.
  let options = ClientOptions::new("h", "/chat").with_subprotocols(at_cap);
  let mut client = ClientHandshake::new(options, &mut TestRng(7)).expect("the cap is writable");
  let mut request = [0u8; 4096];
  let n = client
    .encode_request(&mut request)
    .expect("request encodes");
  let mut server = ServerHandshake::new();
  let ServerProgress::Upgrade(pending) = server
    .handle(&request[..n])
    .expect("what our client writes, our server reads")
  else {
    panic!("complete head")
  };
  assert_eq!(
    pending.request().subprotocols().count(),
    MAX_SUBPROTOCOL_OFFERS
  );

  // h1: one past it never reaches the wire.
  let options = ClientOptions::new("h", "/chat").with_subprotocols(&all);
  assert!(ClientHandshake::new(options, &mut TestRng(7)).is_err());

  // Extended CONNECT: the same two answers, from the same constant.
  let request = ConnectRequest::new(Scheme::Https, "h", "/chat").with_subprotocols(at_cap);
  let headers = request.headers().expect("the cap is writable");
  let pairs: Vec<(&str, &str)> = headers.iter().collect();
  let view = validate_connect_request(&pairs).expect("what we emit, we read");
  assert_eq!(view.subprotocols().count(), MAX_SUBPROTOCOL_OFFERS);
  assert!(
    ConnectRequest::new(Scheme::Https, "h", "/chat")
      .with_subprotocols(&all)
      .headers()
      .is_err()
  );
}

/// Sixty subprotocol offers reach this crate's own server.
///
/// Regression, and the arithmetic is the whole of it: emitting the offers as one
/// field LINE each puts sixty-five lines in the head for sixty offers, and
/// `http1-proto` — the head scanner behind `ServerHandshake` and behind both
/// drivers — refuses a head past `MAX_HEADERS = 64`, so the configuration fails
/// on every path. RFC 6455 §4.1 item 10 spells the offer as "one or more
/// comma-separated subprotocol", and that is what goes out: one field line, so
/// the count of offers does not decide the count of lines.
#[test]
fn sixty_subprotocol_offers_round_trip_through_our_own_server() {
  let names: Vec<String> = (0..60).map(|i| format!("p{i}")).collect();
  let offered: Vec<&str> = names.iter().map(String::as_str).collect();

  let options = ClientOptions::new("example.com", "/chat").with_subprotocols(&offered);
  let mut client =
    ClientHandshake::new(options, &mut TestRng(0xC0FF_EE01)).expect("sixty short offers fit");

  let mut request = [0u8; 4096];
  let n = client
    .encode_request(&mut request)
    .expect("request encodes");
  let head = core::str::from_utf8(&request[..n]).expect("the head is ASCII");
  assert_eq!(
    head.matches("Sec-WebSocket-Protocol").count(),
    1,
    "one field line, whatever the offer count: {head}"
  );
  // Five managed lines plus one for the offers — a line per offer would be 65,
  // one past what a conforming peer reads.
  assert_eq!(head.matches("\r\n").count() - 2, 6, "{head}");

  let mut server = ServerHandshake::new();
  // The last offer, so a server reading only the first element would not find
  // it.
  let chosen = offered.last().copied();
  {
    let ServerProgress::Upgrade(mut pending) = server
      .handle(&request[..n])
      .expect("sixty offers in one line is a head our own server reads")
    else {
      panic!("complete head")
    };
    assert_eq!(pending.request().subprotocols().count(), 60);
    pending
      .validate_accept(&Accept::new().with_subprotocol(chosen))
      .expect("the last offer is one this request made");
  }

  let mut response = [0u8; 2048];
  let (n, negotiated) = server
    .encode_response(&ExtraHeaders::new(), &mut response)
    .expect("our acceptance encodes");
  assert_eq!(negotiated.subprotocol(), chosen);
  match client
    .handle(&response[..n])
    .expect("our response passes our client")
  {
    ClientProgress::Complete(complete) => {
      assert_eq!(complete.negotiated().subprotocol(), chosen);
    }
    other => panic!("complete response head: {other:?}"),
  }
}
