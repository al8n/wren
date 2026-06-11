//! Self-interop round-trip properties: **everything this crate can emit, its
//! own strict parsers must accept.**
//!
//! Three adversarial-review findings were instances of one class — the
//! emitters and the validators drifting apart (a response suppressing the
//! `server_max_window_bits=15` echo the client parser demands; extra-header
//! and managed field values carrying control bytes the inbound parser
//! screens). These properties close that class by construction: any
//! generator/validator divergence on a representable configuration fails
//! here, instead of waiting for a review round to sample it.

#![cfg(feature = "std")]

use proptest::prelude::*;
use websocket_proto::handshake::{
  connect::{
    ConnectAccept, ConnectRequest, Scheme, validate_connect_request, validate_connect_response,
  },
  h1::{
    Accept, ClientHandshake, ClientOptions, ClientProgress, Rejection, ServerHandshake,
    ServerProgress,
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
  // the public emitter REFUSES those configs (Codex R17 found the previous
  // in-range-only strategy never sampled the unvalidated write path).
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
    let client = ClientHandshake::new(options, &mut TestRng(seed | 1))
      .expect("every generated option set is valid to emit");

    let mut request = [0u8; 4096];
    let n = client.encode_request(&mut request).expect("request encodes");

    let server = ServerHandshake::new();
    let view = match server.handle(&request[..n]).expect("our request passes our gate") {
      ServerProgress::Request(view) => view,
      _ => panic!("complete head"),
    };
    prop_assert_eq!(view.host(), host.as_str());

    // Accept with one of the client's own offers (when any).
    let chosen = (!offered.is_empty()).then(|| offered[pick.index(offered.len())]);
    let accept = Accept::new().with_subprotocol(chosen);

    let mut response = [0u8; 2048];
    let (n, negotiated) = server
      .encode_response(&view, &accept, &mut response)
      .expect("our acceptance encodes");
    prop_assert_eq!(negotiated.subprotocol(), chosen);

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

    let mut out = [0u8; 2048];
    let n = ServerHandshake::new()
      .encode_rejection(&rejection, &mut out)
      .expect("our rejection encodes");

    // A client must at least parse the head and see the status we set.
    let options = ClientOptions::new("h", "/");
    let client = ClientHandshake::new(options, &mut TestRng(7)).unwrap();
    let err = client.handle(&out[..n]).expect_err("non-101 fails the upgrade");
    prop_assert!(
      format!("{err}").contains(&status.to_string()),
      "expected UnexpectedStatus({status}), got {err}"
    );
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
      ServerDeflateConfig, accept_deflate_offer, parse_deflate_response,
    };

    let mut offer_buf = [0u8; 160];
    // An invalid config must be an ERROR at the emitter, never wire bytes.
    if offer.validate().is_err() {
      prop_assert!(offer.write(&mut offer_buf).is_err());
      return Ok(());
    }
    let n = offer.write(&mut offer_buf).expect("offer renders");
    let offer_value = core::str::from_utf8(&offer_buf[..n]).unwrap();

    let config = ServerDeflateConfig::new()
      .with_require_client_no_context_takeover(require_cnct)
      .with_server_no_context_takeover(server_snct);
    let (server_params, response) =
      accept_deflate_offer([offer_value].into_iter(), &config)
        .expect("our server accepts every offer we can render");

    let mut resp_buf = [0u8; 160];
    let n = response.write(&mut resp_buf).expect("response renders");
    let resp_value = core::str::from_utf8(&resp_buf[..n]).unwrap();

    let client_params = parse_deflate_response(resp_value, &offer)
      .expect("our client accepts our server's response");
    prop_assert_eq!(client_params, server_params);
  }
}
