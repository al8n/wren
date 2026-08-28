//! The differential corpus for `websocket-proto`'s handshake surfaces: one
//! record per case, naming the verdict THIS build reaches for it.
//!
//! Run it at two revisions and diff the records and you have answered the only
//! question a handshake refactor owes: *did this change move a verdict, and was
//! it one that should have moved?* That is what
//! `cargo run -p xtask -- handshake-diff <base> [head]` does — see
//! `xtask/src/handshake_diff.rs`.
//!
//! # Contract
//!
//! Every record is one line of six tab-separated columns:
//!
//! ```text
//! role <TAB> field <TAB> case <TAB> equivalence-group <TAB> outcome <TAB> detail
//! ```
//!
//! - `role` — which surface answered: the h1 server, the h1 client, the
//!   extended-CONNECT gate on either side, or one of the two EMITTERS read back
//!   by this crate's own gate.
//! - `field` — the handshake field the case varies. `(role, field, case)` is the
//!   record's key and is unique.
//! - `equivalence-group` — a name when this case is one SPELLING of a logical
//!   value that other cases in the same `(role, field)` spell differently, `-`
//!   when it is not. Every member of a group must reach the identical verdict;
//!   see `is_role_singleton` for the one exception the roles themselves make (it
//!   is `deflate`-gated with the rest of the corpus, so it is named rather than
//!   linked).
//! - `outcome` — the verdict's variant path (`error/Http/TooManyHeaders`), which
//!   is what a moved verdict is grouped BY.
//! - `detail` — everything the surface resolved, so two cases compare equal only
//!   when the whole outcome does.
//!
//! # Two constraints this file is written under
//!
//! **Public API only**, and only the part of it the revisions being compared
//! SHARE. A corpus that reached into the crate would measure a private
//! reorganisation as a behaviour change, and one that named an item added by the
//! diff under test would not compile at the baseline. (`ConnectRequestView::origin`
//! is the live example: an accessor a revision under test may not have, so the
//! extended-CONNECT cases read the origin through the `header` escape hatch
//! instead — which is also the reading that can diverge from the accessor.)
//!
//! **One file.** `xtask` copies this source — from the WORKING TREE, never from
//! the revision under test — beside each revision's `websocket-proto`, so both
//! sides are measured by one corpus and only the crate under test changes.

// The corpus needs the permessage-deflate surface to say anything about
// `Sec-WebSocket-Extensions`, and that is the whole extension half of it. Rather
// than fragment every case with `cfg`, the crate has ONE feature boundary: with
// the feature it is the corpus, without it it is a message saying so.
#[cfg(not(feature = "deflate"))]
fn main() {
  eprintln!(
    "handshake-corpus needs the `deflate` feature: \
     cargo run -p handshake-corpus --features deflate"
  );
  std::process::exit(2);
}

#[cfg(feature = "deflate")]
fn main() {
  let mut sink = Sink::default();
  spelling_cases(&mut sink);
  repeated_singleton_cases(&mut sink);
  offer_sweep_cases(&mut sink);
  request_extras_cases(&mut sink);
  response_extras_cases(&mut sink);
  rejection_extras_cases(&mut sink);
  print!("{}", sink.out);
  eprintln!("handshake-corpus: {} cases", sink.cases);
}

#[cfg(feature = "deflate")]
use corpus::*;

#[cfg(feature = "deflate")]
mod corpus {
  use std::fmt::Write as _;
  use websocket_proto::{
    handshake::{
      ExtraHeaders,
      connect::{ConnectRequest, Scheme, validate_connect_request, validate_connect_response},
      h1::{
        Accept, ClientHandshake, ClientOptions, ClientProgress, Rejection, ServerHandshake,
        ServerProgress,
      },
    },
    negotiation::{DeflateOffer, ServerDeflateConfig, accept_deflate_offer},
  };

  // ───────────────────────────── record sink ──────────────────────────────

  /// A verdict: the variant path a surface answered with, and everything it
  /// resolved. Records compare equal only when BOTH halves do; the moved-verdict
  /// grouping reads the `outcome` alone.
  pub struct Verdict {
    outcome: String,
    detail: String,
  }

  impl Verdict {
    fn plain(outcome: &str, detail: String) -> Self {
      Self {
        outcome: outcome.to_owned(),
        detail,
      }
    }

    /// A verdict named by a `Debug` rendering: the variant path becomes the
    /// outcome and the whole rendering the detail.
    fn from_debug(kind: &str, debug: String) -> Self {
      Self {
        outcome: format!("{kind}/{}", variant_path(&debug)),
        detail: debug,
      }
    }
  }

  /// The variant path of a `Debug` rendering — `Http(TooManyHeaders(64))` gives
  /// `Http/TooManyHeaders`.
  ///
  /// Moved verdicts are grouped by the REASON they moved, and the reason is the
  /// variant rather than its payload: a bound that changed from 64 to 32 moves
  /// one number in a detail, not the answer the gate gave.
  fn variant_path(debug: &str) -> String {
    let mut path = String::new();
    for segment in debug.split('(') {
      let name: String = segment
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
      if !name.starts_with(|c: char| c.is_ascii_uppercase()) {
        break;
      }
      if !path.is_empty() {
        path.push('/');
      }
      path.push_str(&name);
    }
    if path.is_empty() {
      // Not an enum rendering (a `bool`, a message): the first word stands in.
      debug
        .split([' ', '(', '{', ':'])
        .next()
        .unwrap_or(debug)
        .to_owned()
    } else {
      path
    }
  }

  #[derive(Default)]
  pub struct Sink {
    pub out: String,
    pub cases: usize,
  }

  impl Sink {
    fn emit(&mut self, role: &str, field: &str, case: &str, group: Option<&str>, verdict: Verdict) {
      let group = group.unwrap_or("-");
      let _ = writeln!(
        self.out,
        "{role}\t{field}\t{case}\t{group}\t{}\t{}",
        verdict.outcome, verdict.detail
      );
      self.cases = self.cases.saturating_add(1);
    }
  }

  // ────────────────────────── spellings of one value ──────────────────────

  /// Every spelling of the one-element list `a`.
  ///
  /// RFC 9110 §5.2 makes the several lines of one field a single comma-joined
  /// value and §5.3 lets a sender split a list across them; RFC 2616 §2.1's
  /// `#rule` — the ABNF RFC 6455 states its grammars in, and RFC 822 §2.7's
  /// wording verbatim — adds that "null elements are allowed, but do not
  /// contribute to the count of elements present". So these are one value
  /// written nine ways.
  fn one(a: &str) -> Vec<Vec<String>> {
    vec![
      vec![a.into()],
      vec![format!("  {a}\t")],
      vec![format!(",{a}")],
      vec![format!("{a},")],
      vec![format!(" , {a} , ")],
      vec![String::new(), a.into()],
      vec![a.into(), String::new()],
      vec![String::new(), String::new(), a.into(), String::new()],
      vec![",".into(), a.into(), " , ".into()],
    ]
  }

  /// Every spelling of the two-element list `a, b`, in that order.
  fn two(a: &str, b: &str) -> Vec<Vec<String>> {
    vec![
      vec![format!("{a}, {b}")],
      vec![format!("{a},{b}")],
      vec![format!("  {a} ,\t{b}  ")],
      // RFC 6455 §9.1's own worked example: one line each.
      vec![a.into(), b.into()],
      vec![format!("{a},"), b.into()],
      vec![String::new(), format!("{a}, {b}")],
      vec![format!("{a}, {b}"), String::new()],
      vec![format!(" , {a} , , {b} , ")],
      vec![
        String::new(),
        a.into(),
        String::new(),
        b.into(),
        String::new(),
      ],
    ]
  }

  /// Every spelling of a field that is PRESENT and names nothing — a different
  /// logical value from an absent field and from any list above (RFC 9110
  /// §5.6.1.2 gives `""`, `","` and `",   ,"` as its own examples).
  fn nothing() -> Vec<Vec<String>> {
    vec![
      vec![String::new()],
      vec![" ".into()],
      vec!["\t".into()],
      vec![",".into()],
      vec![" , ".into()],
      vec![",,,".into()],
      vec![String::new(), String::new()],
      vec![String::new(), ",".into(), " ".into()],
    ]
  }

  /// Values that are NOT one logical value spelled several ways — each is its
  /// own input, and the group carries no equivalence claim.
  fn odd() -> Vec<Vec<String>> {
    vec![
      vec!["has space".into()],
      vec!["a, a".into()],
      vec!["x@y".into()],
      vec!["permessage-deflate;".into()],
      vec!["permessage-deflate;;x".into()],
      vec!["permessage-deflate; x=\"open".into()],
      vec!["null".into()],
    ]
  }

  /// The corpus's list-field groups. The `bool` is the equivalence claim: `true`
  /// when every spelling in the group is the same logical value.
  fn groups() -> Vec<(&'static str, bool, Vec<Vec<String>>)> {
    vec![
      ("one-chat", true, one("chat")),
      ("two-chat-super", true, two("chat", "superchat")),
      ("nothing", true, nothing()),
      ("one-pmd", true, one("permessage-deflate")),
      ("two-pmd-x", true, two("permessage-deflate", "x-private")),
      ("one-origin", true, one("https://example.com")),
      (
        "two-origins",
        true,
        two("https://example.com", "https://evil.example"),
      ),
      ("absent", true, vec![vec![]]),
      ("odd", false, odd()),
    ]
  }

  /// Whether `field` is a SINGLETON for `role` rather than a list — the one
  /// place the equivalence claim does not hold, and it is the roles making the
  /// distinction rather than two readers disagreeing about one.
  ///
  /// - The RESPONSE `Sec-WebSocket-Protocol` is RFC 6455 §4.2.2 item 4's single
  ///   selection, so a second field line is a second answer rather than a
  ///   continuation of the first — unlike the REQUEST role's `1#token`.
  /// - `Origin` is RFC 6454 §7's `origin-list-or-null`, which is SP-separated
  ///   and therefore has no comma-list spelling at all; RFC 9110 §5.3 forbids
  ///   the repeat and both gates refuse it.
  ///
  /// A group of ONE spelling is still one logical value on these pairs, so it
  /// keeps its claim; only the multi-spelling groups lose it.
  pub fn is_role_singleton(role: &str, field: &str) -> bool {
    matches!(
      (role, field),
      ("h1-client", "Sec-WebSocket-Protocol")
        | ("h1-client-nodeflate", "Sec-WebSocket-Protocol")
        | ("connect-client", "sec-websocket-protocol")
        | ("h1-server", "Origin")
        | ("connect-server", "origin")
    )
  }

  // ──────────────────────────── the five surfaces ─────────────────────────

  /// Deterministic `Rng`: the handshake needs sixteen nonce bytes and the corpus
  /// needs the same sixteen at both revisions.
  struct CountingRng(u8);

  impl rand_core::TryRng for CountingRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
      let mut bytes = [0u8; 4];
      self.try_fill_bytes(&mut bytes)?;
      Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
      let mut bytes = [0u8; 8];
      self.try_fill_bytes(&mut bytes)?;
      Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
      for slot in dest {
        *slot = self.0;
        self.0 = self.0.wrapping_add(1);
      }
      Ok(())
    }
  }

  /// The h1 SERVER's whole verdict for a request whose `field` is spelled as
  /// `lines` (one field line each).
  fn h1_server(field: &str, lines: &[String]) -> Verdict {
    let mut raw = String::from(
      "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\n\
       Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
       Sec-WebSocket-Version: 13\r\n",
    );
    for line in lines {
      push_field(&mut raw, field, line);
    }
    raw.push_str("\r\n");

    let mut handshake = ServerHandshake::new();
    match handshake.handle(raw.as_bytes()) {
      Err(error) => Verdict::from_debug("error", format!("{error:?}")),
      Ok(ServerProgress::NeedMore) => Verdict::plain("need-more", String::new()),
      Ok(ServerProgress::Upgrade(mut pending)) => {
        let view = pending.request();
        let host = view.host().to_owned();
        let path = view.path().to_owned();
        let offers: Vec<&str> = view.subprotocols().collect();
        // The managed accessor and the escape hatch, side by side: they resolve
        // the SAME field, and a build where they disagree is the defect class
        // this corpus exists to pin.
        let origin = view.origin().map(lossy);
        let hatch = view.header("origin").map(lossy);
        let extensions = format!(
          "{:?}",
          accept_deflate_offer(view.extensions(), &ServerDeflateConfig::new())
        );
        let accept = pending.validate_accept(&Accept::new()).is_ok();
        Verdict::plain(
          "upgrade",
          format!(
            "host={host} path={path} origin={origin:?} hatch={hatch:?} \
             offers={offers:?} ext={extensions} accept={accept}"
          ),
        )
      }
      Ok(other) => Verdict::from_debug("other", format!("{other:?}")),
    }
  }

  fn lossy(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
  }

  /// Appends one `name: value` field line, CRLF included.
  fn push_field(head: &mut String, name: &str, value: &str) {
    head.push_str(name);
    head.push_str(": ");
    head.push_str(value);
    head.push_str("\r\n");
  }

  /// The h1 CLIENT's verdict for a 101 whose `field` is spelled as `lines`.
  fn h1_client(field: &str, lines: &[String], offer_deflate: bool, offers: &[&str]) -> Verdict {
    let mut options = ClientOptions::new("h", "/chat");
    if !offers.is_empty() {
      options = options.with_subprotocols(offers);
    }
    if offer_deflate {
      options = options.with_deflate(DeflateOffer::new());
    }
    let mut handshake = match ClientHandshake::new(options, &mut CountingRng(0)) {
      Ok(handshake) => handshake,
      Err(error) => return Verdict::from_debug("options-error", format!("{error:?}")),
    };
    let mut buf = [0u8; 8192];
    if let Err(error) = handshake.encode_request(&mut buf) {
      return Verdict::from_debug("encode-error", format!("{error:?}"));
    }

    let accept = accept_for(handshake.key());
    let mut response = String::from("HTTP/1.1 101 Switching Protocols\r\n");
    push_field(&mut response, "Upgrade", "websocket");
    push_field(&mut response, "Connection", "Upgrade");
    push_field(&mut response, "Sec-WebSocket-Accept", &accept);
    for line in lines {
      push_field(&mut response, field, line);
    }
    response.push_str("\r\n");

    match handshake.handle(response.as_bytes()) {
      Err(error) => Verdict::from_debug("error", format!("{error:?}")),
      Ok(ClientProgress::Complete(done)) => {
        let negotiated = done.negotiated();
        Verdict::plain(
          "complete",
          format!(
            "subprotocol={:?} deflate={:?}",
            negotiated.subprotocol(),
            negotiated.deflate()
          ),
        )
      }
      Ok(other) => Verdict::from_debug("other", format!("{other:?}")),
    }
  }

  /// The extended-CONNECT SERVER's whole verdict.
  fn connect_server(field: &str, lines: &[String]) -> Verdict {
    let mut headers: Vec<(&str, &str)> = vec![
      (":method", "CONNECT"),
      (":protocol", "websocket"),
      (":scheme", "https"),
      (":path", "/chat"),
      (":authority", "server.example.com"),
      ("sec-websocket-version", "13"),
    ];
    headers.extend(lines.iter().map(|line| (field, line.as_str())));

    match validate_connect_request(&headers) {
      Err(error) => Verdict::from_debug("error", format!("{error:?}")),
      Ok(view) => {
        let offers: Vec<&str> = view.subprotocols().collect();
        let extensions = format!(
          "{:?}",
          accept_deflate_offer(
            view.extensions().map(str::as_bytes),
            &ServerDeflateConfig::new()
          )
        );
        Verdict::plain(
          "ok",
          format!(
            "path={:?} authority={:?} hatch={:?} offers={offers:?} ext={extensions}",
            view.path(),
            view.authority(),
            // The escape hatch rather than the accessor: `origin()` is what the
            // diff under test ADDED, and a corpus that named it could not be
            // run at the baseline.
            view.header("origin")
          ),
        )
      }
    }
  }

  /// The extended-CONNECT CLIENT's verdict for an accept whose `field` is
  /// spelled as `lines`.
  fn connect_client(field: &str, lines: &[String]) -> Verdict {
    let request =
      ConnectRequest::new(Scheme::Https, "h", "/chat").with_deflate(DeflateOffer::new());
    let headers: Vec<(&str, &str)> = lines.iter().map(|line| (field, line.as_str())).collect();
    match validate_connect_response(&headers, &request) {
      Err(error) => Verdict::from_debug("error", format!("{error:?}")),
      Ok(negotiated) => Verdict::plain(
        "ok",
        format!(
          "subprotocol={:?} deflate={:?}",
          negotiated.subprotocol(),
          negotiated.deflate()
        ),
      ),
    }
  }

  /// `base64(SHA-1(key ++ GUID))`, recomputed here so the corpus can build a 101
  /// the client under test accepts without reaching into the crate for the
  /// derivation the crate is being measured on.
  fn accept_for(key: &[u8]) -> String {
    const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut message = key.to_vec();
    message.extend_from_slice(GUID);
    base64(&sha1(&message))
  }

  fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
      0x6745_2301,
      0xEFCD_AB89,
      0x98BA_DCFE,
      0x1032_5476,
      0xC3D2_E1F0,
    ];
    let mut message = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
      message.push(0);
    }
    message.extend_from_slice(&bits.to_be_bytes());

    for chunk in message.chunks(64) {
      let mut w = [0u32; 80];
      for (index, word) in w.iter_mut().take(16).enumerate() {
        let bytes = chunk.get(index * 4..index * 4 + 4).unwrap_or(&[0; 4]);
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
      }
      for index in 16..80 {
        w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
      }
      let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);
      for (index, word) in w.iter().enumerate() {
        let (f, k) = match index {
          0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
          20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
          40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
          _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let tmp = a
          .rotate_left(5)
          .wrapping_add(f)
          .wrapping_add(e)
          .wrapping_add(k)
          .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
      }
      state[0] = state[0].wrapping_add(a);
      state[1] = state[1].wrapping_add(b);
      state[2] = state[2].wrapping_add(c);
      state[3] = state[3].wrapping_add(d);
      state[4] = state[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
      if let Some(slot) = out.get_mut(index * 4..index * 4 + 4) {
        slot.copy_from_slice(&word.to_be_bytes());
      }
    }
    out
  }

  fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
      let bytes = [
        chunk[0],
        chunk.get(1).copied().unwrap_or(0),
        chunk.get(2).copied().unwrap_or(0),
      ];
      let packed = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
      let symbol = |shift: u32| char::from(ALPHABET[(packed >> shift) as usize & 63]);
      out.push(symbol(18));
      out.push(symbol(12));
      out.push(if chunk.len() > 1 { symbol(6) } else { '=' });
      out.push(if chunk.len() > 2 { symbol(0) } else { '=' });
    }
    out
  }

  // ─────────────────────── emit-then-read (the drift screen) ───────────────

  /// What the h1 client EMITS for a given configuration, read back by THIS
  /// crate's own server. `emit-refused` is the shape that matters: a head this
  /// crate writes and this crate will not read.
  fn h1_emit_and_read(extras: &[(&str, &str)], offers: &[&str]) -> Verdict {
    let mut options = ClientOptions::new("h", "/chat").with_extra_headers(extras);
    if !offers.is_empty() {
      options = options.with_subprotocols(offers);
    }
    let mut handshake = match ClientHandshake::new(options, &mut CountingRng(0)) {
      Ok(handshake) => handshake,
      Err(error) => return Verdict::from_debug("options-error", format!("{error:?}")),
    };
    let mut buf = [0u8; 32768];
    let written = match handshake.encode_request(&mut buf) {
      Ok(written) => written,
      Err(error) => return Verdict::from_debug("encode-error", format!("{error:?}")),
    };
    let request = buf.get(..written).unwrap_or_default();

    let mut server = ServerHandshake::new();
    match server.handle(request) {
      Err(error) => Verdict::from_debug("emit-refused", format!("{error:?}")),
      Ok(ServerProgress::Upgrade(_)) => Verdict::plain("accepted", String::new()),
      Ok(other) => Verdict::from_debug("server-other", format!("{other:?}")),
    }
  }

  /// The extended-CONNECT builder's twin of the above.
  fn connect_emit_and_read(offers: &[&str]) -> Verdict {
    let request = ConnectRequest::new(Scheme::Https, "h", "/chat").with_subprotocols(offers);
    let headers = match request.headers() {
      Ok(headers) => headers,
      Err(error) => return Verdict::from_debug("build-error", format!("{error:?}")),
    };
    let pairs: Vec<(&str, &str)> = headers.iter().collect();
    match validate_connect_request(&pairs) {
      Err(error) => Verdict::from_debug("emit-refused", format!("{error:?}")),
      Ok(view) => Verdict::plain(
        "accepted",
        format!("offers={}", view.subprotocols().count()),
      ),
    }
  }

  // ────────────────────────────── the sections ────────────────────────────

  /// Section 1: one logical field value, every spelling, on every surface that
  /// reads a field.
  pub fn spelling_cases(sink: &mut Sink) {
    // The two managed list fields, the singleton `Origin`, and two fields this
    // crate does NOT manage — a spelling must not change a verdict there either,
    // and the escape hatch is where a reader would silently disagree.
    let fields = [
      ("Sec-WebSocket-Protocol", "sec-websocket-protocol"),
      ("Sec-WebSocket-Extensions", "sec-websocket-extensions"),
      ("Origin", "origin"),
      ("Cookie", "cookie"),
      ("X-Custom", "x-custom"),
    ];

    for (h1_field, connect_field) in fields {
      for (group, equivalent, spellings) in groups() {
        for (index, lines) in spellings.iter().enumerate() {
          let case = format!("{group}/{index}");
          // A group of one spelling cannot break an equivalence, so it keeps
          // its claim even where the field is a role-singleton.
          let claim = |role: &str, field: &str| {
            let singleton = is_role_singleton(role, field) && spellings.len() > 1;
            (equivalent && !singleton).then_some(group)
          };

          sink.emit(
            "h1-server",
            h1_field,
            &case,
            claim("h1-server", h1_field),
            h1_server(h1_field, lines),
          );
          sink.emit(
            "connect-server",
            connect_field,
            &case,
            claim("connect-server", connect_field),
            connect_server(connect_field, lines),
          );
          sink.emit(
            "h1-client",
            h1_field,
            &case,
            claim("h1-client", h1_field),
            h1_client(h1_field, lines, true, &["chat", "superchat"]),
          );
          sink.emit(
            "h1-client-nodeflate",
            h1_field,
            &case,
            claim("h1-client-nodeflate", h1_field),
            h1_client(h1_field, lines, false, &["chat"]),
          );
          sink.emit(
            "connect-client",
            connect_field,
            &case,
            claim("connect-client", connect_field),
            connect_client(connect_field, lines),
          );
        }
      }
    }
  }

  /// Section 2: the managed singletons, repeated. Absent, once, twice — the
  /// third is the one a gate that reads "the first occurrence" gets wrong.
  pub fn repeated_singleton_cases(sink: &mut Sink) {
    for (field, value) in [
      ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
      ("Sec-WebSocket-Version", "13"),
      ("Host", "other.example"),
      ("Upgrade", "websocket"),
      ("Connection", "Upgrade"),
    ] {
      for count in 0..3usize {
        let lines: Vec<String> = (0..count).map(|_| String::from(value)).collect();
        sink.emit(
          "h1-server",
          field,
          &format!("repeat-{count}"),
          None,
          h1_server(field, &lines),
        );
      }
    }
  }

  /// Section 3: how many offers, and how many bytes of them, each side will
  /// write and each gate will read. The counts bracket every bound this crate
  /// states — `MAX_SUBPROTOCOL_OFFERS` (64), the 60 the round-trip fixture
  /// pins, the 171 that `MAX_SUBPROTOCOL_OFFER_BYTES` admits at the one-byte
  /// floor — and the sizes bracket `http1_proto::MAX_HEAD_BYTES` (16384).
  pub fn offer_sweep_cases(sink: &mut Sink) {
    const H1_FIELD: &str = "Sec-WebSocket-Protocol";
    const CONNECT_FIELD: &str = "sec-websocket-protocol";

    let names: Vec<String> = (0..300).map(|index| format!("p{index}")).collect();
    for count in [
      0usize, 1, 2, 16, 32, 59, 60, 61, 63, 64, 65, 66, 100, 128, 170, 171, 172, 200, 300,
    ] {
      let offers: Vec<&str> = names.iter().take(count).map(String::as_str).collect();
      let case = format!("offers-{count}");
      sink.emit(
        "h1-emit",
        H1_FIELD,
        &case,
        None,
        h1_emit_and_read(&[], &offers),
      );
      sink.emit(
        "connect-emit",
        CONNECT_FIELD,
        &case,
        None,
        connect_emit_and_read(&offers),
      );
      // The same counts as an inbound comma list on both gates.
      let joined = offers.join(", ");
      sink.emit(
        "h1-server",
        H1_FIELD,
        &case,
        None,
        h1_server(H1_FIELD, core::slice::from_ref(&joined)),
      );
      sink.emit(
        "connect-server",
        CONNECT_FIELD,
        &case,
        None,
        connect_server(CONNECT_FIELD, &[joined]),
      );
    }

    // Inbound byte sweeps: ONE element of N bytes (cheap to check, and a shape
    // real deployments use), and N bytes of tiny offers (what costs the
    // quadratic uniqueness proof).
    for size in [
      64usize, 512, 1024, 4096, 8192, 16000, 16382, 16383, 16384, 16385, 32768, 65536,
    ] {
      let one_long = "a".repeat(size);
      sink.emit(
        "h1-server",
        H1_FIELD,
        &format!("one-long-{size}"),
        None,
        h1_server(H1_FIELD, core::slice::from_ref(&one_long)),
      );
      sink.emit(
        "connect-server",
        CONNECT_FIELD,
        &format!("one-long-{size}"),
        None,
        connect_server(CONNECT_FIELD, &[one_long]),
      );

      let mut dense = String::new();
      let mut index = 0usize;
      while dense.len() < size {
        if index > 0 {
          dense.push(',');
        }
        let _ = write!(dense, "q{index}");
        index = index.saturating_add(1);
      }
      sink.emit(
        "connect-server",
        CONNECT_FIELD,
        &format!("dense-{size}"),
        None,
        connect_server(CONNECT_FIELD, &[dense.clone()]),
      );
      sink.emit(
        "h1-server",
        H1_FIELD,
        &format!("dense-{size}"),
        None,
        h1_server(H1_FIELD, &[dense]),
      );
    }
  }

  /// The extra header lists a caller can inject, on either role. The repeats are
  /// the point: RFC 9110 §5.3 binds the SENDER, and its exception covers every
  /// list-valued field — so `Origin`, which has no comma-list spelling, must be
  /// refused repeated while `Cache-Control` and `Via` must not be.
  fn extras() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
      ("none", vec![]),
      ("origin-1", vec![("Origin", "http://a.example")]),
      (
        "cachecontrol-2",
        vec![("Cache-Control", "no-store"), ("Cache-Control", "no-cache")],
      ),
      ("via-2", vec![("Via", "1.1 alpha"), ("Via", "1.1 beta")]),
      (
        "origin-2",
        vec![
          ("Origin", "http://a.example"),
          ("Origin", "http://evil.example"),
        ],
      ),
      (
        "origin-2-case",
        vec![("origin", "http://a.example"), ("ORIGIN", "http://evil")],
      ),
      (
        "origin-3",
        vec![
          ("Origin", "http://a"),
          ("Origin", "http://b"),
          ("Origin", "http://c"),
        ],
      ),
      ("cl-0", vec![("Content-Length", "0")]),
      ("cl-5", vec![("Content-Length", "5")]),
      (
        "cl-2",
        vec![("Content-Length", "0"), ("Content-Length", "1")],
      ),
      ("te-chunked", vec![("Transfer-Encoding", "chunked")]),
      ("expect", vec![("Expect", "100-continue")]),
      (
        "auth-2",
        vec![("Authorization", "Bearer a"), ("Authorization", "Bearer b")],
      ),
      ("cookie-2", vec![("Cookie", "a=1"), ("Cookie", "b=2")]),
      (
        "ct-2",
        vec![
          ("Content-Type", "text/plain"),
          ("Content-Type", "text/html"),
        ],
      ),
      ("date-2", vec![("Date", "a"), ("Date", "b")]),
      (
        "ref-2",
        vec![("Referer", "http://a"), ("Referer", "http://b")],
      ),
      ("mf-2", vec![("Max-Forwards", "1"), ("Max-Forwards", "2")]),
      ("te-trailers", vec![("TE", "trailers")]),
      ("trailer", vec![("Trailer", "X-Late")]),
      ("x-2", vec![("X-Trace", "a"), ("X-Trace", "b")]),
      (
        "wwwauth-2",
        vec![
          ("WWW-Authenticate", "Basic realm=\"a\""),
          ("WWW-Authenticate", "Newauth realm=\"b\""),
        ],
      ),
      (
        "setcookie-2",
        vec![("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")],
      ),
      (
        "proxyauth-2",
        vec![
          ("Proxy-Authenticate", "Basic"),
          ("Proxy-Authenticate", "Digest"),
        ],
      ),
      ("managed-key", vec![("Sec-WebSocket-Key", "x")]),
      ("managed-host", vec![("Host", "evil.example")]),
      ("crlf", vec![("X-Evil", "a\r\nX-Injected: b")]),
      (
        "mixed",
        vec![("Cookie", "a=1"), ("Authorization", "Bearer t")],
      ),
    ]
  }

  /// Section 4: the request head the client emits for each extras list, read
  /// back by this crate's own server.
  pub fn request_extras_cases(sink: &mut Sink) {
    for (id, list) in extras() {
      sink.emit("h1-emit", "extras", id, None, h1_emit_and_read(&list, &[]));
      sink.emit(
        "h1-emit",
        "extras",
        &format!("{id}+offers"),
        None,
        h1_emit_and_read(&list, &["chat", "superchat"]),
      );
    }
  }

  /// Section 5: the same lists on the RESPONSE side — the 101 the server writes
  /// for a request it accepted.
  pub fn response_extras_cases(sink: &mut Sink) {
    const UPGRADE_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\r\n";

    for (id, list) in extras() {
      let mut server = ServerHandshake::new();
      // The classification's borrow of `server` has to end before the response
      // is encoded on it, so the arm answers with a value rather than carrying
      // the pending upgrade into the encode.
      let validated = match server.handle(UPGRADE_REQUEST) {
        Ok(ServerProgress::Upgrade(mut pending)) => {
          Ok(pending.validate_accept(&Accept::new()).is_ok())
        }
        other => Err(format!("{other:?}")),
      };
      let verdict = match validated {
        Err(debug) => Verdict::from_debug("classify", debug),
        Ok(false) => Verdict::plain("accept-refused", String::new()),
        Ok(true) => {
          let mut buf = [0u8; 16384];
          match server.encode_response(&ExtraHeaders::from(list.as_slice()), &mut buf) {
            Ok((written, _)) => Verdict::plain("emitted", format!("bytes={written}")),
            Err(error) => Verdict::from_debug("refused", format!("{error:?}")),
          }
        }
      };
      sink.emit("h1-response-extras", "extras", id, None, verdict);
    }
  }

  /// Section 6: the same lists on the REJECTION side, plus the version lists
  /// only this path can write.
  ///
  /// It is the one surface that exempts a managed name — `Sec-WebSocket-Version`,
  /// because the RFC 6455 §4.2.2 wrong-version answer carries it — and §11.3.5
  /// makes that field "MAY appear multiple times in an HTTP response", so a
  /// screen that reached it would silence §4.4's own instruction to send
  /// "multiple |Sec-WebSocket-Version| header fields".
  pub fn rejection_extras_cases(sink: &mut Sink) {
    let version_lists: Vec<(&'static str, Vec<(&'static str, &'static str)>)> = vec![
      ("version-1", vec![("Sec-WebSocket-Version", "13")]),
      (
        "version-2",
        vec![
          ("Sec-WebSocket-Version", "13"),
          ("Sec-WebSocket-Version", "8"),
        ],
      ),
      (
        "version-3",
        vec![
          ("Sec-WebSocket-Version", "13"),
          ("Sec-WebSocket-Version", "8"),
          ("Sec-WebSocket-Version", "7"),
        ],
      ),
    ];

    const UPGRADE_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\r\n";

    for (id, list) in extras().into_iter().chain(version_lists) {
      let mut server = ServerHandshake::new();
      // Classified but not accepted: what the connection owes is the rejection.
      // The pending upgrade's borrow ends with the match, as on the 101 side.
      let classified = match server.handle(UPGRADE_REQUEST) {
        Ok(ServerProgress::Upgrade(_)) => Ok(()),
        other => Err(format!("{other:?}")),
      };
      let verdict = match classified {
        Err(debug) => Verdict::from_debug("classify", debug),
        Ok(()) => {
          let mut buf = [0u8; 16384];
          let rejection =
            Rejection::new(426, "Upgrade Required").with_extra_headers(list.as_slice());
          match server.encode_rejection(&rejection, &mut buf) {
            Ok(written) => Verdict::plain("emitted", format!("bytes={written}")),
            Err(error) => Verdict::from_debug("refused", format!("{error:?}")),
          }
        }
      };
      sink.emit("h1-rejection-extras", "extras", id, None, verdict);
    }
  }
}
