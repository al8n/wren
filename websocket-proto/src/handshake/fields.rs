//! The ONE answer to "what is the logical value of this field".
//!
//! # The defect class this module ends
//!
//! A handshake field is read twice: once by the gate that decides whether the
//! head is conforming, and once by the reader that acts on what it says. Every
//! time those two reads were written separately they eventually disagreed, and
//! the disagreement is always about one of three questions:
//!
//! 1. **The grammar** — what the value's elements are.
//! 2. **The cardinality** — how many physical field lines make up the value.
//! 3. **The presence** — whether a field that is there but names nothing counts
//!    as a field that is not there.
//!
//! Question 1 was collapsed onto one walk ([`crate::negotiation`]'s §9.1
//! grammar). Questions 2 and 3 are collapsed here: a field is reachable ONLY
//! through the accessor named for it, that accessor yields the field's COMPLETE
//! logical value — every occurrence in arrival order — and the only questions
//! askable of it are the three [`FieldValue`](crate::handshake::fields::FieldValue)
//! methods, each with exactly one implementation in the crate.
//!
//! So the gate and the reader cannot answer either question differently,
//! because neither of them answers it: they read the same accessor, and the
//! rule that turns occurrences into a verdict lives in the grammar layer that
//! already knows the field's ABNF.
//!
//! # What lives where
//!
//! - **Here**: which name a field has, every occurrence of it, and RFC 9110
//!   §5.3's singleton rule — the transport-level question of how many field
//!   lines a name may have.
//! - **[`crate::negotiation`]**: the field's own cardinality — `1#extension`
//!   (RFC 6455 §9.1), `1#token` (§11.3.4), "a response grants exactly one
//!   extension" (RFC 6455 §4.1 step 5). Those are grammar, and they are asked
//!   over the complete value this module hands them.
//! - **The gate and the readers**: what the resolved value MEANS. Nothing else.
//!
//! A regression test at the bottom of this file fails if any handshake module
//! reads a field for itself again.

use http1_proto::HeadView;

/// `Upgrade` (RFC 9110 §7.8).
const UPGRADE: &str = "upgrade";
/// `Host` (RFC 9112 §3.2).
const HOST: &str = "host";
/// `Origin` (RFC 6454; RFC 6455 §4.1 item 8).
const ORIGIN: &str = "origin";
/// `Sec-WebSocket-Key` (RFC 6455 §4.1 item 7).
const KEY: &str = "sec-websocket-key";
/// `Sec-WebSocket-Accept` (RFC 6455 §4.2.2 item 5).
const ACCEPT: &str = "sec-websocket-accept";
/// `Sec-WebSocket-Version` (RFC 6455 §4.1 item 9).
const VERSION: &str = "sec-websocket-version";
/// `Sec-WebSocket-Protocol` (RFC 6455 §11.3.4).
const PROTOCOL: &str = "sec-websocket-protocol";
/// `Sec-WebSocket-Extensions` (RFC 6455 §9.1).
const EXTENSIONS: &str = "sec-websocket-extensions";
/// `Connection` (RFC 9110 §7.6.1). Read only where `http1-proto` has not
/// already proven §7.8's upgrade pairing for itself — a head the CALLER read
/// and handed to the server handshake — and written by the handshake machines
/// either way, so it belongs to the managed set below.
const CONNECTION: &str = "connection";
/// `Expect` (RFC 9110 §10.1.1). Read for the same reason `Connection` is, and
/// nowhere else: the outstanding `100 (Continue)` a tunnel connection reports
/// is `http1-proto`'s own reading of this field.
const EXPECT: &str = "expect";

/// The field names the handshake machines write themselves, so a caller's
/// extra header must not collide with one: the wire would then contradict the
/// [`Negotiated`](crate::negotiation::Negotiated) the machine returns.
///
/// Built from the constants above rather than spelled again, because "is this
/// name one the handshake owns" is the same question the accessors answer and a
/// second list of names is a second answer waiting to drift. `Origin` is
/// deliberately absent: the client SENDS it as an extra and the server reads it
/// as application policy, so it is a caller's field on both sides. What the
/// client may not do is send it TWICE — that rule is
/// [`ExtraHeaders::validate`](crate::handshake::ExtraHeaders)'s, and it is the
/// general one rather than a second list naming `Origin` again.
pub(crate) const MANAGED: &[&str] = &[
  HOST, UPGRADE, CONNECTION, KEY, VERSION, PROTOCOL, EXTENSIONS, ACCEPT,
];

/// The field names whose complete value is ONE field line, so an extra header
/// naming one twice is something this crate's own readers would refuse.
///
/// RFC 9110 §5.3 states the rule the other way round — a sender MUST NOT repeat
/// a name "unless that field's definition allows multiple field line values to
/// be recombined as a comma-separated list (i.e., at least one alternative of
/// the field's definition allows a comma-separated list, such as an ABNF rule of
/// #(values) defined in Section 5.6.1)". The names a sender MAY repeat are
/// therefore every list-valued field, which is an open set: `Cache-Control`
/// (`#cache-directive`), `Via` (`#( received-protocol …)`), and whatever field
/// is registered next. An allowlist of those would be wrong the moment a caller
/// used one it did not contain, so the screen is stated over the DENIED side —
/// and that side is enumerable precisely because it is this crate's own.
///
/// A name belongs here when both hold:
///
/// - a gate in this crate resolves it with [`FieldValue::single`], so a repeat
///   is a head this crate writes and this crate will not read; and
/// - no role's ABNF gives its value a list alternative, so §5.3's exception
///   cannot apply in whichever role the extras are written in.
///
/// Both halves are load-bearing, and `Sec-WebSocket-Version` shows why: the
/// request gate does resolve it with `single`, but the ONLY extras that may
/// carry it are a rejection's, and there RFC 6455 §11.3.5 says in as many words
/// that it "MAY appear multiple times in an HTTP response (which is logically
/// the same as a single |Sec-WebSocket-Version| header field that contains all
/// values)" — with `Sec-WebSocket-Version-Server = 1#version` (§4.3) for the
/// ABNF and §4.4 for the instruction to send "multiple |Sec-WebSocket-Version|
/// header fields" when refusing a version. §11.3.5's other half, "MUST NOT
/// appear more than once in an HTTP request", needs no entry: a REQUEST extra
/// naming it is refused outright as [`MANAGED`]. `Sec-WebSocket-Protocol`
/// (§11.3.4's "MAY appear multiple times in an HTTP request"),
/// `Sec-WebSocket-Extensions` (§11.3.2, the same), `Upgrade` (`#protocol`) and
/// `Connection` (`#connection-option`) are absent for the list half of the same
/// test; their singleton ROLE is likewise covered by [`MANAGED`].
///
/// What is left is the four whose singleton-ness holds in every role an extra
/// can reach:
///
/// - `Origin` — RFC 6454 §7.1's `origin-list = serialized-origin *( SP
///   serialized-origin )` is SP-separated, so the field has no comma-list
///   alternative at all. It is the one member NOT in [`MANAGED`], which makes it
///   the only one this screen actually decides: a caller may legitimately send
///   `Origin`, and may not send two.
/// - `Host` — RFC 9112 §3.2's single authority.
/// - `Sec-WebSocket-Key` — RFC 6455 §11.3.1: "MUST NOT appear more than once in
///   an HTTP request".
/// - `Sec-WebSocket-Accept` — §11.3.3: "MUST NOT appear more than once in an
///   HTTP response".
///
/// The last three are already refused outright by the managed-collision check,
/// so their entry here is defence in depth for a path that screens names without
/// it.
///
/// Lowercase because the comparison is ASCII case-insensitive (RFC 9110 §5.1).
pub(crate) const SINGLETON: &[&str] = &[ORIGIN, HOST, KEY, ACCEPT];

/// Whether `name` is a field this module RESOLVES for the request role and that
/// an application can also reach by name — so the first-occurrence escape hatch
/// must route it back through its own accessor rather than answer it itself.
///
/// `Origin` is the whole of it, on both transports. Every other resolved field
/// is either in [`MANAGED`] (refused as an extra outright, and read by its
/// accessor here), or a pseudo-header, which has an accessor and no h1
/// spelling, or a field whose accessor here resolves it as a LIST — `Expect`
/// (RFC 9110 §10.1.1's `#expectation`) — where the hatch's first-line answer
/// contradicts no singleton this module decided, and
/// [`RequestView::header`](crate::handshake::h1::RequestView::header)'s own
/// warning already scopes itself to a value that is not a list.
/// The predicate is one function so the two `other`s cannot come to disagree
/// about which names the hatch may answer.
fn resolved_by_name(name: &str) -> bool {
  name.eq_ignore_ascii_case(ORIGIN)
}

/// A field whose value is not a list arrived on more than one line, which RFC
/// 9110 §5.3 forbids ("a sender MUST NOT generate multiple field lines with the
/// same name in a message … unless that field's definition allows multiple field
/// line values to be recombined as a comma-separated list").
///
/// Its own type rather than an `Option`: [`FieldValue::single`] has THREE
/// answers — absent, exactly one (possibly empty), and repeated — and a reader
/// that could only see two of them would be re-deciding at the call site which
/// two, which is the class this module exists to end.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct Repeated;

/// The complete logical value of one header field: every occurrence, in arrival
/// order, and whether the field was present at all.
///
/// There is no accessor for "the first line" and no `is_some`. A reader asks
/// one of exactly three questions:
///
/// - [`present`](Self::present) — was the field there? One occurrence, even an
///   EMPTY one, is present. Whether a present field that names nothing is
///   acceptable is its ABNF's `1#` question, and it is asked in
///   [`crate::negotiation`] over the whole value, never here.
/// - [`single`](Self::single) — RFC 9110 §5.3's singleton rule, for the fields
///   whose value is not a list.
/// - `IntoIterator` — every occurrence, for the grammar layer that knows how to
///   join and split them (RFC 9110 §5.2).
#[derive(Debug, Copy, Clone)]
pub(crate) struct FieldValue<L> {
  lines: L,
}

impl<V, L: Iterator<Item = V> + Clone> FieldValue<L> {
  /// Private: the ONLY constructor a field accessor may use is one of this
  /// module's two source walks, so no caller can build a value out of a
  /// truncated occurrence list.
  const fn new(lines: L) -> Self {
    Self { lines }
  }

  /// Whether the field appeared at all — one occurrence, even one whose value
  /// is empty, is present.
  ///
  /// Present-and-empty is deliberately NOT absent: collapsing the two is how a
  /// `1#` field that names nothing came to read as a field nobody sent.
  pub(crate) fn present(&self) -> bool {
    self.lines.clone().next().is_some()
  }

  /// RFC 9110 §5.3's singleton rule: `Ok(None)` when the field is absent,
  /// `Ok(Some(value))` when it arrived on exactly one line — the value may
  /// still be empty, which is the caller's to judge — and `Err(Repeated)` when
  /// it arrived on more.
  pub(crate) fn single(&self) -> Result<Option<V>, Repeated> {
    let mut lines = self.lines.clone();
    let Some(first) = lines.next() else {
      return Ok(None);
    };
    if lines.next().is_some() {
      return Err(Repeated);
    }
    Ok(Some(first))
  }
}

impl<V, L: Iterator<Item = V> + Clone> IntoIterator for FieldValue<L> {
  type Item = V;
  type IntoIter = L;

  /// Every occurrence, in arrival order — RFC 9110 §5.2's combined value, for
  /// the grammar layer that knows the field's own cardinality rule.
  fn into_iter(self) -> L {
    self.lines
  }
}

/// One of the two source walks: an `http1-proto` head, by field name.
///
/// `head` by value because [`HeadView`] is `Copy` and the iterator it yields
/// borrows the BUFFER rather than the view, so the returned value outlives this
/// call.
fn h1<'a>(
  head: HeadView<'a>,
  name: &'static str,
) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
  FieldValue::new(head.header_all(name))
}

/// The other source walk: an HTTP/2 or HTTP/3 header list, by field name
/// (ASCII case-insensitive, RFC 9110 §5.1 — H2/H3 names are lowercase on the
/// wire, but a list assembled by the application need not be).
fn list<'a>(
  headers: &'a [(&'a str, &'a str)],
  name: &'static str,
) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
  FieldValue::new(
    headers
      .iter()
      .filter_map(move |(n, v)| n.eq_ignore_ascii_case(name).then_some(*v)),
  )
}

/// RFC 8441 §5: the h1 upgrade machinery has no place on the extended-CONNECT
/// transports — `Sec-WebSocket-Key`/`Accept` are not used, and HTTP/2 (RFC 9113
/// §8.2.2) / HTTP/3 treat connection-specific fields as malformed outright
/// (incl. `HTTP2-Settings`, an h1-upgrade artifact). The ONE exception: `TE` may
/// appear in REQUESTS carrying exactly `trailers` — any other value, or any `TE`
/// in a response, is malformed.
///
/// A set-membership question over EVERY field line, so it is one walk of the
/// list rather than a lookup per name.
fn forbidden_h1_field(headers: &[(&str, &str)], te_trailers_ok: bool) -> bool {
  const FORBIDDEN: &[&str] = &[
    "connection",
    "upgrade",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "http2-settings",
    KEY,
    ACCEPT,
  ];
  headers.iter().any(|(name, value)| {
    if FORBIDDEN.iter().any(|f| name.eq_ignore_ascii_case(f)) {
      return true;
    }
    if name.eq_ignore_ascii_case("te") {
      // RFC 9113 §8.2.2: "MUST NOT contain any value other than 'trailers'".
      return !(te_trailers_ok
        && value
          .trim_matches([' ', '\t'])
          .eq_ignore_ascii_case("trailers"));
    }
    false
  })
}

/// Every field the h1 SERVER reads out of an upgrade request (RFC 6455 §4.2.1).
#[derive(Debug, Copy, Clone)]
pub(crate) struct RequestFields<'a> {
  head: HeadView<'a>,
}

impl<'a> RequestFields<'a> {
  /// Wraps the head `http1-proto` just validated.
  pub(crate) const fn new(head: HeadView<'a>) -> Self {
    Self { head }
  }

  /// The borrowed head, for application code that needs a field this crate does
  /// not manage in a shape [`other`](Self::other) cannot express. Not for this
  /// crate's own readers — see the module note.
  pub(crate) const fn head(&self) -> &HeadView<'a> {
    &self.head
  }

  /// `Upgrade` — RFC 9110 §7.8's `#protocol`, so the token may arrive in any
  /// occurrence (proxies split lists across lines).
  pub(crate) fn upgrade(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, UPGRADE)
  }

  /// `Connection` — RFC 9110 §7.6.1's `#connection-option`, the other half of
  /// §7.8's upgrade offer, on the same any-occurrence terms as
  /// [`upgrade`](Self::upgrade).
  pub(crate) fn connection(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, CONNECTION)
  }

  /// `Expect` — RFC 9110 §10.1.1's `#expectation`, and a list like the two
  /// above, so the `100-continue` expectation may arrive in any occurrence.
  pub(crate) fn expect(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, EXPECT)
  }

  /// `Host` — RFC 9112 §3.2's singleton, already held to "exactly one line
  /// whose value is an authority or empty" by `http1-proto`'s own validator.
  pub(crate) fn host(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, HOST)
  }

  /// `Origin` — RFC 6454's single `origin-list-or-null`, and the input to the
  /// application's origin policy.
  pub(crate) fn origin(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, ORIGIN)
  }

  /// `Sec-WebSocket-Key` — RFC 6455 §4.2.1 item 5's exactly-once field.
  pub(crate) fn websocket_key(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, KEY)
  }

  /// `Sec-WebSocket-Version` — RFC 6455 §4.2.1 item 6's exactly-once field.
  pub(crate) fn websocket_version(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, VERSION)
  }

  /// `Sec-WebSocket-Protocol` in the REQUEST role — RFC 6455 §11.3.4's
  /// `1#token` offer list, which §9.1's own words about `Sec-WebSocket-Extensions`
  /// apply to just as well: the field "MAY be split or combined across multiple
  /// lines".
  pub(crate) fn subprotocol_offers(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, PROTOCOL)
  }

  /// `Sec-WebSocket-Extensions` in the REQUEST role — RFC 6455 §9.1's
  /// `1#extension`.
  pub(crate) fn extension_offers(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, EXTENSIONS)
  }

  /// The first occurrence of a field this crate does NOT manage — cookies,
  /// authorization, whatever the application routes on.
  ///
  /// An escape hatch, and the name says so: nothing in this crate reads a
  /// managed field through it, and a caller that needs every occurrence of a
  /// repeated field takes [`head`](Self::head).
  ///
  /// A [`resolved_by_name`] field is the one thing it will not answer as "the
  /// first line": it routes back through that field's own accessor, so the
  /// hatch cannot become a second answer to a question already answered.
  pub(crate) fn other(&self, name: &str) -> Option<&'a [u8]> {
    if resolved_by_name(name) {
      // `single()`, because a repeated `Origin` is refused at the gate: this
      // cannot lose a value the caller would otherwise have seen.
      return self.origin().single().ok().flatten();
    }
    self.head.header_all(name).next()
  }
}

/// Every field the h1 CLIENT reads out of a 101 (RFC 6455 §4.1 steps 2-6).
#[derive(Debug, Copy, Clone)]
pub(crate) struct ResponseFields<'a> {
  head: HeadView<'a>,
}

impl<'a> ResponseFields<'a> {
  /// Wraps the head `http1-proto` just validated.
  pub(crate) const fn new(head: HeadView<'a>) -> Self {
    Self { head }
  }

  /// `Upgrade` — RFC 9110 §7.8's `#protocol`, as on the request side.
  pub(crate) fn upgrade(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, UPGRADE)
  }

  /// `Sec-WebSocket-Accept` — RFC 6455 §4.1 step 4's exactly-once field.
  pub(crate) fn websocket_accept(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, ACCEPT)
  }

  /// `Sec-WebSocket-Protocol` in the RESPONSE role — RFC 6455 §4.2.2 item 4
  /// makes it the ONE subprotocol the server selected, so unlike the request
  /// role this is a singleton and not a list.
  pub(crate) fn selected_subprotocol(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, PROTOCOL)
  }

  /// `Sec-WebSocket-Extensions` in the RESPONSE role — still RFC 6455 §9.1's
  /// `1#extension`, still splittable across lines. How many extensions a
  /// RESPONSE may grant is RFC 6455 §4.1 step 5's question, asked over the
  /// whole value by `crate::negotiation::parse_deflate_response`.
  pub(crate) fn granted_extensions(self) -> FieldValue<impl Iterator<Item = &'a [u8]> + Clone> {
    h1(self.head, EXTENSIONS)
  }
}

/// Every field the extended-CONNECT SERVER reads out of a request (RFC 8441 §4,
/// RFC 9220 §3).
#[derive(Debug, Copy, Clone)]
pub(crate) struct ConnectRequestFields<'a> {
  headers: &'a [(&'a str, &'a str)],
}

impl<'a> ConnectRequestFields<'a> {
  /// Wraps the caller's header list.
  pub(crate) const fn new(headers: &'a [(&'a str, &'a str)]) -> Self {
    Self { headers }
  }

  /// `:method` — RFC 9113 §8.3.1 makes every pseudo-header a singleton.
  pub(crate) fn method(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, ":method")
  }

  /// `:protocol` — RFC 8441 §4's extended-CONNECT selector.
  pub(crate) fn protocol(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, ":protocol")
  }

  /// `:scheme`.
  pub(crate) fn scheme(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, ":scheme")
  }

  /// `:path`.
  pub(crate) fn path(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, ":path")
  }

  /// `:authority`.
  pub(crate) fn authority(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, ":authority")
  }

  /// `sec-websocket-version` — the h1 server's exactly-once rule, mirrored.
  pub(crate) fn websocket_version(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, VERSION)
  }

  /// `origin` — RFC 8441 §5 carries it onto this transport with RFC 6455's own
  /// semantics ("The Origin \[RFC6454\], Sec-WebSocket-Version,
  /// Sec-WebSocket-Protocol, and Sec-WebSocket-Extensions header fields are used
  /// in the CONNECT request and response-header fields as defined in
  /// \[RFC6455\]"), so it is the same single `origin-list-or-null` the h1 server
  /// reads, and the same input to the application's origin policy.
  pub(crate) fn origin(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, ORIGIN)
  }

  /// `sec-websocket-protocol` in the REQUEST role — RFC 6455 §11.3.4's
  /// `1#token`, exactly as on h1.
  pub(crate) fn subprotocol_offers(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, PROTOCOL)
  }

  /// `sec-websocket-extensions` in the REQUEST role — RFC 6455 §9.1's
  /// `1#extension`, exactly as on h1.
  pub(crate) fn extension_offers(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, EXTENSIONS)
  }

  /// The first occurrence of a field this crate does not manage. The escape
  /// hatch; see [`RequestFields::other`], including its routing of a
  /// [`resolved_by_name`] field back through that field's own accessor.
  pub(crate) fn other(&self, name: &str) -> Option<&'a str> {
    if resolved_by_name(name) {
      return self.origin().single().ok().flatten();
    }
    self
      .headers
      .iter()
      .find_map(|(n, v)| n.eq_ignore_ascii_case(name).then_some(*v))
  }

  /// Whether the request carries an h1-only or connection-specific field. See
  /// [`forbidden_h1_field`].
  pub(crate) fn has_forbidden_h1_field(&self) -> bool {
    forbidden_h1_field(self.headers, true)
  }
}

/// Every field the extended-CONNECT CLIENT reads out of a response.
#[derive(Debug, Copy, Clone)]
pub(crate) struct ConnectResponseFields<'a> {
  headers: &'a [(&'a str, &'a str)],
}

impl<'a> ConnectResponseFields<'a> {
  /// Wraps the caller's header list.
  pub(crate) const fn new(headers: &'a [(&'a str, &'a str)]) -> Self {
    Self { headers }
  }

  /// `sec-websocket-protocol` in the RESPONSE role — the one selection, as on
  /// h1.
  pub(crate) fn selected_subprotocol(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, PROTOCOL)
  }

  /// `sec-websocket-extensions` in the RESPONSE role — as on h1.
  pub(crate) fn granted_extensions(self) -> FieldValue<impl Iterator<Item = &'a str> + Clone> {
    list(self.headers, EXTENSIONS)
  }

  /// Whether the response carries an h1-only or connection-specific field.
  /// `TE` is forbidden outright here: RFC 9113 §8.2.2's exception is for
  /// requests.
  pub(crate) fn has_forbidden_h1_field(&self) -> bool {
    forbidden_h1_field(self.headers, false)
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  /// Everything below the `#[cfg(all(test` marker is a module's own test code,
  /// which reads fields through the PUBLIC surface on purpose.
  ///
  /// Exactly one marker per file, asserted rather than assumed: with two of
  /// them the cut would be ambiguous, and production code could sit between
  /// them where the scan below would not look.
  fn production_source<'a>(path: &str, source: &'a str) -> &'a str {
    const MARKER: &str = "\n#[cfg(all(test";
    assert_eq!(
      source.matches(MARKER).count(),
      1,
      "{path} must have exactly one `{}` marker for the production/test cut",
      MARKER.trim_start()
    );
    match source.split_once(MARKER) {
      Some((head, _)) => head,
      None => source,
    }
  }

  /// The same source with whole-line comments dropped.
  ///
  /// The scan is about CODE that reads a field, and documentation that NAMES
  /// the lookup is the opposite of the defect — `RequestView::header`'s own
  /// warning has to send a caller to `head().header_all(name)`, which is
  /// exactly the escape hatch that keeps a repeated field visible. Only lines
  /// that are entirely a comment are dropped, so a read with a comment after it
  /// is still scanned.
  fn production_code(path: &str, source: &str) -> String {
    production_source(path, source)
      .lines()
      .filter(|line| !line.trim_start().starts_with("//"))
      .collect::<Vec<_>>()
      .join("\n")
  }

  /// The class, pinned mechanically: a handshake module that reads a field for
  /// itself is a second answer to "what is the logical value of this field",
  /// which is how the same disagreement relocated twice.
  ///
  /// Each transport's lookup primitives are named per file, so adding a read
  /// outside this module fails the build rather than waiting for a reviewer to
  /// notice that two places now disagree about occurrences or about presence:
  ///
  /// - h1 reads a [`HeadView`], whose only lookups are `header` and
  ///   `header_all`.
  /// - The extended-CONNECT modules read a `&[(&str, &str)]`, where matching a
  ///   name ASCII case-insensitively (RFC 9110 §5.1) is the only way to find a
  ///   field at all — so `eq_ignore_ascii_case` marks every possible lookup
  ///   there. (Value comparisons use `grammar::eq_ignore_ascii`, which is a
  ///   different call and a different question.)
  ///
  /// A read this module cannot express belongs HERE as a new accessor, not at
  /// the call site.
  #[test]
  fn no_handshake_module_reads_a_field_for_itself() {
    const SOURCES: &[(&str, &str, &[&str])] = &[
      (
        "h1/client.rs",
        include_str!("h1/client.rs"),
        &["header_all", ".header("],
      ),
      (
        "h1/server.rs",
        include_str!("h1/server.rs"),
        &["header_all", ".header("],
      ),
      (
        "connect.rs",
        include_str!("connect.rs"),
        &["eq_ignore_ascii_case"],
      ),
    ];
    for (path, source, lookups) in SOURCES {
      let production = production_code(path, source);
      for lookup in *lookups {
        assert!(
          !production.contains(lookup),
          "{path} reads a header field itself ({lookup:?}); every field read \
           belongs in handshake/fields.rs, which is the crate's one answer to \
           what a field's logical value is"
        );
      }
    }
  }

  /// The head the h1 accessors are exercised against: one repeated field, one
  /// present-but-EMPTY singleton, and one absent field.
  const HEAD: &[u8] = b"GET / HTTP/1.1\r\n\
Host: h\r\n\
Sec-WebSocket-Protocol: chat\r\n\
Sec-WebSocket-Protocol: superchat\r\n\
Origin: \r\n\
\r\n";

  /// The same three shapes as an H2/H3 header list, mixed-case names included
  /// (RFC 9110 §5.1 matching is case-insensitive on both transports).
  const LIST: &[(&str, &str)] = &[
    ("host", "h"),
    ("sec-websocket-protocol", "chat"),
    ("Sec-WebSocket-Protocol", "superchat"),
    ("origin", ""),
  ];

  fn with_h1_fields(f: impl FnOnce(RequestFields<'_>)) {
    use http1_proto::{Connection, General, Item, Server};
    let mut connection = Connection::<Server, General>::new();
    let mut items = connection.handle(HEAD);
    let Some(Item::Head { view, .. }) = items.next().unwrap() else {
      panic!("the fixture is one complete head")
    };
    f(RequestFields::new(view));
  }

  /// The two questions the class kept answering twice, asked of BOTH sources:
  /// a repeated field yields every occurrence and is not a singleton, and a
  /// field that is there with an empty value is not a field that is absent.
  #[test]
  fn both_sources_answer_occurrences_and_presence_alike() {
    with_h1_fields(|fields| {
      let offers = fields.subprotocol_offers();
      assert!(offers.present());
      assert_eq!(offers.single(), Err(Repeated));
      let lines: Vec<&[u8]> = offers.into_iter().collect();
      assert_eq!(lines, [b"chat".as_slice(), b"superchat".as_slice()]);

      let origin = fields.origin();
      assert!(origin.present(), "`Origin:` with no value is still present");
      assert_eq!(origin.single(), Ok(Some(b"".as_slice())));

      let extensions = fields.extension_offers();
      assert!(!extensions.present());
      assert_eq!(extensions.single(), Ok(None));
      assert_eq!(fields.other("ABSENT"), None);
    });

    let fields = ConnectRequestFields::new(LIST);
    let offers = fields.subprotocol_offers();
    assert!(offers.present());
    assert_eq!(offers.single(), Err(Repeated));
    let lines: Vec<&str> = offers.into_iter().collect();
    assert_eq!(lines, ["chat", "superchat"]);

    let origin = fields.origin();
    assert!(origin.present());
    assert_eq!(origin.single(), Ok(Some("")));

    let extensions = fields.extension_offers();
    assert!(!extensions.present());
    assert_eq!(extensions.single(), Ok(None));
    assert_eq!(fields.other("ORIGIN"), Some(""));
    assert_eq!(fields.other("ABSENT"), None);
  }

  /// A head carrying the ambiguity both gates refuse, so the layer BELOW them
  /// can be asked what it would have said.
  const TWO_ORIGINS: &[u8] = b"GET / HTTP/1.1\r\n\
Host: h\r\n\
Origin: https://example.com\r\n\
Origin: https://evil.example\r\n\
\r\n";

  const TWO_ORIGINS_LIST: &[(&str, &str)] = &[
    ("host", "h"),
    ("origin", "https://example.com"),
    ("Origin", "https://evil.example"),
  ];

  /// The escape hatch never answers a RESOLVED field as "the first line".
  ///
  /// Both gates refuse a repeated `Origin` before a view exists, so in
  /// production the two answers coincide and this is defence in depth — which is
  /// exactly why it is asserted HERE, below the gates, where the ambiguity can
  /// still be built. Without it, a later reader that reached a view without
  /// passing a gate would get `https://example.com` for a request that also said
  /// `https://evil.example`, which is the header-confusion shape the named
  /// accessors exist to refuse rather than hide.
  #[test]
  fn the_escape_hatch_does_not_answer_a_resolved_field() {
    use http1_proto::{Connection, General, Item, Server};
    let mut connection = Connection::<Server, General>::new();
    let mut items = connection.handle(TWO_ORIGINS);
    let Some(Item::Head { view, .. }) = items.next().unwrap() else {
      panic!("the fixture is one complete head")
    };
    let fields = RequestFields::new(view);
    assert_eq!(fields.origin().single(), Err(Repeated));
    assert_eq!(
      fields.other("Origin"),
      None,
      "the hatch must not report the first of two contradicting origins"
    );
    // …while the head itself still shows both, for a caller that asked for it.
    assert_eq!(fields.head().header_all("origin").count(), 2);

    let fields = ConnectRequestFields::new(TWO_ORIGINS_LIST);
    assert_eq!(fields.origin().single(), Err(Repeated));
    assert_eq!(fields.other("origin"), None);
    assert_eq!(fields.other("ORIGIN"), None);
    // An unresolved name is still first-occurrence, which is what the hatch is.
    assert_eq!(fields.other("host"), Some("h"));
  }
}
