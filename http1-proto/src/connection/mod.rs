//! The connection state machine: what a driver holds for one HTTP/1.1
//! connection, and everything that survives between the messages carried on it.
//!
//! Two questions this module answers, and they are deliberately answered in
//! different ways.
//!
//! **What kind of endpoint is this?** A compile-time one. [`Connection`] is
//! parameterised by a [`Role`] (client or server) and a [`Mode`] (a general
//! request/response endpoint, or a connection that has been taken over as a
//! tunnel), and both are type-state: sealed marker types rather than runtime
//! flags, so a call that belongs to one shape cannot be made on the other and
//! the mistake is a compile error rather than a state check. The pattern is
//! `http3-proto`'s, for the same reason it is used there — RFC 9110 §9.3.6
//! takeover changes what the bytes after a head MEAN, and a core that decided
//! that at runtime would be deciding it with the peer's help.
//!
//! **Where in the protocol is this connection?** A runtime one, and it is the
//! rest of this module: the receive FSM, the exchange counter that names
//! messages (RFC 9112 §9.3.2 makes their ORDER the only association between a
//! request and its response), the send-side gate that keep-alive re-arm waits on,
//! and the lifecycle latch that ends both.
//!
//! **Two modes, two APIs, and no overlap.** Everything in the paragraph above is
//! [`General`]'s. A [`Tunnel`] connection has no exchange, no body and no
//! keep-alive: it completes ONE protocol switch — RFC 9110 §7.8's upgrade or
//! §9.3.6's CONNECT — and hands the byte stream over, which is what
//! `connection::tunnel` is. Neither mode's calls exist on the other, and
//! [`Tunnel`]'s own documentation pins that with `compile_fail` proofs rather
//! than with prose.
//!
//! # No buffers
//!
//! A `Connection` holds FSM state and nothing else — the size budget below is
//! const-asserted on every `cargo check` of every tier. The bytes stay in the
//! driver's own accumulation buffer and reach the driver back as borrowed
//! [`Item`]s, so a megabyte upload crosses this core without being copied and
//! without an allocator being involved. What the connection keeps of the input is
//! two integers: how much of the current offer it has consumed, and how far into
//! an unfinished head it has already scanned.
//!
//! # The consumption contract
//!
//! [`handle`](Connection::handle) is handed the driver's buffer FROM ITS
//! UNCONSUMED START, and reports back how many of those bytes are now the
//! connection's business rather than the driver's. Bytes are counted as consumed
//! only when the item they produced has been yielded (the invariant documented on
//! [`Items`]), so a driver that stops pulling items — or drops the iterator —
//! re-offers the remainder and gets exactly the items it had not seen yet.
//!
//! # Sending
//!
//! The mirror image, and deliberately the same shape on every storage tier: a
//! send call encodes into a slice the CALLER owns and reports how many bytes it
//! wrote, so the core frames a message without holding a buffer to frame it in.
//! [`open_request`](Connection::open_request),
//! [`send_response`](Connection::send_response) and their neighbours live in
//! `connection::outbound`; [`BodyPlan`] is what tells them how the body that
//! follows a head is framed.
//!
//! There is NO transmit queue in this crate, on any tier. An HTTP/3-style
//! `poll_transmit` would need owned per-message storage, which is the one thing
//! a heap tier could add here — and it would add it in front of exactly these
//! calls rather than instead of them, since a queue that encodes differently
//! would be a second implementation of the framing rules to keep in step. The
//! consumer this crate was written for hands the encoded bytes straight to a
//! transport, so the queue would have no caller; a tier that wants one wraps
//! these calls. **A deliberate scope decision, not an omission.**

// `pub(crate)` rather than private: the pump is the body of `Items::next`, which
// lives in `crate::event` where the iterator's contract is documented, so the two
// halves of one function sit in different modules on purpose — the vocabulary
// type keeps its doc, and the state machine keeps its neighbours.
pub(crate) mod inbound;
// The send side, in its own module for the same reason the receive side is in
// one: the inherent methods it defines land on `Connection` either way (rustdoc
// merges them onto the type), so the split is about where the RULES live rather
// than about what a caller sees.
pub(crate) mod outbound;
// The OTHER mode, whole: a tunnel's receive and send sides are one handshake, so
// they are one module rather than being split the way General's are.
pub(crate) mod tunnel;

use core::marker::PhantomData;

use derive_more::Display;

use crate::{
  body::{BodyDecoder, Budget},
  error::{Error, H1Error, Refusal},
  event::{Event, ExchangeId, Item, Items, SWITCHED},
  head::Version,
};

pub use outbound::{BodyPlan, NO_TRAILERS};
use tunnel::TunnelPhase;
pub use tunnel::{ClientTunnelOutcome, HeadBinding, ServerTunnelRequest};

// The no-buffer budget, checked at module scope so that every `cargo check` on
// every tier enforces it — inside a `#[test]` it would only fire under `cargo
// test` on the tiers that run one (the rationale `HeadView`'s own assert is
// written against). Both roles are asserted because the receive and send states
// they exercise are not the same, and both modes because the type-state is what
// decides which of those states a connection uses.
const _: () = assert!(core::mem::size_of::<Connection<Server, General>>() <= 256);

const _: () = assert!(core::mem::size_of::<Connection<Client, General>>() <= 256);
const _: () = assert!(core::mem::size_of::<Connection<Server, Tunnel>>() <= 256);
const _: () = assert!(core::mem::size_of::<Connection<Client, Tunnel>>() <= 256);

/// RFC 9112 §4 `status-code` for RFC 9110 §15.2.2's Switching Protocols — the
/// response that ends HTTP framing on a connection, which is why all three of
/// this module's parts have a rule about it and none of them may spell it
/// differently.
pub(crate) const SWITCHING_PROTOCOLS: u16 = 101;

/// RFC 9110 §9.3.6, and the one method whose request-target is RFC 9112 §3.2.3's
/// authority-form.
pub(crate) const CONNECT: &str = "CONNECT";

/// Folds a complete head block into the 64-bit digest a connection keeps of the
/// request that armed it — FNV-1a, one wrapping pass over borrowed bytes.
///
/// WHAT IT IS FOR, stated sharply, because the guarantee runs in one direction
/// only. It answers "did this head arm this connection", so that
/// [`Connection::head_binding`] can refuse a head the caller took from
/// somewhere else. Against that mistake — an application holding two heads and
/// pairing the wrong one — the miss probability is 2⁻⁶⁴ per event, which is the
/// whole of what a driver needs.
///
/// It is NOT a commitment and MUST NOT be read as a security boundary. Head
/// content is peer-controlled and arbitrary field lines are free padding; FNV-1a
/// is invertible per byte-step, so a colliding pair is constructible offline and
/// a second preimage against a KNOWN target costs about 2³² by
/// meet-in-the-middle. A shared intermediary whose head-to-connection pairing is
/// defective, where one peer supplies or predicts both blocks, is exactly the
/// shape this buys nothing against; there the content checks the upgrade layer
/// runs, and the client's own RFC 6455 §4.1 `Sec-WebSocket-Accept` check, are
/// the residue. Two facts narrow that shape rather than closing it: the upgrade
/// layer's once-only latch makes classification one-shot per handshake, so there
/// is no online oracle, and a WebSocket head embeds a 128-bit random key, so the
/// known-target shape needs a victim head carrying no entropy of its own. A
/// keyed hash is the upgrade path if that guarantee is ever wanted; the `no_std`
/// core has no RNG to key one with, which is why it is not what runs here.
///
/// One bounded pass over at most [`MAX_HEAD_BYTES`](crate::MAX_HEAD_BYTES), and
/// only for a head that offered a switch — the callers gate on that before
/// spending it, so an ordinary request pays nothing for a mechanism that exists
/// to cross a mode transition.
pub(crate) fn head_digest(block: &[u8]) -> u64 {
  // FNV-1a's published 64-bit parameters. Wrapping is the algorithm rather than
  // an overflow guard, which is also what keeps this inside the crate's
  // no-panic wall: nothing here indexes, divides or can overflow a check.
  const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
  const PRIME: u64 = 0x0000_0100_0000_01b3;
  let mut hash = OFFSET_BASIS;
  for &byte in block {
    hash = (hash ^ u64::from(byte)).wrapping_mul(PRIME);
  }
  hash
}

mod sealed {
  pub trait Sealed {}
  pub trait SealedMode {}
}

/// Which end of the connection this is. Sealed: only [`Client`] and [`Server`]
/// implement it.
///
/// The role decides what a head IS — a server reads the RFC 9112 §3
/// request-line, a client the §4 status-line — and therefore which validation
/// rules apply, whether an inbound head opens an exchange or continues one, and
/// what an unexpected byte means (§9.2).
pub trait Role: sealed::Sealed {
  /// True for [`Client`], false for [`Server`].
  ///
  /// The runtime discriminant of the type-state, for the one place that needs
  /// it: the inbound pump is a single non-generic function, so the role reaches
  /// it as this `bool` rather than by monomorphising the FSM twice.
  const IS_CLIENT: bool;

  /// The default ceiling on the PAYLOAD octets any one inbound message body may
  /// deliver — a request at a server, a response at a client.
  ///
  /// Role-dependent because the two directions are not the same problem: RFC
  /// 9112 §6.3 item 8's framing, which declares nothing and is delimited only
  /// by the connection closing, is RESPONSE-only, so a client is where the
  /// least-boundable case lives and where a real ceiling has to be larger. No
  /// RFC supplies either number — RFC 9110 §8.6: "there is no predefined limit
  /// to the length of content" — and §17.5 sanctions the rejection while
  /// declining the value, which is why this is named `DEFAULT_` and is
  /// configurable through [`Limits`].
  ///
  /// A limit RESERVES nothing: it is a number compared against, so an embedded
  /// target meets it immediately rather than paying for it.
  const DEFAULT_MAX_BODY_BYTES: u64;

  /// The FLOOR under the chunk-framing budget: octets one inbound body may
  /// spend on RFC 9112 §7.1 chunk-size lines when a sixteenth of the payload
  /// ceiling would be less than this.
  ///
  /// The budget itself is resolved from the payload ceiling in force — see
  /// [`Limits::max_chunk_framing_bytes`] — so that raising one knob does not
  /// silently leave the other refusing ordinary traffic. This is the floor
  /// under that resolution, which is what a caller who narrows the payload
  /// ceiling to nothing still gets.
  const DEFAULT_MAX_CHUNK_FRAMING_BYTES: u64;
}

/// Role marker: this endpoint sends requests and reads responses.
#[derive(Debug)]
pub struct Client;

/// Role marker: this endpoint reads requests and sends responses.
#[derive(Debug)]
pub struct Server;

impl sealed::Sealed for Client {}
impl sealed::Sealed for Server {}
impl Role for Client {
  const IS_CLIENT: bool = true;
  /// 64 MiB. Large enough that being refused is exceptional — ordinary
  /// documents, API responses and page assets sit orders of magnitude inside
  /// it — and small enough that a consumer accumulating one survives on an
  /// ordinary deployment. RFC 9112 §6.3 item 8's undeclared, close-delimited
  /// framing is response-only, so this is the direction that most needs a
  /// ceiling of some kind. `websocket-proto`'s own `max_message_size` default
  /// is the same number, which makes the two crates agree rather than each
  /// guessing.
  const DEFAULT_MAX_BODY_BYTES: u64 = 64 << 20;
  /// 4 MiB — a sixteenth of the payload default above, so the two are one
  /// progression. 64 MiB delivered in 4 KiB chunks, the commonest CDN
  /// granularity, spends 96 KiB of chunk-size lines, far inside it.
  const DEFAULT_MAX_CHUNK_FRAMING_BYTES: u64 = 4 << 20;
}
impl Role for Server {
  const IS_CLIENT: bool = false;
  /// 1 MiB, on two anchors rather than a preference: it is nginx's own
  /// `client_max_body_size 1m`, and it is exactly
  /// [`MAX_HEAD_BYTES`](crate::MAX_HEAD_BYTES) × [`MAX_HEADERS`](crate::MAX_HEADERS)
  /// (16384 × 64), so this crate's declared limits are one progression rather
  /// than unrelated numbers.
  const DEFAULT_MAX_BODY_BYTES: u64 = 1 << 20;
  /// 64 KiB — a sixteenth of the payload default above. A sender chunking 1 MiB
  /// at 8 KiB writes 128 six-octet size lines, two orders of magnitude inside
  /// it; a peer spending it on one-octet chunks is refused after about 128 KiB
  /// of wire.
  const DEFAULT_MAX_CHUNK_FRAMING_BYTES: u64 = 1 << 16;
}

/// The deterministic, role-seeded limits a connection is constructed with.
///
/// Read ONCE, at construction: a [`Connection`] copies the values it needs, so
/// there is no path from a live connection back to this type and no way to
/// raise a ceiling on a connection that is already running. That is what makes
/// the narrowing direction the only one there is.
///
/// Seeded from the connection type being built —
/// [`Connection::default_limits`] — rather than from a free constructor, so the
/// wrong role's seed has no shorter spelling than the right one.
///
/// # The two knobs are not independent
///
/// The chunk-framing budget is resolved FROM the payload ceiling in force,
/// unless a caller states one explicitly, so raising the payload ceiling
/// carries the framing budget with it. A budget derived from the DEFAULT
/// payload would reproduce, one knob up, the failure a budget exists to
/// prevent: a server that set `with_max_body_bytes(100 << 20)` and kept a 64 KiB
/// framing budget would refuse ordinary 4 KiB-granularity chunked traffic about
/// 42.7 MiB in. See [`max_chunk_framing_bytes`](Self::max_chunk_framing_bytes).
///
/// # Equality compares what was STATED
///
/// Presence is part of the value, so `default_limits()` and
/// `default_limits().with_max_chunk_framing_bytes(n)` are different limits even
/// on a role where the two resolve to the same number — the first still tracks
/// the payload ceiling and the second does not.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Limits {
  /// The payload ceiling, in octets.
  payload: u64,
  /// The chunk-framing budget a caller STATED, or `None` for "resolve it".
  /// Presence, not a value — see `max_chunk_framing_bytes`.
  framing: Option<u64>,
  /// `Ro::DEFAULT_MAX_CHUNK_FRAMING_BYTES`, captured where the role was in
  /// scope. Carried so the resolution below has a role-less answer to give.
  floor: u64,
  /// Whether this connection may offer an RFC 9110 §7.8 upgrade on an ordinary
  /// exchange, and therefore whether it may accept the 101 that answers one.
  ///
  /// **Default: it may not.** §7.8 obliges a client to nothing — it makes the
  /// offer an invitation the server "MAY ignore" and says "Upgrade cannot be
  /// used to insist on a protocol change" — so refusing is fully conforming,
  /// and a driver that wants the capability asks for it. A proxy-shaped driver
  /// forwarding a downstream client's headers verbatim never chose to send
  /// `Upgrade`, and must not be switched for carrying one through.
  opportunistic_upgrade: bool,
}

impl Limits {
  /// Sets the ceiling on the PAYLOAD octets one inbound message body may
  /// deliver.
  ///
  /// `u64::MAX` disables the bound. `0` refuses every message that carries
  /// content — and is NOT nginx's spelling of "unlimited", deliberately, since
  /// a magic zero would invert the narrowing direction. A message with no
  /// content at all (RFC 9112 §6.3 items 1 and 7, and `Content-Length: 0`) is
  /// never refused whatever this says.
  ///
  /// Raises the resolved chunk-framing budget with it unless one has been
  /// stated: see [`max_chunk_framing_bytes`](Self::max_chunk_framing_bytes).
  #[must_use]
  pub const fn with_max_body_bytes(self, n: u64) -> Self {
    Self {
      payload: n,
      framing: self.framing,
      floor: self.floor,
      opportunistic_upgrade: self.opportunistic_upgrade,
    }
  }

  /// States the budget for the RFC 9112 §7.1 chunk-size lines one inbound body
  /// may spend, instead of resolving it from the payload ceiling.
  ///
  /// Stating it pins it: the budget then no longer moves when the payload
  /// ceiling does.
  ///
  /// A body that spends more is refused with
  /// [`Refusal::ChunkFramingTooLarge`] — policy rather than a protocol failure,
  /// since every line of such a body was well-formed. The budget bounds a quantity the payload ceiling cannot see:
  /// `chunk-size = 1*HEXDIG` admits unlimited leading zeros, so a size line may
  /// announce one octet and cost hundreds.
  ///
  /// `0` refuses every chunked body, the empty one included: RFC 9112 §7.1's
  /// `last-chunk` is itself a size line and is charged like any other. A
  /// message framed some other way is untouched.
  #[must_use]
  pub const fn with_max_chunk_framing_bytes(self, n: u64) -> Self {
    Self {
      payload: self.payload,
      framing: Some(n),
      floor: self.floor,
      opportunistic_upgrade: self.opportunistic_upgrade,
    }
  }

  /// The ceiling on the payload octets one inbound message body may deliver.
  #[must_use]
  pub const fn max_body_bytes(&self) -> u64 {
    self.payload
  }

  /// The RESOLVED chunk-framing budget: what was stated, or a sixteenth of the
  /// payload ceiling, or the role's floor — whichever of the last two is larger.
  ///
  /// Resolved from the ceiling IN FORCE rather than from the role's default,
  /// which is the whole point of the rule: 100 MiB delivered in 4 KiB chunks
  /// needs 153,600 octets of chunk-size lines, so a budget frozen at the
  /// server's 64 KiB default would refuse ordinary chunked traffic about 42.7
  /// MiB into a body its own payload ceiling allows. The role default survives
  /// as the FLOOR, so narrowing the payload ceiling never leaves a body unable
  /// to state its own framing.
  ///
  /// A consequence worth stating rather than discovering: `u64::MAX >> 4` is
  /// 2⁶⁰, so an unbounded payload ceiling unbounds this too — "unbounded" stays
  /// one knob.
  ///
  /// WHAT IS CHARGED against it: the whole chunk-size line — digits,
  /// `chunk-ext` and the CRLF that ends it — for every chunk of one body, the
  /// terminating `0\r\n` included. So the budget also fixes the smallest chunk
  /// a whole body can be sent in, and because it scales with the payload
  /// ceiling that boundary does not move with the role: 65 octets at either.
  /// Ordinary traffic is nowhere near the boundary — 1 MiB in 4 KiB chunks, the
  /// commonest reverse-proxy granularity, writes 256 six-octet size lines and
  /// spends 1,539 octets of the server's 65,536.
  #[must_use]
  pub const fn max_chunk_framing_bytes(&self) -> u64 {
    match self.framing {
      Some(stated) => stated,
      // `>> 4`, not `/ 16`: `clippy::integer_division` is denied crate-wide.
      // Spelled out rather than through `Ord::max`, which is not `const`.
      None => {
        let scaled = self.payload >> 4;
        if scaled > self.floor {
          scaled
        } else {
          self.floor
        }
      }
    }
  }

  /// Permits this connection to offer an RFC 9110 §7.8 upgrade on an ordinary
  /// exchange, and to accept the 101 that answers one.
  ///
  /// This is the operator's ceiling. A request may decline to offer on a
  /// permitting connection; it may not offer on a refusing one.
  ///
  /// Named `allow_`, not `with_` like its siblings, deliberately: they set a
  /// VALUE — `with_max_body_bytes(1024)` — where this grants a PERMISSION.
  /// `with_opportunistic_upgrade(false)` would read as assigning a property
  /// the value false; `allow_opportunistic_upgrade(false)` reads as
  /// withholding permission, which is what it does.
  #[must_use]
  pub const fn allow_opportunistic_upgrade(self, allow: bool) -> Self {
    Self {
      payload: self.payload,
      framing: self.framing,
      floor: self.floor,
      opportunistic_upgrade: allow,
    }
  }

  /// Whether [`allow_opportunistic_upgrade`](Self::allow_opportunistic_upgrade)
  /// was set.
  pub(crate) const fn opportunistic_upgrade_allowed(&self) -> bool {
    self.opportunistic_upgrade
  }
}

/// Where the body being received stands.
///
/// The observing half of [`Limits`]: that type is what a ceiling is STATED
/// with, and this is what a message measured against one reports back. Read
/// through [`Connection::body_progress`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BodyProgress {
  /// The exchange this body belongs to.
  pub exchange: ExchangeId,
  /// Payload octets already delivered as [`Item::BodyChunk`] for this message.
  ///
  /// The SAMPLE PRIMITIVE for a driver's own liveness policy. This core is
  /// Sans-I/O and holds no clock, so it can bound what a peer sends and not how
  /// long the peer takes over it; a driver that samples this against its own
  /// wall clock has what a minimum-throughput or deadline rule needs, and the
  /// socket read deadline is where such a rule belongs.
  pub received: u64,
  /// The ceiling in force for this message: the operator's, as narrowed by
  /// [`Items::limit_body`].
  pub limit: u64,
  /// Octets the framing has COMMITTED to and has not yet handed over — and what
  /// that covers depends on the framing, which is the whole point of reading it:
  ///
  /// - `Some(n)` for a `Content-Length` body (RFC 9112 §6.3 item 6): the whole
  ///   remainder of the BODY, known from the moment its head was read.
  /// - `Some(n)` inside a chunk (§7.1): the remainder of THAT CHUNK only. §7.1
  ///   never declares a body's total, and this value must not be read as one.
  /// - `None` between chunks, for a close-delimited body (§6.3 item 8), and once
  ///   the body is over.
  ///
  /// Read immediately after [`Item::Head`] the three cases separate cleanly:
  /// `Some(total)` is a counted body, `None` is chunked or close-delimited —
  /// with ONE exception, and it falls at exactly this read point. A counted body
  /// whose declaration was already refused against the ceiling reads `None` too,
  /// because a refused body has committed to nothing; a driver that takes that
  /// for chunked streams instead of waiting and meets [`Refusal::BodyTooLarge`]
  /// on its next pull.
  ///
  /// # The contiguous handover
  ///
  /// This is what makes ZERO-COPY contiguous handover possible for a counted
  /// body with no new API and no copy path: wait until the driver's own buffer
  /// holds `announced` more octets, and the next `handle` yields the whole body
  /// as ONE [`Item::BodyChunk`] borrowed from that buffer, because the counted
  /// framing claims `min(remaining, input.len())` in one go.
  ///
  /// The recipe has two steps its signature does not reveal, and both are
  /// required:
  ///
  /// 1. **Stop pulling at [`Item::Head`] and DROP the iterator.** One more
  ///    [`Items::next`] may hand back a partial chunk of whatever happened to be
  ///    buffered, and [`Connection::body_progress`] is unreachable while
  ///    [`Items`] borrows the connection. The order is: pull to the head, drop,
  ///    read the progress, then `handle` again.
  /// 2. **Answer any pending expectation BEFORE waiting.**
  ///    [`Item::ExpectContinue`] is yielded by the BODY pump, so a driver that
  ///    stopped at the head has never seen it — the ask has to be re-derived
  ///    from the `Expect` field of the head just read. RFC 9110 §10.1.1
  ///    provides for a client that waits for its `100 (Continue)` before sending
  ///    content, so against one that does both ends wait: the server for octets,
  ///    the client for permission to send them.
  ///
  /// # The wait is bounded in magnitude and UNBOUNDED IN TIME
  ///
  /// A declaration above the ceiling was already refused, so the wait can never
  /// ask for more than `limit` octets of driver buffer. It can ask for them for
  /// as long as the peer likes: a peer that declares exactly the ceiling and
  /// then dribbles pins that buffer for the whole dribble, which is the
  /// consumer-side accumulation the ceiling exists to close, reintroduced at
  /// `limit`. On a server that is the server ceiling per connection; on a CLIENT
  /// it is 64 MiB per connection by default, and a contiguous-handover driver at
  /// ten thousand connections is holding roughly 640 GB against a streaming
  /// driver's few hundred bytes each.
  ///
  /// **Liveness is the DRIVER's**, and this core cannot take it: it owns no
  /// clock. [`received`](Self::received) is the quantity to sample and the
  /// socket read deadline is the real control.
  pub announced: Option<u64>,
}

/// Whether this connection carries ordinary messages ([`General`]) or has been
/// taken over as a tunnel ([`Tunnel`]). Sealed: only those two implement it.
///
/// Type-state rather than a flag, because takeover is not a mode a connection
/// can be talked into. RFC 9110 §9.3.6 makes everything after a 2xx to CONNECT
/// opaque octets, and RFC 9110 §15.2.2 does the same after a 101 — in both cases
/// the message framing this core applies STOPS applying. A [`General`]
/// connection therefore refuses the CONNECT tunnel where it arrives instead of
/// switching itself over, and refuses every 101 but the one its own permitted
/// offer asked for — see [`General`]. A driver that wants to BUILD a handshake
/// asks for one by naming [`Tunnel`] in the type it constructs.
///
/// No members, unlike [`Role`]. A role reaches the inbound pump as a runtime
/// `bool` because that pump is ONE non-generic function serving both roles; the
/// mode never does, because mode separation here is STRUCTURAL — each mode's
/// calls are defined in an `impl` block of its own, so no shared body ever has
/// to ask which mode it is in. A discriminant const would be dead API on a
/// sealed trait no downstream crate can implement.
pub trait Mode: sealed::SealedMode {}

/// Mode marker: an ordinary request/response endpoint.
///
/// A CONNECT request arriving at a General server is answered as a protocol
/// error: RFC 9110 §9.3.6 makes everything after the 2xx that would answer it
/// opaque octets, and this mode has no state to become a tunnel with.
///
/// A `101` is the one takeover this mode can carry, and only in the narrow shape
/// RFC 9110 §7.8 describes — a CLIENT whose operator permitted an opportunistic
/// upgrade ([`Limits::allow_opportunistic_upgrade`]) and whose request actually
/// made the offer. That client takes the answering 101 as
/// [`Item::Switched`] and is spent from there: the
/// transport belongs to the protocol switched to, and every later call refuses.
/// Every OTHER 101 is a protocol error, which is every 101 a server, an
/// unpermitted client, or a client that offered nothing can receive — §7.8:
/// "A server MUST NOT switch to a protocol that was not indicated by the client
/// in the corresponding request's Upgrade header field."
///
/// Building a handshake from scratch is still [`Tunnel`]'s: what this mode does
/// is carry one that arrived on an ordinary exchange.
#[derive(Debug)]
pub struct General;

/// Mode marker: a connection that carries a tunnel.
///
/// A `Connection<_, Tunnel>` exists to complete ONE protocol switch — RFC 9110
/// §7.8's upgrade, answered by the §15.2.2 `101`, or §9.3.6's CONNECT tunnel,
/// answered by any 2xx — and then to hand the byte stream over. It has no
/// exchange, no body decoder and no keep-alive, because after the head that
/// switches, the octets on the connection are not HTTP.
///
/// The API is [`open_upgrade`](Connection::open_upgrade),
/// [`open_connect`](Connection::open_connect) and
/// [`handle_response`](Connection::handle_response) on a client;
/// [`handle_request`](Connection::handle_request),
/// [`send_interim`](Connection::send_interim), [`accept`](Connection::accept)
/// and [`reject`](Connection::reject) on a server.
///
/// ```
/// use http1_proto::{Client, ClientTunnelOutcome, Connection, Target, Tunnel};
///
/// let mut client = Connection::<Client, Tunnel>::new();
/// // RFC 9110 §7.8 wants both halves of the offer; what protocol it names — and
/// // whatever else that protocol's handshake adds — is the caller's field.
/// let offer: &[(&str, &[u8])] = &[
///   ("Host", b"example.com"),
///   ("Connection", b"Upgrade"),
///   ("Upgrade", b"websocket"),
/// ];
/// let mut out = [0u8; 128];
/// let target = Target::Origin { path_and_query: "/chat" };
/// let n = client.open_upgrade(&target, offer, &mut out).unwrap();
/// assert_eq!(
///   &out[..n],
///   b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
/// );
///
/// let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x03abc";
/// let ClientTunnelOutcome::Switched { leftover, .. } = client.handle_response(response).unwrap()
/// else {
///   panic!("the server switched protocols")
/// };
/// // Everything after the 101's head is the new protocol's, verbatim.
/// assert_eq!(leftover, b"\x81\x03abc");
/// ```
///
/// # The General API is not here
///
/// Mode isolation is structural rather than a state check, and these are the
/// proofs: every General call is a COMPILE error on a tunnel connection.
///
/// ```compile_fail,E0599
/// use http1_proto::{BodyPlan, Client, Connection, Target, Tunnel};
///
/// let mut connection = Connection::<Client, Tunnel>::new();
/// let headers: &[(&str, &[u8])] = &[("Host", b"example.com")];
/// let mut out = [0u8; 64];
/// let target = Target::Origin { path_and_query: "/" };
/// // A tunnel opens its handshake with `open_upgrade` or `open_connect`.
/// let _ = connection.open_request("GET", &target, headers, BodyPlan::None, &mut out);
/// ```
///
/// ```compile_fail,E0599
/// use http1_proto::{BodyPlan, Connection, Server, Tunnel};
///
/// let mut connection = Connection::<Server, Tunnel>::new();
/// let headers: &[(&str, &[u8])] = &[("Content-Length", b"0")];
/// let mut out = [0u8; 64];
/// // A tunnel answers with `accept` or `reject`, and neither takes a body plan.
/// let _ = connection.send_response(200, b"OK", headers, BodyPlan::None, &mut out);
/// ```
///
/// ```compile_fail,E0599
/// use http1_proto::{Client, Connection, Tunnel};
///
/// let mut connection = Connection::<Client, Tunnel>::new();
/// // The General inbound pump: a tunnel reads its ONE response with
/// // `handle_response` and hands the rest of the stream over untouched.
/// let _ = connection.handle(b"HTTP/1.1 101 Switching Protocols\r\n\r\n");
/// ```
#[derive(Debug)]
pub struct Tunnel;

impl sealed::SealedMode for General {}
impl sealed::SealedMode for Tunnel {}
impl Mode for General {}
impl Mode for Tunnel {}

/// Why a mode transition was refused, naming the gate that failed.
///
/// A [`General`] connection does not become a [`Tunnel`] on request. RFC 9110
/// §7.8 lets a server switch only in answer to a request that offered the
/// protocol and has been completely sent, and everything a General connection
/// carries beyond that request — an unanswered exchange, an undrained notice, a
/// half-closed read side — is state the tunnel has nowhere to put. Each of those
/// conditions is therefore a gate of its own, and the one that failed is what
/// comes back.
///
/// The gates are checked in a FIXED order, which is why this names one rather
/// than reporting a set: several of them fail together on the same connection —
/// a peer that stated `close` moved the lifecycle and ended the exchange in the
/// same step — and a caller told a different reason on different runs could act
/// on none of them.
///
/// The gate is the machine-readable half and the reason string is the human one:
/// a driver that BRANCHES compares against the constants below, and one that
/// LOGS reads [`reason`](Self::reason) or renders the value through
/// [`Display`](core::fmt::Display), which writes that same string.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[display("{_0}")]
pub struct TransitionRefused(&'static str);

impl TransitionRefused {
  /// No exchange is in flight, so there is no request whose offer could be
  /// answered. The switch is an ANSWER, and RFC 9110 §7.8 says so: "A server
  /// MUST NOT switch to a protocol that was not indicated by the client in the
  /// corresponding request's Upgrade header field." With no request there is no
  /// indication to have been given.
  pub const NO_EXCHANGE: Self = Self("no exchange is in flight to switch");

  /// The request stated no RFC 9110 §7.8 offer — one half of it, neither, or an
  /// `Upgrade` field naming no protocol — or stated one on an HTTP/1.0 request,
  /// where §7.8 makes ignoring the field a MUST.
  pub const NO_UPGRADE_OFFERED: Self = Self("the request offered no protocol to switch to");

  /// The request has not been completely received. RFC 9110 §7.8: "A client
  /// cannot begin using an upgraded protocol on the connection until it has
  /// completely sent the request message" — so a body still arriving is a body
  /// whose remaining octets are HTTP, and a tunnel has no framing left to read
  /// them with.
  pub const REQUEST_INCOMPLETE: Self = Self("the request has not been completely received");

  /// This exchange's final response has already begun going out, so the 101
  /// would be a SECOND answer to one request. RFC 9112 §2.1 makes a response one
  /// message; a switch appended to — or injected into — bytes the peer is
  /// already reading as the answer is §11.1 response splitting.
  pub const ANSWER_BEGUN: Self = Self("this exchange's answer has already begun");

  /// The connection already switched protocols under RFC 9110 §7.8. Its
  /// transport belongs to the protocol the 101 named, and there is no HTTP left
  /// on it to tunnel.
  ///
  /// Never the reported reason on either of today's edges, and both halves of
  /// that are worth stating. A General SERVER cannot reach the phase at all: the
  /// only writer of it is the client's response path. A client reaches it, and
  /// `nothing_outstanding` fires first with
  /// [`EXCHANGE_IN_FLIGHT`](Self::EXCHANGE_IN_FLIGHT) — which §7.8 makes TRUE
  /// rather than coincidental, since "the server still has an outstanding
  /// request to satisfy after the protocol has been changed". Named and gated
  /// all the same, for the reason [`RECV_NOT_IDLE`](Self::RECV_NOT_IDLE) is: a
  /// coincidence between today's writers is not a rule, and what this one guards
  /// is a transport another protocol is already reading.
  pub const SWITCHED: Self = Self("the connection already switched protocols");

  /// Keep-alive is over or the connection has failed. RFC 9112 §9.6 makes the
  /// `close` connection option a promise to close BEHIND the exchange in flight,
  /// and a tunnel that outlives that exchange is the opposite of one; a failed
  /// connection has only its single error response left to send.
  pub const NOT_OPEN: Self = Self("the connection is no longer open");

  /// The peer's write side has ended, so nothing it sends can reach the switched
  /// protocol. The 101 is still writable as a RESPONSE (RFC 9112 §9.6: a
  /// connection half-closed by the client "does not delimit a request message,
  /// nor does it imply that the client is no longer interested in a response"),
  /// which is exactly why the answer stays with the General connection that owes
  /// it rather than moving to a tunnel with no inbound stream.
  pub const READ_CLOSED: Self = Self("the peer's write side has ended");

  /// A completed exchange left bytes this connection has not read back. RFC 9112
  /// §9.2's barrier: those octets arrived before anything this end would switch
  /// for, so handing them to the new protocol would give it bytes that are not
  /// its own.
  pub const TAIL_UNRESOLVED: Self = Self("an unread tail of the last exchange is outstanding");

  /// A lone `\r` is sitting undecided at the connection's cursor. RFC 9112 §2.2
  /// makes a CR a line terminator only once its LF has arrived, so the byte
  /// belongs to a decision HTTP has not finished making and the tunnel would
  /// inherit it as opaque data.
  pub const PENDING_CR: Self = Self("an undecided line terminator is pending");

  /// An exchange abort is still queued. The transition drops the General state
  /// that queued it, so a driver that had not yet called
  /// [`poll_event`](Connection::poll_event) would lose it outright — and an
  /// abort names a message whose exchange is already gone, so nothing else could
  /// tell the driver afterwards.
  ///
  /// The end of keep-alive is NOT among the things this protects: it is a level
  /// read from [`transport`](Connection::transport), so it cannot be queued,
  /// lost, or dropped by a transition.
  pub const EVENT_UNDRAINED: Self = Self("a queued notice has not been drained");

  /// An exchange is already outstanding on this connection. The client edge has
  /// no request to answer the way the server edge does — it is deciding, on its
  /// own, to spend a connection on a handshake — so what is outstanding here is
  /// a response this end is still OWED rather than one it owes. RFC 9112 §9.3.2
  /// lets a client pipeline, but this core keeps exactly one request of its own
  /// in flight, so that single answer is the whole of what the switch would
  /// silently drop: the transition discards the General receive state the
  /// response was going to arrive into, and the response with it.
  pub const EXCHANGE_IN_FLIGHT: Self =
    Self("an exchange is already outstanding on this connection");

  /// The receive side is not between messages — a response is being read, or
  /// its completion is still waiting on this end's own send side.
  ///
  /// On today's writers this can never be the reported reason: a client's
  /// `recv` leaves `Idle` only once an exchange exists, so
  /// [`EXCHANGE_IN_FLIGHT`](Self::EXCHANGE_IN_FLIGHT) always fires first.
  /// Named and gated anyway — a coincidence between today's writers is not a
  /// rule this type enforces.
  pub const RECV_NOT_IDLE: Self = Self("the receive side is not between messages");

  /// The send side is not between messages: a request body is still being
  /// written, or was abandoned mid-write when the peer's answer released this
  /// end from finishing it. The release is RFC 9112 §9.6's close-after-reading
  /// MUST rather than its "cease sending", whose object is requests: an end told
  /// to "close the connection after reading the response message" is one the
  /// rest of that body will never go out on. Abandoned is not idle — a
  /// switch taken over it would proceed as though that write had never mattered.
  pub const SEND_NOT_IDLE: Self = Self("the send side is not between messages");

  /// The reason this refusal names, which is also what
  /// [`Display`](core::fmt::Display) writes.
  ///
  /// For a log line or an error message. A driver that RECOVERS differently per
  /// gate compares against the constants above instead: the wording is a
  /// message rather than an identifier, and two gates that came to read alike
  /// would still be two distinct values.
  #[inline(always)]
  pub const fn reason(&self) -> &'static str {
    self.0
  }
}

/// The exchange the connection is currently carrying.
///
/// Minted by the server when a request head arrives, and by the client when it
/// opens a request; cleared when both directions of the exchange are through and
/// the connection re-arms. The two method facts travel with it because RFC 9112
/// §6.3 items 1-2 frame a RESPONSE by the REQUEST that provoked it, which is not
/// something the response itself can be read for.
///
/// ONE at a time, and the asymmetry that follows is deliberate rather than an
/// oversight. A server accepts inbound pipelining — RFC 9112 §9.3.2 lets a client
/// send the next request early, and those bytes simply wait unconsumed until the
/// response goes out — but this end never has more than one request of its OWN in
/// flight, so a client reads exactly one response at a time. Outbound pipelining
/// would need a queue of outstanding requests here, which is a storage decision
/// for the task that adds the request API rather than something the receive path
/// can invent.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct Exchange {
  /// The id every item of this exchange carries. [`Item::Switched`] is not one
  /// of them: RFC 9110 §7.8's switch ends HTTP framing on the CONNECTION rather
  /// than reporting anything about the exchange, which it leaves outstanding.
  pub(crate) id: ExchangeId,
  /// The request used HEAD, so item 1 makes its response bodiless "regardless of
  /// the header fields present in the message".
  pub(crate) method_head: bool,
  /// The request used CONNECT, so item 2 makes a 2xx to it bodiless.
  ///
  /// Recorded for the framing rule alone. Whether a CONNECT may be OPENED on a
  /// [`General`] connection at all is the send API's question and a caller-side
  /// one — the inbound path has only this end's own record to go on, so it frames
  /// what it is told rather than second-guessing it. The INBOUND takeover, which
  /// is the half a peer controls, is refused by the receive path instead.
  pub(crate) connect: bool,
  /// The version the REQUEST stated (RFC 9112 §2.3), which is a fact about the
  /// RESPONSE this end may send and one the response cannot be read for.
  ///
  /// §6.1: "A server MUST NOT send a response containing Transfer-Encoding
  /// unless the corresponding request indicates HTTP/1.1 (or later minor
  /// revisions)" — so the version travels with the exchange for the same reason
  /// the two method facts do.
  ///
  /// On a client this is the version of the request THIS end wrote, which
  /// `head::encode` fixes at HTTP/1.1; the field is the server side's to read.
  pub(crate) version: Version,
  /// RFC 9110 §7.8's ordering MUST, kept for the answer rather than for the
  /// receive side: `RecvState::Body`'s copy is cleared when the item is yielded
  /// and overwritten wholesale when the body ends, so by the time an answer is
  /// written the transient fact is gone. The response cannot be read to recover
  /// it.
  pub(crate) expect_unanswered: bool,
  // gate-exempt: outbound::open_request — the SENT half of a two-writer field;
  // this field's own declaration writes neither half, both writers named here
  // are elsewhere, and RECEIVED's writer (`inbound`) is bare prose next to
  // it for the same reason.
  /// Whether the request offered a §7.8 upgrade. RFC 9110 §7.8: "A server MUST
  /// NOT switch to a protocol that was not indicated by the client in the
  /// corresponding request's Upgrade header field."
  ///
  /// TWO WRITERS, and each records the strongest fact its side can know:
  ///
  /// - RECEIVED (`inbound`): both of §7.8's halves, and not on a 1.0 request,
  ///   since the MUST-ignore is folded into `has_upgrade`. A recipient may be
  ///   stricter than the MUST NOT — declining to switch is always allowed — so
  ///   an un-optioned field arriving here is classified as no offer.
  /// - SENT (`outbound::open_request`): §7.8's indication, which is the
  ///   `Upgrade` field alone. A sender may NOT be stricter in the same way,
  ///   because the strictness would be an exemption: the connection option is
  ///   required inside that branch instead (`OFFER_NEEDS_BOTH_HALVES`), so what
  ///   is recorded true here still went out stating both halves on HTTP/1.1.
  pub(crate) upgrade_offered: bool,
  // gate-exempt: outbound::open_request — the client-exchange half of a
  // per-site rule stated over TWO fields' relationship; this field's own
  // declaration hashes nothing itself, so neither named site is this one.
  /// WHICH request that offer came in, as [`head_digest`] of its whole head
  /// block — the fact a `Tunnel` connection answers
  /// [`head_binding`](Connection::head_binding) from once
  /// [`into_tunnel`](Connection::into_tunnel) has carried it across.
  ///
  /// NO ABSENT REPRESENTATION, deliberately: every construction site that did
  /// not hash a head writes a dead value. What keeps a dead one from being read
  /// is stated PER SITE, because one rule over the field would be false at one
  /// of them:
  ///
  /// - **A server's exchange** (`inbound`) hashes exactly when
  ///   [`upgrade_offered`](Self::upgrade_offered) is recorded, and
  ///   `offered_switch` reads it exactly behind that same fact. Here the fact
  ///   beside it IS the validity.
  /// - **A client's exchange** (`outbound::open_request`) never hashes, offer or
  ///   no offer: a permitted §7.8 offer records `upgrade_offered: true` beside a
  ///   dead zero, so the rule above does not hold on this side. What holds
  ///   instead is the ROLE — the sole reader is on `impl Connection<Server,
  ///   General>` and `Ro` is a type parameter, so an exchange a client built
  ///   cannot reach it. A client-side reader is therefore a change to this rule
  ///   and must hash the head where the exchange is built.
  /// - **Past the transition**, a live non-CONNECT handshake, which is the guard
  ///   `Handshake::head_digest` states for itself.
  ///
  /// The phase and the role ARE the validity, which is what keeps this at eight
  /// bytes rather than `Option<u64>`'s sixteen on a struct with a const-asserted
  /// budget, and what makes a genuine digest of `0` harmless rather than a
  /// sentinel collision.
  pub(crate) head_digest: u64,
  /// This end's own limit refused this exchange's inbound body.
  ///
  /// Kept on the EXCHANGE rather than on the connection because it governs what
  /// this end may still WRITE for this message: RFC 9112 §9.3 makes reading the
  /// whole request body or closing the connection a MUST, and a refusal takes
  /// the second branch — so the one response still owed has to state `close`,
  /// and no interim may invite content that will not be read. Nothing clears
  /// it, because a refusal is not undone.
  ///
  /// The SECOND of the two windows that hold this fact, and never read on its
  /// own: [`body_refused`] is what the gates call, because until the refusal is
  /// resolved the fact lives in the decoder instead — which for a head's
  /// declaration gate is every pull until the pump reaches it.
  pub(crate) body_refused: bool,
}

/// Where the inbound side of the connection stands.
///
/// Three states, because the driver-visible questions are three: is the next
/// byte the start of a message, part of the body of one, or the first byte the
/// connection may not touch until its own send side catches up?
// Equality under `cfg(test)` alone, for the reason `BodyDecoder`'s own derive
// carries: a mode-edge differential compares whole connections, and no product
// path asks whether two receive states are the same.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) enum RecvState {
  /// Between messages. The next bytes begin one — a request for a server, the
  /// response to the outstanding request for a client — or, when a client has
  /// nothing outstanding, they are bytes RFC 9112 §9.2 says are not a response
  /// at all.
  Idle,
  /// A head has been yielded and the body it framed is being decoded.
  Body {
    /// The decoder built from this message's RFC 9112 §6.3 framing decision.
    decoder: BodyDecoder,
    /// RFC 9110 §10.1.1: the head carried `Expect: 100-continue` and the ask is
    /// still to be delivered. It is owed BEFORE any body octet, since the point
    /// of the expectation is that the body has not been sent.
    ///
    /// TWO writers clear it, and they state the same invariant — the ask is
    /// delivered at most once, and never after it has stopped being one:
    ///
    /// - the PUMP, when it hands the [`Item::ExpectContinue`] over, so a
    ///   re-offer of the same buffer does not hand it over again;
    /// - the SEND side ([`discharge_expect`]), when a `100 (Continue)` answers
    ///   it or a final response makes it moot. RFC 9110 §15.2 leaves no room for
    ///   an informational response after a final one, so a driver that answered
    ///   the head — before or without pulling the item — must not be told
    ///   afterwards that the ask is still outstanding.
    expect_owed: bool,
  },
  /// The inbound side of the exchange is complete, and the connection is holding
  /// everything after it until the outbound side is complete too.
  ///
  /// RFC 9112 §9.3.2: a server MUST NOT process a pipelined request before the
  /// previous response is finished, so the bytes of the next message stay
  /// unconsumed in the driver's buffer while this state holds.
  AwaitingRearm,
}

/// Where the LOCAL side of the current exchange stands.
///
/// One half of the keep-alive re-arm gate — the half the inbound pump cannot see
/// for itself. RFC 9112 §9.3.2 lets the next exchange begin only once BOTH
/// directions of this one are through, so the receive side's completion is not
/// enough on its own; this is what the send calls in `connection::outbound`
/// move, and [`settle`] is where the two meet.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SendState {
  /// Nothing is owed: the local side of the current exchange, if there is one,
  /// is through.
  Idle,
  /// The local side still owes the rest of this exchange — a server's response
  /// to the request just parsed. Its head has not gone out yet, which is what
  /// makes an interim response still sendable (RFC 9110 §15.2).
  Owed,
  /// The head went out and the body it framed is being written.
  Sending(SendBody),
  /// The exchange ended from the RECEIVE side while this end was still writing
  /// its request body, so the body is abandoned and nothing more may be written.
  ///
  /// RFC 9112 §9.6 makes a client that read the peer's `close` option "close the
  /// connection after reading the response message", so the rest of the body
  /// never goes out; §9.5 says it of the body itself — "the client SHOULD
  /// immediately cease transmitting the body and close its side of the
  /// connection". Nothing is OWED — the
  /// re-arm gate treats this as idle, so receive completion can settle and
  /// `is_awaiting_send` goes false — but it is not [`Idle`](Self::Idle) either:
  /// a caller that goes on writing is told what happened rather than being given
  /// a silent success or a misleading "no body in flight".
  ///
  /// Client-side only. A server's response is owed to a request it already holds
  /// in full, and no inbound event withdraws that.
  Abandoned,
  /// The connection failed and a server owes exactly one error response, after
  /// which no further exchange is possible.
  ///
  /// CARRIES NOTHING, and must not. Whether the end of keep-alive has already
  /// been announced is derivable, and [`Connection::transport`] derives it on
  /// the ask. Caching it here — because the failure latch overwrites the state
  /// that held it, and the owed answer forces a close of its own — would be a
  /// second copy of one bit, put here only because a transition destroyed the
  /// first.
  ErrorOwed,
}

/// The body a head declared, as far as it has been written.
///
/// The send-side twin of [`BodyDecoder`]'s framing: what the peer will use to
/// delimit the message, so it is what a further write is checked against.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SendBody {
  /// RFC 9112 §6.3 item 6: this many octets are still owed. Zero means the count
  /// is satisfied and only [`finish_body`](Connection::finish_body) is left.
  Counted(u64),
  /// RFC 9112 §7.1: the chunked coding, which ends at the `last-chunk` that
  /// [`finish_body`](Connection::finish_body) writes rather than at a count.
  Chunked,
  /// RFC 9112 §6.3 item 8: the body ends when the CONNECTION does, so nothing
  /// on the wire delimits it and there is no state to keep but the fact that a
  /// body is in flight. The octets go out raw and
  /// [`finish_body`](Connection::finish_body) writes none of its own; what ends
  /// the message is the close the head already committed the connection to.
  ToClose,
}

/// Where the connection stands in its life, independently of any one message.
///
/// POLICY ONLY: whether this end will accept another exchange, and whether it
/// has failed. Whether the TRANSPORT can still produce bytes is a separate,
/// orthogonal fact and lives in a field of its own
/// ([`Connection::read_closed`]) — the two are independent (a peer can close its
/// write side without ever stating `close`, and can state `close` without
/// closing anything yet), and folding them into one state machine is how a
/// transition that meant to move one of them silently erased the other.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Lifecycle {
  /// Keep-alive holds: another exchange may begin after this one.
  Open,
  /// Keep-alive is over (RFC 9112 §9.6) — the peer sent the `close` connection
  /// option or the local driver called [`close`](Connection::close) — but the
  /// exchange in flight may still finish.
  Closing,
  /// No further inbound byte is processed. §9.6 makes this a MUST rather than a
  /// courtesy: a recipient that kept parsing pipelined requests after close was
  /// signalled would be acting on messages the sender has already given up on.
  Draining,
  /// A protocol violation was surfaced. The violation is handed back exactly
  /// once, by the call that found it; every call after that is caller-side
  /// misuse.
  Failed,
}

/// A protocol violation was surfaced already; the connection has nothing else to
/// say about the wire.
pub(crate) const FAILED: &str = "connection failed on a protocol violation";

/// The connection has drained (RFC 9112 §9.6): keep-alive is over and the
/// exchange that was in flight, if any, is through.
pub(crate) const DRAINED: &str = "connection is draining";

/// Whether the connection is in a state that can still ACT on a caller's call at
/// all — the lifecycle gate, stated ONCE.
///
/// Two callers in opposite directions: [`Connection::sendable`], which every
/// send call opens with, and [`Items::limit_body`], which narrows the ceiling on
/// the body being received. The rule is the same for both because it is about
/// the CONNECTION rather than about either direction — a failed connection has
/// handed its one violation back, a drained one is past RFC 9112 §9.6's point of
/// no return — and two statements of it would be free to drift apart while
/// nothing made them. That is the failure this crate's own
/// [`peer_close_effects`] records twice.
///
/// POLICY decides it and the transport fact deliberately does not appear: the
/// peer shutting its WRITE side says nothing about whether it is still reading
/// the response it asked for (RFC 9112 §9.5), so a closed read side must not
/// refuse an owed answer to a request that arrived in full.
///
/// BY VALUE, so it can read the lifecycle and cannot write it — the same
/// argument [`signal_close`] and [`latch`] are already written to. Exhaustive,
/// so a [`Lifecycle`] variant added later is a compile error here rather than a
/// silent default at either caller.
///
/// [`Items::limit_body`]: crate::Items::limit_body
pub(crate) const fn writable(lifecycle: Lifecycle) -> Result<(), Error> {
  match lifecycle {
    Lifecycle::Failed => Err(Error::InvalidState(FAILED)),
    Lifecycle::Draining => Err(Error::InvalidState(DRAINED)),
    Lifecycle::Open | Lifecycle::Closing => Ok(()),
  }
}

/// The HTTP/1.1 connection state machine.
///
/// Sans-I/O and no-alloc: it owns no socket, no timer, and no buffer. The driver
/// reads bytes, offers them to [`handle`](Self::handle), drains the borrowed
/// [`Item`]s that come back, and acts on them; the connection keeps only where
/// in the protocol those bytes left it.
///
/// # Driving it
///
/// 1. Offer the accumulation buffer from its unconsumed start to
///    [`handle`](Self::handle) and pull [`Items::next`] until it answers
///    `Ok(None)`.
/// 2. Advance the buffer by [`Items::consumed`].
/// 3. Ask WHY the items ran out: [`wants_read`](Self::wants_read) says more
///    transport bytes would help, [`is_awaiting_send`](Self::is_awaiting_send)
///    says the local send side is what is missing. The two are split because
///    `Ok(None)` alone cannot tell a driver whether to read the socket or to
///    write to it.
/// 4. Drain [`poll_event`](Self::poll_event) for the connection-scoped notices.
/// 5. On transport EOF, call [`handle_eof`](Self::handle_eof) once.
///
/// # What it refuses
///
/// A protocol violation is terminal. [`Items::next`] hands it back once, the
/// connection latches, and everything afterwards is
/// [`Error::InvalidState`] — including a later `handle`, whose first `next` is
/// where the latch surfaces. A server whose response to the message in flight has
/// not started going out is left owing exactly one error response, which
/// [`is_awaiting_send`](Self::is_awaiting_send) reports; one that has
/// already answered owes nothing, since a second final response would be read as
/// part of the first.
/// # Which fields which mode uses
///
/// The struct is shared by both modes and the type-state decides which of it is
/// live. A [`Tunnel`] connection uses five of the fields below: `watermark` (the
/// same resumable head scan), `lifecycle` (the failure latch), `tunnel`, and the
/// pair that carries the TRANSPORT's own ending, which is not a General fact —
/// `read_closed`, which its reads consult to tell a stop for want of bytes from
/// a truncation and which [`transport`](Self::transport) reads beside the
/// lifecycle. It touches none of the rest: it
/// has no exchange to number, no receive or send FSM to advance, no tail to
/// resolve, and no idle cursor a stray CRLF could sit at, since a tunnel client
/// reads nothing before it has written its request and a tunnel server's first
/// byte is its request-line's. The General fields are documented as General's
/// own below.
#[derive(Debug)]
pub struct Connection<Ro, Mo> {
  /// GENERAL. Bytes of the CURRENT offer that have been consumed. Reset by every
  /// [`handle`](Self::handle), because each offer starts at the driver's
  /// unconsumed byte; it lives here rather than in [`Items`] so that dropping
  /// the iterator cannot lose it.
  consumed: usize,
  /// BOTH MODES. How far into the head being accumulated the scan has already
  /// looked, so repeated feeds over a growing buffer stay linear in total. Reset
  /// to zero when a head completes and when the connection re-arms: it belongs
  /// to ONE head.
  watermark: usize,
  /// GENERAL. The number the next exchange to begin on this connection will
  /// take. The counter is the connection's, which is what makes [`ExchangeId`]s
  /// monotone.
  next_exchange: u64,
  /// GENERAL. Where the inbound side stands.
  recv: RecvState,
  /// GENERAL. The exchange in flight, if any.
  exchange: Option<Exchange>,
  /// GENERAL. Where the local side stands — the other half of the re-arm gate.
  send: SendState,
  /// BOTH MODES. Where the connection stands in its life — POLICY and failure
  /// only. A tunnel uses only [`Lifecycle::Failed`], since a handshake that ends
  /// is terminal in its own right and there is no keep-alive to tear down.
  lifecycle: Lifecycle,
  /// GENERAL. The PEER's write side has ended, so no further byte can arrive.
  ///
  // gate-exempt: inbound::no_more_input — names the pump function that READS
  // this field once set; the field's own declaration only latches the flag,
  // it never itself calls the reader.
  /// Its own field rather than a `Lifecycle` state, and that is the whole point:
  /// "can the transport still produce bytes?" and "will this end accept another
  /// exchange?" are ORTHOGONAL — a peer can half-close without ever stating
  /// `close`, and can state `close` while its write side stays open — so a
  /// single state machine carrying both has transitions that move one dimension
  /// and silently drop the other. Set once by [`latch_read_closed`] and never
  /// cleared, so no lifecycle transition can erase it.
  ///
  /// Read wherever the question is "will more input come?": `wants_read`, and
  /// the pump's need-more decisions (`inbound::no_more_input`), which is where a
  /// stop for want of bytes becomes either exhaustion or a truncation.
  read_closed: bool,
  /// The PEER stated RFC 9112 §9.6's `close` connection option, on some head this
  /// connection received — or sent a response §6.3 item 8 delimits by the close,
  /// which says the same thing without a field.
  ///
  /// PROVENANCE, and its own field for the reason [`read_closed`] is:
  /// [`Lifecycle::Closing`] answers "will another exchange begin on this
  /// connection?", which BOTH ends can decide, while this answers "will the peer
  /// go on READING?", which only the peer can. The two have different
  /// consequences — §9.6's "cease sending" releases this end's outstanding
  /// request body when the PEER is closing, and deliberately does not when the
  /// local driver called [`close`](Connection::close), since §9.6 lets the
  /// exchange in flight finish. A decision taken from `Closing` cannot tell them
  /// apart.
  ///
  /// Sticky, and that is the other half: an interim head may carry the option
  /// (RFC 9110 §15.2 lets any number precede the final response), and the final
  /// head that ends the exchange need not repeat it. Reading the current head
  /// alone forgets what an earlier one said.
  ///
  /// Set only from a head this connection RECEIVED. A local `close()` and this
  /// end's own outbound `close` option move the lifecycle and never this.
  ///
  /// [`read_closed`]: Self::read_closed
  peer_close: bool,
  /// GENERAL. The exchange that ended without its final response, waiting to be
  /// reported as [`Event::ExchangeAborted`].
  ///
  /// THE ONLY QUEUED SLOT on this connection. What it holds is message-scoped,
  /// which is exactly the fact a level cannot carry: the exchange it names is
  /// destroyed at `settle` before a driver could ask about it. The
  /// connection-scoped fact — the end of keep-alive — is not stored at all;
  /// [`transport`](Connection::transport) derives it on the ask.
  aborted: Option<ExchangeId>,
  /// GENERAL, client only. An exchange completed and the offer that completed it
  /// may still hold bytes this connection has not read back.
  ///
  /// The barrier under RFC 9112 §9.2. A client that opens its next request while
  /// such a tail is outstanding would have the tail parsed as the NEW request's
  /// response — bytes that arrived before that request was written, which §9.2
  /// says "MUST NOT" be considered a response at all. The idle path already
  /// diagnoses them; what this preserves is that they are still on the IDLE path
  /// when they are read, instead of being adopted by an exchange opened over
  /// them.
  ///
  /// Set by the pump when a client exchange completes, and cleared only by the
  /// pump — on the pass that reaches the idle boundary with the offer fully
  /// consumed, or by the §9.2 diagnosis, which latches. The connection cannot
  /// see the driver's buffer, so exhaustion is not something this end may assume:
  /// the same epistemics the EOF path is built on.
  tail_unresolved: bool,
  /// BOTH MODES. Where the ONE protocol takeover this connection can carry
  /// stands. Its own field rather than a reading of the General states above:
  /// those states describe a message being framed, and this one's question is
  /// whether the connection is still HTTP at all.
  ///
  /// TUNNEL walks the whole enum: a handshake is opened or classified, and then
  /// answered. GENERAL writes exactly one of its values, and only on a CLIENT
  /// whose operator permitted an opportunistic upgrade and whose request made
  /// the offer — the inbound pump writes `TunnelPhase::Switched` in the same
  /// step that yields [`Item::Switched`], and no other General path writes the
  /// field at all. So a General connection reads `Idle` until RFC 9110 §7.8's
  /// switch and `Switched` for the rest of its life, which is the whole of what
  /// `live_general_phase` asks it.
  tunnel: TunnelPhase,
  /// GENERAL. A lone `\r` is sitting unconsumed at a client's idle cursor, waiting for the
  /// byte that decides it (RFC 9112 §2.2: a CR is a line terminator only once its
  /// LF has arrived, and a CR at the end of a read proves nothing).
  ///
  /// Its own field rather than a value folded into the watermark: the watermark
  /// is progress through a head being scanned, this is an undecided terminator in
  /// front of bytes no head has claimed, and the two are written on different
  /// paths. At most one CR is ever pending — the CRLF pairs before it were
  /// discarded on the spot — so this cannot accumulate across offers.
  pending_cr: bool,
  /// GENERAL, client only. How many stray empty lines this connection has
  /// DISCARDED since its last request (RFC 9112 §9.2), bounded by
  /// `head::scan::MAX_LEADING_EMPTY_LINES`.
  ///
  /// The tally lives here because the bytes do not: an idle client CONSUMES the
  /// CRLF pairs it discards, so a bound counted per offer would reset with every
  /// read and leave a peer that dribbles one pair at a time an unbounded
  /// keep-alive channel on a connection with nothing outstanding. A server needs
  /// no such field — its leading empty lines are left unconsumed, so the growing
  /// region they sit in carries the count for them.
  ///
  /// Cleared by [`open_request`](Connection::open_request): the allowance is per
  /// idle period rather than per connection. A `u8` because the bound is a
  /// single digit and the counter saturates.
  idle_crlfs: u8,
  /// BOTH MODES. The OPERATOR'S CEILING on the payload octets one inbound body
  /// may deliver, resolved at construction from [`Limits`].
  ///
  /// ONE WRITER, and it is the constructor. There is no setter, no `&mut` path
  /// to this field, and no consuming builder on a live connection; it reaches
  /// the receive pump BY VALUE (a `u64` copy in [`Items`], beside `is_client`),
  /// so no step of the pump can raise it even by accident. That is a property
  /// of the field having one writer, not a convention — the same argument
  /// [`signal_close`] makes about taking `read_closed` by value.
  ///
  /// Mode-generic, and carried across [`into_tunnel`](Connection::into_tunnel):
  /// the ceiling is a property of the connection. It is inert in Tunnel mode —
  /// RFC 9110 §9.3.6 gives CONNECT no content and this core refuses content on
  /// a handshake — and it neither constrains nor seeds whatever bounds the
  /// protocol on the other side of a switch applies to its own messages.
  max_body: u64,
  /// BOTH MODES. The OPERATOR'S resolved permission to offer an RFC 9110 §7.8
  /// upgrade on an ordinary exchange, and to accept the 101 that answers one —
  /// copied from [`Limits::opportunistic_upgrade_allowed`] at construction.
  ///
  /// ONE WRITER, and it is the constructor, for the same reason `max_body` is:
  /// there is no setter and no `&mut` path to this field on a live connection,
  /// so a ceiling stated at construction cannot be raised mid-connection.
  opportunistic_upgrade: bool,
  /// BOTH MODES. The budget for the RFC 9112 §7.1 chunk-size lines one inbound
  /// body may spend, resolved at construction from [`Limits`].
  ///
  /// One writer, by value, for the same reason `max_body` is. Carried and
  /// readable from the day the type exists so that the resolution rule has one
  /// spelling — [`Limits::max_chunk_framing_bytes`] — rather than a second one
  /// re-derived here.
  max_chunk_framing: u64,
  /// The type-state. Zero-sized, so the markers cost the connection nothing.
  shape: PhantomData<(Ro, Mo)>,
}

impl<Ro: Role, Mo: Mode> Default for Connection<Ro, Mo> {
  fn default() -> Self {
    Self::new()
  }
}

impl<Ro: Role, Mo: Mode> Connection<Ro, Mo> {
  /// A connection with nothing in flight, ready for its first exchange.
  ///
  /// Exchange ids start at 1, so a zero is never an id this core minted.
  ///
  /// Bounded like [`HashMap::with_hasher`](std::collections::HashMap::with_hasher),
  /// and for the same reason: a constructor decides what a meaningful value of
  /// the type IS, and this crate's type-state argument is that a mode is a real
  /// capability set rather than an arbitrary parameter. It is also the bound that
  /// makes every OTHER impl's widening free rather than a trade — `Connection`'s
  /// fields are all private, so a `Connection<SomeForeign, SomeOther>` cannot be
  /// built by any route except this one, and this one still refuses it.
  ///
  /// `Self::with_limits(Self::default_limits())`, so the defaults are stated in
  /// one place and this constructor is not a second one.
  #[inline]
  pub const fn new() -> Self {
    Self::with_limits(Self::default_limits())
  }

  /// The defaults this connection's ROLE would be constructed with — the seed a
  /// caller narrows from.
  ///
  /// The only place a role is in scope, which is why the role's chunk-framing
  /// floor is captured here rather than looked up later. The framing budget
  /// itself is left UNSET, so that a caller who narrows or raises the payload
  /// ceiling carries the framing budget with it: seeding it with a value would
  /// make `default_limits().with_max_body_bytes(100 << 20)` keep a 64 KiB
  /// framing budget and refuse ordinary chunked traffic well inside its own
  /// payload allowance.
  #[must_use]
  #[inline]
  pub const fn default_limits() -> Limits {
    Limits {
      payload: Ro::DEFAULT_MAX_BODY_BYTES,
      framing: None,
      floor: Ro::DEFAULT_MAX_CHUNK_FRAMING_BYTES,
      opportunistic_upgrade: false,
    }
  }

  /// A connection with nothing in flight, bounded by `limits`.
  ///
  /// The limits are read here and nowhere else: the connection copies the two
  /// resolved numbers and keeps no path back to the type they came from.
  ///
  /// The ceiling a driver states here is the connection's MAXIMUM, and the
  /// value to construct with is therefore the maximum over every route this
  /// connection may serve. [`Items::limit_body`] can only narrow it, and it
  /// narrows by `min` and does not report having done so: a route asking for 8
  /// MiB on a connection built with 1 MiB answers `Ok` and is granted 1 MiB. A
  /// ceiling constructed from any one route's limit therefore silently caps
  /// every route above it.
  #[must_use]
  #[inline]
  pub const fn with_limits(limits: Limits) -> Self {
    Self {
      consumed: 0,
      watermark: 0,
      next_exchange: 1,
      recv: RecvState::Idle,
      exchange: None,
      send: SendState::Idle,
      lifecycle: Lifecycle::Open,
      read_closed: false,
      peer_close: false,
      tail_unresolved: false,
      aborted: None,
      tunnel: TunnelPhase::Idle,
      pending_cr: false,
      idle_crlfs: 0,
      max_body: limits.max_body_bytes(),
      opportunistic_upgrade: limits.opportunistic_upgrade_allowed(),
      // Obtained by CALLING the resolution rather than re-deriving it: written
      // the other way — this connection applying its own `Ro`'s floor to a seed
      // minted from another role — the two answers to one question would differ
      // by a factor of 64, and the getter would disagree with the connection.
      max_chunk_framing: limits.max_chunk_framing_bytes(),
      shape: PhantomData,
    }
  }
}

impl<Ro, Mo> Connection<Ro, Mo> {
  /// The operator's ceiling on the payload octets one inbound message body may
  /// deliver. Constant for the connection's life.
  ///
  /// A per-message limit, not a per-connection total: each body starts from
  /// zero. A breach is [`Error::Refused`], not a protocol failure.
  #[must_use]
  #[inline]
  pub const fn max_body_bytes(&self) -> u64 {
    self.max_body
  }

  /// The budget for the RFC 9112 §7.1 chunk-size lines one inbound body may
  /// spend, as resolved at construction. Constant for the connection's life.
  ///
  /// Observable because a budget that refuses traffic must be readable by the
  /// operator who set the payload ceiling it was resolved from — see
  /// [`Limits::max_chunk_framing_bytes`], which also states what is charged
  /// against it. A body that spends more is refused with
  /// [`Refusal::ChunkFramingTooLarge`].
  ///
  /// PER MESSAGE, like the payload ceiling: every body on a keep-alive
  /// connection starts with the whole budget.
  #[must_use]
  #[inline]
  pub const fn max_chunk_framing_bytes(&self) -> u64 {
    self.max_chunk_framing
  }

  /// Takes the next queued connection-scoped notice, or `None`.
  ///
  /// Mode-generic, though only General can produce what it carries: an
  /// [`Event`] is a fact about a MESSAGE, and Tunnel frames none. It stays on
  /// both modes so a driver polls one surface rather than remembering which mode
  /// it is holding.
  ///
  /// Drained after the items rather than among them: an [`Event`] is a fact about
  /// the connection, not about any byte of the input, so it neither borrows the
  /// input nor has a place in the item order.
  /// The EXCHANGE-scoped notice comes first: it names a message the driver was
  /// tracking, while the connection-scoped one is about everything. A driver that
  /// acted on the close before hearing which exchange died would have to work out
  /// the second from the first, which is what the abort exists to spare it.
  ///
  /// `Role`- and `Mode`-free: it reads only `aborted` and `event`, neither of
  /// which either type-state answers a question about.
  ///
  /// Not gated by RFC 9110 §7.8's switch either: an abort names a message that
  /// ended before the transport changed hands, and it stays true afterwards.
  /// What the driver should DO with that transport is
  /// [`transport`](Self::transport), which answers
  /// [`Transport::HandedOver`] — so this call
  /// carries no instruction and needs no gate.
  #[inline]
  pub fn poll_event(&mut self) -> Option<Event> {
    self
      .aborted
      .take()
      .map(|exchange| Event::ExchangeAborted { exchange })
  }

  /// What the driver should now do with the transport — see [`Transport`].
  ///
  /// DERIVED, on every ask, from state this connection already holds. Nothing is
  /// stored and nothing is consumed, so asking twice is two reads rather than
  /// two instructions, and a driver that never asks is told nothing rather than
  /// losing something.
  ///
  /// # The derivation, and why the order is the answer
  ///
  /// One `match`, exhaustive over `TunnelPhase` and `Lifecycle`, so a phase
  /// or a lifecycle state added later is a compile error here rather than a
  /// channel somebody forgot to teach. `Role`- and `Mode`-free by construction,
  /// because every field it reads is shared by all four type-states: a fix
  /// applied to one mode and not the other is not a shape this can take.
  ///
  /// 1. **The phase first.** A completed handover is absorbing and outranks
  ///    everything: RFC 9110 §7.8 leaves the server still owing an answer in the
  ///    new protocol, so the transport is the negotiated protocol's whatever
  ///    this connection went on to record about itself. This is where "a switch
  ///    wins over a local close" lives now — as one arm's position in one
  ///    `match`, rather than as machinery that defers a notice and then has to
  ///    decide when to stop.
  /// 2. **Then the failure latch**, which is absorbing for the same reason and
  ///    is checked before the disjunction below because it also satisfies it.
  /// 3. **Then the end of keep-alive**: RFC 9112 §9.6's option or a local close
  ///    took the lifecycle off `Lifecycle::Open`, or the read side ended. One
  ///    answer for all three, and it is the disjunction the failure latch has
  ///    always computed for itself.
  /// 4. **Otherwise the connection is this crate's**, and the readiness
  ///    accessors say what to do with it.
  #[must_use]
  #[inline]
  pub const fn transport(&self) -> Transport {
    match self.tunnel {
      TunnelPhase::Switched => Transport::HandedOver,
      // TERMINAL, and the lifecycle cannot say so. All three writers of this
      // phase leave `Lifecycle::Open` — a client reading an ordinary final
      // refusal, a client reading a persistence-ending interim, and a server
      // that successfully wrote `reject` — so projecting it from the lifecycle
      // would report `Live` for a connection whose every later call fails, and a
      // driver treating this accessor as authoritative could pool a dead socket.
      //
      // `Failed` still wins, because a connection can fail and then be rejected:
      // `refuse` sets `RejectionOwed` and latches, and `reject` moves the phase
      // here while the lifecycle stays `Failed`.
      //
      // `RejectionOwed` joins it: it means a server owes exactly one rejection
      // and nothing after it, which is not `Live` either. It is unreachable
      // beside `Open` today — `refuse` sets it and latches in the same call —
      // and it is answered anyway, because "the lifecycle happens to say so" is
      // not an argument that a phase is live.
      TunnelPhase::Refused | TunnelPhase::RejectionOwed => match self.lifecycle {
        Lifecycle::Failed => Transport::Failed,
        Lifecycle::Open | Lifecycle::Closing | Lifecycle::Draining => Transport::Ending,
      },
      TunnelPhase::Idle | TunnelPhase::Handshaking(_) => match self.lifecycle {
        Lifecycle::Failed => Transport::Failed,
        Lifecycle::Closing | Lifecycle::Draining => Transport::Ending,
        Lifecycle::Open => {
          if self.read_closed {
            Transport::Ending
          } else {
            Transport::Live
          }
        }
      },
    }
  }
}

// `Ro` is free, and that is the guard's own claim: RFC 9110 §7.8's switch is a
// fact about the CONNECTION, not about either end's message state, so nothing
// that reads it needs the role. A `Connection<Server, General>` cannot reach the
// phase today — the arm that writes it lives on the client's response path — and
// a bound here would say the opposite: that the answer depends on which end is
// asking.
impl<Ro> Connection<Ro, General> {
  /// The RFC 9110 §7.8 phase, for a General connection that may have switched.
  ///
  /// General's mirror of [`live_phase`], and the ONE reader of the phase on this
  /// surface: after the switch this connection is spent — the driver holds the
  /// leftover, and §15.2.2 makes the 101 the head that "indicates which
  /// protocol(s) will be in effect after this response" — so every entry point
  /// that can refuse consults this, and the accessors that cannot refuse read it
  /// through `is_err`. One reader is what keeps the answer from drifting between
  /// them.
  ///
  /// The failure latch is deliberately NOT read here. Each caller keeps its own,
  /// because they order it differently on purpose ([`body_sendable`] puts the
  /// specific reason ahead of the generic one), and the two facts cannot both
  /// hold: a failed connection's pump refuses before it can parse the 101, and a
  /// switched connection's pump refuses before it can parse anything that would
  /// latch.
  ///
  /// [`live_phase`]: Connection::live_phase
  /// [`body_sendable`]: Connection::body_sendable
  fn live_general_phase(&self) -> Result<(), Error> {
    if matches!(self.tunnel, TunnelPhase::Switched) {
      return Err(Error::InvalidState(SWITCHED));
    }
    Ok(())
  }
}

/// The General-mode connection API.
///
/// Everything below is a rule about MESSAGES — the receive FSM, the keep-alive
/// gate, the lifecycle those two share — so none of it exists on a [`Tunnel`]
/// connection, whose bytes stop being HTTP at the head that switches. The
/// separation is the type-state's whole point: `Tunnel`'s own doc pins it with
/// `compile_fail` proofs.
impl<Ro: Role> Connection<Ro, General> {
  /// Offers inbound bytes and returns the items they produce.
  ///
  /// `input` is the driver's APPEND-ONLY accumulation buffer, offered from its
  /// unconsumed start: the connection re-reads whatever it did not consume last
  /// time, so a message split across reads is assembled by the driver's buffer
  /// growing rather than by a buffer in here. Offering a slice that does NOT
  /// begin where the last [`Items::consumed`] left off is caller error — the
  /// connection has no way to detect it, and the bytes would be misattributed.
  ///
  /// A head is consumed only once the whole block is present: a partial head
  /// answers `Ok(None)` with `consumed` still zero across the head region, and
  /// the scan resumes where it left off rather than restarting. A body's octets
  /// are consumed as the items carrying them are yielded.
  ///
  /// The returned iterator borrows this connection for as long as it lives, and
  /// borrows the input for longer: the items it yields point into `input` and
  /// stay valid after the iterator is gone.
  #[inline]
  pub fn handle<'a>(&mut self, input: &'a [u8]) -> Items<'a, '_> {
    // Each offer starts at the driver's unconsumed byte, so the count is per
    // offer; the FSM state it left behind is what carries across.
    self.consumed = 0;
    let Self {
      consumed,
      watermark,
      next_exchange,
      recv,
      exchange,
      send,
      tunnel,
      lifecycle,
      read_closed,
      peer_close,
      tail_unresolved,
      aborted,
      pending_cr,
      idle_crlfs,
      max_body,
      max_chunk_framing,
      ..
    } = self;
    Items::new(
      input,
      Borrows {
        is_client: Ro::IS_CLIENT,
        // BY VALUE, which is the whole of the "cannot be raised" argument: the
        // pump is handed a copy, so no step of it can write the field back.
        max_body: *max_body,
        max_chunk_framing: *max_chunk_framing,
        consumed,
        watermark,
        next_exchange,
        recv,
        exchange,
        send,
        tunnel,
        lifecycle,
        read_closed,
        peer_close,
        tail_unresolved,
        aborted,
        pending_cr,
        idle_crlfs,
      },
    )
  }

  /// Signals that the transport reached end of input.
  ///
  /// Yields no item today, and the `Option` says so rather than promising one:
  /// this call observes the transport and draws no conclusion that depends on
  /// the driver's buffer, which is where every remaining item comes from (see
  /// "What this call does NOT conclude" below). The shape is kept so the EOF has
  /// a channel if an item ever becomes owed by the transport alone.
  ///
  /// An EOF is not one event. What it means depends on the ROLE, on how far the
  /// message in flight had got, and on whether this end still owes the other
  /// half of the exchange — and the three answers a driver can be given (an
  /// item, silence, an error) are far too few to be handed out by feel. The
  /// table below is the whole decision, and every row of it is pinned by a test.
  ///
  /// | Role | Receive side | Send side | Answer |
  /// |---|---|---|---|
  /// | either | between messages, nothing in flight | idle | `Ok(None)` — RFC 9112 §9.5's ordinary end of a persistent connection. Drains |
  /// | either | a head still accumulating (`watermark > 0`) | any | `Ok(None)` here; **`Err`** (`CLOSED_MID_HEAD`) from the re-offer that exhausts the buffer — §2.1 makes a message begin with a complete head |
  /// | either | a counted or chunked body still owed octets | any | `Ok(None)` here; **`Err`** from the re-offer — §6.3 item 6's MUST-incomplete, and §7.1's for a chunked body whose trailer section never closed |
  /// | either | a close-delimited body (item 8) | any | `Ok(Some(ExchangeComplete))` — the close IS the delimiter |
  /// | either | a body whose octets all arrived, item not yet pulled | see below | `Ok(Some(ExchangeComplete))` — an intact message, and the item stream says so rather than ending on silence |
  /// | **client** | idle with an exchange outstanding — no final head, or interim heads only | any | `Ok(None)` here; **`Err`** (`CLOSED_BEFORE_RESPONSE`) from the re-offer — §9.5: the request went out and no response came back, and an interim head is explicitly not one (RFC 9110 §15.2) |
  /// | **client** | receive side complete | its own request body still owed | `Ok(…)`, and the unwritten body is abandoned — §9.6 tells a client whose peer is closing to "cease sending", so it is not an obligation to preserve |
  /// | **server** | any state that is not a truncation | any | `Ok(…)`, and the connection latches `read_closed` rather than draining: an owed response SURVIVES, and so does every request the peer pipelined behind it |
  /// | **client** | switched under RFC 9110 §7.8 | any | `Err(Error::InvalidState)` — the transport belongs to the protocol the 101 named, so this call reads nothing off it and records nothing about it |
  /// | either | already failed | any | `Err(Error::InvalidState)` — the violation was handed back once, by the call that found it |
  ///
  /// # What this call does NOT conclude, and the driver step that follows
  ///
  /// It never reports a truncation, and it never completes a body. Both are
  /// claims about bytes that may be sitting in the DRIVER's buffer, unoffered —
  /// [`Items`] is explicit that a driver may stop pulling mid-stream and re-offer
  /// the remainder later — and this connection cannot see that buffer. A call
  /// that guessed either way would fail an intact message, or complete one over
  /// octets it then discarded.
  ///
  /// So every buffer-dependent conclusion belongs to the PUMP, which is the only
  /// place the buffer is visible: the truncations above, §6.3 item 8's
  /// close-delimited completion, and the drain that ends the connection. **After reporting EOF, re-offer the buffer to
  /// [`handle`](Self::handle) until the connection drains or reports the fault.**
  /// An EMPTY slice is a sufficient re-offer, and is what resolves the EOF when
  /// the buffer is already empty.
  ///
  /// A pending CR is not a trace of a message: RFC 9112 §2.2 makes a CR a
  /// terminator only once its LF has arrived, and one sitting at an idle client's
  /// cursor is in front of bytes no head has claimed — so an EOF over it is the
  /// clean close §9.5 describes, not a truncation.
  ///
  /// # The half-closed row
  ///
  /// A peer that shuts its write side and waits for the answer is doing legal
  /// HTTP, and destroying the owed response would be this core's own fault: the
  /// request arrived in full, so the peer is entitled to what it asked for. RFC
  /// 9112 §9.6 says it outright — "a TCP connection that is half-closed by the
  /// client does not delimit a request message, nor does it imply that the
  /// client is no longer interested in a response".
  ///
  /// That sentence also settles what happens to anything the peer PIPELINED
  /// behind the message being answered. §9.3.2 left those bytes unconsumed in the
  /// driver's buffer until the current response went out; the FIN says the peer
  /// will send no MORE, not that it withdrew what it already sent. So the
  /// connection keeps serving them: each response re-arms it, the driver
  /// re-offers its buffer, and the next buffered request is read and answered in
  /// §9.3.2's order. It drains when that buffer is exhausted at a message
  /// boundary — or at once, if a `close` connection option appears, which is the
  /// rule that really does forbid processing anything further.
  ///
  /// Throughout it, [`wants_read`](Self::wants_read) is false (the socket has
  /// nothing left to give; re-offering the BUFFER is what makes progress),
  /// [`is_awaiting_send`](Self::is_awaiting_send) is true while a reply is owed,
  /// and every send call keeps working. The close is signalled once, here, so a
  /// driver knows before it writes that no NEW exchange will follow.
  ///
  /// # WHEN the EOF is reported does not change WHAT it means
  ///
  /// The read side closing is a fact about the transport. It is therefore
  /// latched on its own (`latch_read_closed`) rather than read off whatever
  /// exchange happened to be in flight when the driver got round to reporting
  /// it — an EOF that arrives between two pipelined requests means exactly what
  /// one that arrives mid-exchange means, and a rule derived from the exchange
  /// state says otherwise. Every ordering below lands in the same place:
  ///
  /// | Ordering | Result |
  /// |---|---|
  /// | EOF, then the response | `read_closed`; the response is owed and sendable, and the buffered request behind it is served after it |
  /// | The response, re-arm, THEN the EOF | `read_closed` — the receive side is idle and nothing is owed, and it still must not drain, because the driver may be holding the next request |
  /// | EOF, response, re-arm, EOF again | unchanged: re-latching is a no-op, and nothing clears the flag |
  /// | EOF at a boundary with the buffer truly empty | `read_closed`, then `Draining` on the next re-offer — the connection cannot see the driver's buffer, so exhaustion is the PUMP's finding, not this call's |
  /// | EOF with a message part-received | `read_closed`; the truncation is the PUMP's finding too, for exactly the same reason, and on exactly the same re-offer |
  /// | EOF after a `close` option | `Closing` AND `read_closed`, which is the point of keeping them apart: the option suppresses whatever was pipelined behind it (§9.6), and the transport fact still stops `wants_read` and still turns a stop for want of bytes into a truncation |
  ///
  /// A FAILED connection is not half-closed either: a violation found at EOF has
  /// nobody left to answer, which is why the `answerable` flag is false below.
  ///
  /// Idempotent: a driver may report the same EOF twice.
  pub fn handle_eof(&mut self) -> Result<Option<Item<'static>>, Error> {
    // The transport stopped belonging to this connection at the 101, so an EOF
    // on it is not this connection's news and NOTHING here may act on it:
    // latching `read_closed` would rewrite a spent connection's state, and
    // abandoning the send side would write off a request RFC 9110 §7.8 leaves
    // alive — "the server still has an outstanding request to satisfy after the
    // protocol has been changed", in a protocol this core does not read.
    //
    // Ahead of the failure latch, which costs nothing: the two cannot both hold,
    // since a switched connection's pump refuses before it can parse anything
    // that would latch.
    self.live_general_phase()?;
    if matches!(self.lifecycle, Lifecycle::Failed) {
      return Err(Error::InvalidState(FAILED));
    }
    // The transport fact, latched for BOTH roles and before anything else is
    // decided: it is the only thing this call actually observes.
    latch_read_closed(&mut self.read_closed);

    // RFC 9112 §9.6 tells the sender of a request to "cease sending" once the
    // peer is closing, so a CLIENT's unwritten request body is abandoned. This
    // is the ONLY other thing this call decides, and it is not buffer-dependent:
    // it is a fact about THIS end's send side, and no byte the peer might still
    // have buffered could make the body deliverable.
    //
    // Clearing it is what keeps the readiness split honest: left in place,
    // `is_awaiting_send` would report an obligation that can never be met.
    if Ro::IS_CLIENT {
      abandon_send(&mut self.send);
    }

    Ok(None)
  }

  /// Whether more transport bytes would let the connection make progress.
  ///
  /// The read half of the readiness split, and it consults every one of the
  /// connection's independent facts — reading is pointless if any says so:
  ///
  /// - this connection SWITCHED protocols (RFC 9110 §7.8), so the bytes on that
  ///   transport are the next protocol's and this end must never ask for them;
  /// - the TRANSPORT can produce no more bytes (`read_closed`), whatever this end
  ///   would have been willing to do with them;
  /// - or POLICY has ended the connection (failed, or drained under RFC 9112
  ///   §9.6), the inbound side is waiting on the local send side, or this is a
  ///   client with no outstanding request — for which §9.2 makes arriving data a
  ///   fault rather than progress.
  ///
  /// # The switch is answered from the PHASE, and it has to be
  ///
  /// The switch RETAINS the exchange — §7.8 leaves the server with "an
  /// outstanding request to satisfy after the protocol has been changed", so
  /// nothing was aborted and nothing completed — and the idle-client rule below
  /// reads exactly that: an outstanding exchange is a response still to come. An
  /// exchange-first answer would therefore report `true` on a connection whose
  /// every further byte belongs to somebody else. The phase is read first, and
  /// the answer is `false`.
  ///
  /// # A body being received is not the same as a body that needs an octet
  ///
  /// The question is asked of the DECODER — `BodyDecoder::wants_input` — never
  /// of the receive state that holds it. A body whose octets have all arrived, and a
  /// body this end has REFUSED, are both mid-`Body` and neither can be moved by
  /// another read: the first owes an item the next call produces from bytes
  /// already in hand, and the second answers every further octet with the same
  /// refusal. Answering "read" for either tells a driver to wait for input that
  /// changes nothing — and against a peer withholding its content until it is
  /// answered (RFC 9110 §10.1.1's `Expect: 100-continue`) both ends then wait
  /// until a timeout breaks the tie.
  ///
  /// # A PENDING CONCLUSION, and the one rule a driver needs for it
  ///
  /// So `false` here while a message is still being received means something
  /// specific and new: **the pump owes an item or an error that no further
  /// octet can change.** Re-offer what the driver already holds — an EMPTY
  /// slice is a sufficient offer — and [`Items::next`] hands it over: the
  /// `ExchangeComplete` of a body already through, or the
  /// [`Error::Refused`] of one this end declined. That
  /// is the same rule [`handle_eof`](Self::handle_eof) already states for the
  /// other conclusion nothing but a re-offer can produce, and it is what keeps
  /// a refusal deliverable to a driver that has stopped reading.
  ///
  /// A SERVER is told the same thing twice over, since
  /// [`is_awaiting_send`](Self::is_awaiting_send) turns true on a refused body
  /// and its one answer is due. A CLIENT is told it by this call alone: it owes
  /// no response and its own request body has already been stopped, so both
  /// readiness answers go quiet together and the pending conclusion is the only
  /// thing left to collect.
  ///
  /// [`Items::next`]: crate::Items::next
  /// [`Error::Refused`]: crate::Error::Refused
  #[inline]
  pub fn wants_read(&self) -> bool {
    // RFC 9110 §7.8's switch, read BEFORE the message state below and through the
    // one reader of the phase: §15.2.2 makes the 101 the head that "indicates
    // which protocol(s) will be in effect after this response", so the octets
    // behind it are that protocol's. The retained exchange would send the
    // `RecvState::Idle` arm the other way — see the section above.
    if self.live_general_phase().is_err() {
      return false;
    }
    // The transport fact first, because it outranks every reading of the second:
    // no arrangement of the message state makes a byte arrive on a closed read
    // side. This is what keeps a driver from waiting for input that cannot come.
    if self.read_closed {
      return false;
    }
    match self.lifecycle {
      Lifecycle::Failed | Lifecycle::Draining => false,
      Lifecycle::Open | Lifecycle::Closing => match &self.recv {
        RecvState::AwaitingRearm => false,
        // An idle client with a half-arrived line terminator in front of it DOES
        // need the next byte: it is what decides whether the CR was a stray empty
        // line to discard (RFC 9112 §9.2) or the start of something that is not a
        // response at all. Without this the connection would stall on a CR that
        // only a read can resolve.
        RecvState::Idle => !Ro::IS_CLIENT || self.exchange.is_some() || self.pending_cr,
        // Asked of the decoder, not of the state: see the two sections above.
        RecvState::Body { decoder, .. } => decoder.wants_input(),
      },
    }
  }
}

// `Role`-bounded for ONE reason, and it is the same one the body send gate has:
// a refused body leaves a SERVER owing its one answer and leaves a CLIENT with
// nothing to write, so `is_awaiting_send` cannot give one answer for both.
// `body_progress`, `close` and `settle` read `lifecycle`, `recv` and `send`
// alone and would still compile without the bound.
impl<Ro: Role> Connection<Ro, General> {
  /// Where the body being received stands, or `None` between messages.
  ///
  /// On the CONNECTION rather than on [`Items`] because the iterator borrows the
  /// connection for as long as it lives: a driver reads this after dropping the
  /// iterator, which is exactly the point in the contiguous-handover recipe
  /// where it is wanted (see [`BodyProgress::announced`]). Narrowing is the
  /// other way round and is on [`Items`] for the reason stated there.
  ///
  /// `None` is "no body is being received" — between messages, and on a
  /// connection holding a complete message until its own send side catches up.
  /// It is NOT "this message has no body": RFC 9112 §6.3 items 1 and 7 frame a
  /// bodiless message as a body of no octets, which is reported as a body
  /// already through rather than as no body at all.
  ///
  /// `None` on a connection that switched protocols (RFC 9110 §7.8) as well, and
  /// this call needs no phase check to say so: the arm that switches bypasses
  /// `commit_head`, the only writer of `RecvState::Body`, so the receive side is
  /// still `Idle` and "no body is being received" is simply TRUE of it. The
  /// answer is a consequence of the state the switch left behind rather than of
  /// the phase, so a later switch that retained a body would change it — which
  /// is why the assertions in `connection/tests.rs` pin it rather than leaving
  /// it to today's guards.
  ///
  /// Exhaustive over the receive states, so a state added later has to say
  /// whether a body is being received in it.
  #[must_use]
  #[inline]
  pub fn body_progress(&self) -> Option<BodyProgress> {
    let decoder = match &self.recv {
      RecvState::Body { decoder, .. } => decoder,
      RecvState::Idle | RecvState::AwaitingRearm => return None,
    };
    // A receive state holding a decoder was written beside a minted exchange, so
    // the `else` is defensive: progress nothing can be named against is not
    // progress a driver can act on.
    let exchange = self.exchange?.id;
    Some(BodyProgress {
      exchange,
      received: decoder.received(),
      limit: decoder.limit(),
      announced: decoder.announced(),
    })
  }

  /// Whether progress is blocked on the LOCAL send side.
  ///
  /// The write half of the readiness split, and the one a driver must not
  /// confuse with need-more-input: reading the socket will not clear it. Three
  /// causes — a parsed message whose reply is still owed, which keep-alive re-arm
  /// waits on (RFC 9112 §9.3.2); the single error response owed after a
  /// violation; and the same owed reply on a connection whose peer has
  /// closed its write side, where it is the ONLY thing left to do and
  /// `wants_read` has already gone false.
  ///
  /// # A refused body is a fourth cause, on a SERVER
  ///
  /// The inbound side of an exchange is through when the message ended — and
  /// also when this end REFUSED it, because no further octet of it will be
  /// read. RFC 9112 §9.3 has already taken the close branch on the driver's
  /// behalf, so the one response a server still owes is due from the moment the
  /// refusal exists, not from the later pump step that formalises it. Waiting
  /// for that step is the stall: with `wants_read` correctly false, a server
  /// told "nothing to write" has nothing to do at all.
  ///
  /// A CLIENT is deliberately NOT included. It owes no response, and its own
  /// request body has already been stopped for the same refusal (see
  /// `REFUSED_RESPONSE_ENDS_THE_REQUEST`), so reporting an obligation would name
  /// a write every send call refuses. Its readiness goes quiet in both halves
  /// and the pending conclusion on [`wants_read`](Self::wants_read) is what it
  /// collects instead.
  ///
  /// # A switched connection owes nothing
  ///
  /// After RFC 9110 §7.8's switch this end has no write left to make: the
  /// request that offered the upgrade is being satisfied in a protocol this core
  /// does not speak, and every send call refuses. So the answer is `false`, from
  /// the phase, and both halves of the readiness split go quiet together.
  #[inline]
  pub fn is_awaiting_send(&self) -> bool {
    // Through the one reader, so this answer cannot drift from `wants_read`'s.
    // Today the message state would say `false` too — a §7.8 offer carries no
    // content (`OFFER_HAS_NO_CONTENT`), so the request that switched left `send`
    // at `SendState::Idle` and `recv` at `RecvState::Idle` — but that is a
    // property of the OFFER's shape rather than a rule about the phase, and a
    // spent connection owes nothing whatever state it was left holding.
    if self.live_general_phase().is_err() {
      return false;
    }
    match self.lifecycle {
      Lifecycle::Failed => matches!(self.send, SendState::ErrorOwed),
      Lifecycle::Open | Lifecycle::Closing | Lifecycle::Draining => {
        self.inbound_side_is_through()
          && !matches!(self.send, SendState::Idle | SendState::Abandoned)
      }
    }
  }

  /// Whether the inbound side of the exchange in flight will produce nothing
  /// further that this end's answer should wait for.
  ///
  /// Exhaustive over the receive states, so a state added later has to say
  /// which side of that line it falls on.
  fn inbound_side_is_through(&self) -> bool {
    match self.recv {
      RecvState::AwaitingRearm => true,
      // The refusal, on a server. Read through the ONE reader, so this answer
      // and the send gates' cannot come to disagree about when a body counts as
      // refused; it covers both windows, and in this one the flag half is not
      // yet written.
      RecvState::Body { .. } => !Ro::IS_CLIENT && body_refused(&self.recv, &self.exchange),
      // Nothing is in flight to be through with.
      RecvState::Idle => false,
    }
  }

  /// Initiates a graceful local close: no further exchange begins on this
  /// connection.
  ///
  /// RFC 9112 §9.6's local half. The exchange in flight, if any, still finishes —
  /// its response is owed and its remaining inbound bytes are still processed —
  /// and the connection stops at the point where it would otherwise have
  /// re-armed. Between exchanges there is nothing to finish, so it stops at once.
  ///
  /// Idempotent, and a no-op on a connection that has already failed or drained.
  ///
  /// Accepted, and INERT, on one that has switched protocols (RFC 9110 §7.8).
  /// The guard is kept, but it is not what makes the call harmless: after the
  /// switch [`transport`](Self::transport) answers
  /// [`Transport::HandedOver`], which is absorbing and checked ahead of the
  /// lifecycle, so a close recorded here could not change what a driver reads.
  /// The transport belongs to the protocol the 101 named, and this crate's
  /// contract is that the driver HANDS IT OVER rather than tearing it down.
  ///
  /// There is nothing to say in any case: no further exchange was going to begin
  /// on a spent connection. What was queued BEFORE the switch is untouched and
  /// still drainable — see [`poll_event`](Self::poll_event), which is the one
  /// entry point the phase deliberately leaves live.
  #[inline]
  pub fn close(&mut self) {
    // Read through the ONE phase guard, as `wants_read` and `is_awaiting_send`
    // do: this signature cannot return the refusal, so it takes the only other
    // answer its signature permits.
    if self.live_general_phase().is_err() {
      return;
    }
    // NOT DEFERRED, and nothing is queued to defer. `signal_close` moves the
    // lifecycle, and what that means for the transport is read on the ask by
    // `transport()` — where a completed handover outranks it. Deciding it here
    // instead would put the question at every producer of the fact, each of
    // which would have to remember.
    //
    // So the lifecycle moves at once, which is also the more faithful reading of
    // this call: "no further exchange BEGINS" is true from the moment it is
    // asked, whatever the in-flight one turns into.
    signal_close(&mut self.lifecycle);
    self.settle();
  }

  /// Re-arms for the next exchange if both directions of the current one are
  /// through.
  fn settle(&mut self) {
    settle(
      &mut self.recv,
      &mut self.exchange,
      &mut self.watermark,
      &self.send,
      &mut self.lifecycle,
      &mut self.pending_cr,
    );
  }
}

/// What the driver should now do with the transport it holds.
///
/// **A LEVEL, derived on the ask — never stored, never delivered.** Answering
/// this question with a queued `Event` would make the answer an INSTANCE:
/// something minted at one moment, cached in several places, and spoken once.
/// An instance can be delivered stale, stranded, destroyed, duplicated, leaked
/// through `Debug`, or diverged between two modes. A level has no instances, so
/// it has none of those: there is nothing to mint, nothing to destroy, nothing
/// to deliver twice, and no second copy to disagree with the first. Reading it
/// twice is two reads.
///
/// The crate's two other transport questions are answered the same way —
/// [`wants_read`](Connection::wants_read) and
/// [`is_awaiting_send`](Connection::is_awaiting_send) are polled levels about
/// the same subject. This is the third, and it is the one that says what to do
/// when they both say nothing.
///
/// # Polling it
///
/// A driver reads it after draining items and events. Nothing pushes it, so
/// nothing can be missed by not listening; equally, a driver that stops asking
/// learns nothing, which is the Sans-I/O bargain this crate makes everywhere. A
/// driver that wants to act ONCE on a change edge-detects against its own last
/// value — the crate does not keep one, because keeping one is what this type
/// exists to stop doing.
///
/// [`HandedOver`](Self::HandedOver) and [`Failed`](Self::Failed) are ABSORBING:
/// once either is the answer, no later state of this connection changes it.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Transport {
  /// This connection's, and still usable: pump it and send on it, refined by
  /// [`wants_read`](Connection::wants_read) and
  /// [`is_awaiting_send`](Connection::is_awaiting_send).
  Live,
  /// Keep-alive is over — a local [`close`](Connection::close), the peer's RFC
  /// 9112 §9.6 `close` option, or a read-EOF. Finish what is already parsed,
  /// send what is still owed, then close it.
  ///
  /// One answer for all three causes, deliberately: §9.6 makes them one fact
  /// about the connection, and a driver's action is the same for each. Which
  /// cause it was is not this question.
  Ending,
  /// A wire violation latched. Send the owed error response if
  /// [`is_awaiting_send`](Connection::is_awaiting_send) says one is, then close
  /// it. Nothing further will be parsed.
  Failed,
  /// RFC 9110 §7.8's switch or §9.3.6's tunnel completed: the transport belongs
  /// to the negotiated protocol. **Hand it over; never close it.**
  ///
  /// ABSORBING, and that is what makes a missed guard on a parked connection
  /// harmless rather than dangerous: a stray write this crate failed to refuse
  /// cannot change the answer a driver reads here.
  HandedOver,
}

/// RFC 9112 §2.1: a message begins with a complete head, so a close inside one
/// leaves a message the sender never finished stating.
///
/// `pub(crate)` because the pump reports the same fault: a buffered head that
/// turns out to be partial once the read side has ended is the same truncation,
/// found later.
pub(crate) const CLOSED_MID_HEAD: &str = "connection closed before the head ended";

/// RFC 9112 §9.5 with RFC 9110 §15.2: a client's request went out and the
/// connection ended before any FINAL response came back.
///
/// A truncated exchange, not the clean close §9.5 describes — that one happens
/// between messages, with nothing outstanding. An interim (1xx) head does not
/// close the gap either: §15.2 makes it informational and explicitly not the
/// answer, so a client that had seen one and then EOF is in exactly this state.
pub(crate) const CLOSED_BEFORE_RESPONSE: &str = "connection closed before the response arrived";

/// The disjoint `&mut` borrows of the connection fields the inbound pump touches.
///
/// The borrow set documented on [`Items`], handed over at construction: the
/// iterator never holds `&mut Connection`, because a whole-struct borrow would
/// make advancing the receive FSM and, in the same expression, minting an id or
/// bumping the consumed counter conflict. This type is only the vehicle —
/// [`Items`] destructures it into one field per borrow.
pub(crate) struct Borrows<'c> {
  /// Whether the connection is a client. Copied rather than borrowed: it is
  /// [`Role::IS_CLIENT`], which is a constant of the type-state.
  pub(crate) is_client: bool,
  /// The operator's ceiling on one inbound body's payload octets. Copied rather
  /// than borrowed, so the pump can read it and cannot write it.
  pub(crate) max_body: u64,
  /// The budget for one inbound body's RFC 9112 §7.1 chunk-size lines. Copied
  /// for the same reason, and read at the same one site.
  pub(crate) max_chunk_framing: u64,
  /// Bytes of the current offer consumed so far.
  pub(crate) consumed: &'c mut usize,
  /// How far into the head being accumulated the scan has looked.
  pub(crate) watermark: &'c mut usize,
  /// The number the next exchange will take.
  pub(crate) next_exchange: &'c mut u64,
  /// Where the inbound side stands.
  pub(crate) recv: &'c mut RecvState,
  /// The exchange in flight.
  pub(crate) exchange: &'c mut Option<Exchange>,
  /// Where the local side stands.
  pub(crate) send: &'c mut SendState,
  /// Where the connection stands on the one RFC 9110 §7.8 switch a General
  /// connection can take. Borrowed rather than copied — the pump WRITES it and
  /// re-reads it live; the field doc on [`Items`] carries the whole reason.
  pub(crate) tunnel: &'c mut TunnelPhase,
  /// Where the connection stands in its life — policy and failure only.
  pub(crate) lifecycle: &'c mut Lifecycle,
  /// Whether the peer's write side has ended.
  pub(crate) read_closed: &'c mut bool,
  /// Whether the PEER has stated the `close` connection option.
  pub(crate) peer_close: &'c mut bool,
  /// Whether a completed client exchange left an unread tail behind it.
  pub(crate) tail_unresolved: &'c mut bool,
  /// The exchange that ended without its final response.
  pub(crate) aborted: &'c mut Option<ExchangeId>,
  /// Whether a lone `\r` is pending at a client's idle cursor.
  pub(crate) pending_cr: &'c mut bool,
  /// How many stray empty lines an idle client has discarded since its last
  /// request.
  pub(crate) idle_crlfs: &'c mut u8,
}

/// Records the RFC 9112 §9.6 `close` connection option: this end will accept no
/// further exchange.
///
/// POLICY, and nothing else. It moves the lifecycle and touches nothing else —
/// in particular not `read_closed`, which is the TRANSPORT's fact and this
/// function's counterpart's. Neither producer has to dedup against the other,
/// because [`Connection::transport`] reads both facts on the ask.
///
/// The option is what makes the §9.6 rule true: "The server MUST NOT process
/// any further requests received on that connection". That is why it — and not
/// a transport event — leads to [`Lifecycle::Draining`] through [`settle`].
pub(crate) fn signal_close(lifecycle: &mut Lifecycle) {
  if !matches!(*lifecycle, Lifecycle::Open) {
    return;
  }
  *lifecycle = Lifecycle::Closing;
}

/// Records that the PEER's write side has ended: no further byte can arrive.
///
/// The counterpart to [`signal_close`], and deliberately a SEPARATE fact stored
/// in a SEPARATE place. The two answer different questions, and RFC 9112 §9.6
/// keeps them apart in as many words:
///
/// - `signal_close` is the `close` connection OPTION. It is what makes the §9.6
///   rule true: "The server MUST NOT process any further requests received on
///   that connection". So it is a statement about POLICY, and it ends in
///   [`Lifecycle::Draining`].
/// - This is a TRANSPORT event, which §9.6 says carries no such meaning: "a TCP
///   connection that is half-closed by the client does not delimit a request
///   message, nor does it imply that the client is no longer interested in a
///   response". It says only that nothing further will ARRIVE.
///
/// Three properties, and each of them is a defect ruled out rather than a
/// nicety:
///
/// - **Nothing ever clears it.** This is the only writer, and it only ever
///   writes `true`. A transport fact cannot be un-observed, so no lifecycle
///   transition — a `close` option, a re-arm, a drain — can erase it. THAT is
///   what makes the two facts unconflatable, and it is the property the earlier
///   encodings lacked: while this lived in the `Lifecycle` enum, any transition
///   that moved the policy dimension silently dropped the transport one.
/// - **Idempotent.** [`handle_eof`](Connection::handle_eof) is documented to
///   take the same EOF twice; the second report finds the flag already set, so
///   it changes nothing — and there is nothing to re-announce, since what the
///   flag means is derived on the ask rather than delivered when it is set.
/// - **Independent of the exchange.** Nothing about the message in flight is
///   consulted, so WHEN a driver reports the EOF cannot change what it means.
pub(crate) fn latch_read_closed(read_closed: &mut bool) {
  // The transport fact, and nothing else. Keep-alive being over follows from it
  // — `Connection::transport` reads this flag beside the lifecycle — so there is
  // nothing to mint here, and no lifecycle to dedup against.
  *read_closed = true;
}

/// Discharges RFC 9110 §10.1.1's ask, which only a SEND can end.
///
/// ONE routine for both reasons a send ends it — the `100 (Continue)` that
/// ANSWERS the expectation, and the final response that makes it moot — because
/// the effect on the receive side is the same and the two are easiest to keep in
/// step when they are the same call. Left to the call sites, neither was made.
///
/// Called only after the head is in the caller's buffer: a refused encode wrote
/// nothing, so the ask it would have answered is still outstanding.
///
/// A no-op when the pump has already handed the item over, and a no-op when
/// there was no expectation — so a driver may answer in either order, and an
/// unsolicited 100 (RFC 9110 §15.2.1 requires a client to tolerate one) costs
/// nothing.
pub(crate) fn discharge_expect(recv: &mut RecvState) {
  if let RecvState::Body { expect_owed, .. } = recv {
    *expect_owed = false;
  }
}

/// Latches the connection into [`Lifecycle::Failed`], leaving a server the single
/// error response it is still allowed, and returns the error to hand back.
///
/// Three conditions have to hold before that response is owed, and the SEND SIDE
/// is the one it is easiest to forget. RFC 9112 §2.1 makes a response one
/// message: a server that has already sent this exchange's final head has no
/// second answer to give, and one written anyway would be appended to — or, mid
/// body, injected INTO — bytes the peer is already reading as the first response.
/// That is §11.1 response splitting produced by this core rather than by a peer,
/// so a violation found once the head has gone out kills the connection and owes
/// nothing.
///
/// NOTHING is queued here, and nothing is computed about the transport either.
/// The latch is reported by the `Err` this call returns — exactly once, and
/// terminal — and what the transport now is follows from the lifecycle it sets:
/// [`Connection::transport`] reads [`Lifecycle::Failed`] as
/// [`Transport::Failed`].
pub(crate) fn latch(
  send: &mut SendState,
  lifecycle: &mut Lifecycle,
  is_client: bool,
  answerable: bool,
  in_flight: bool,
  error: H1Error,
) -> Error {
  let unanswered = match *send {
    // A request was parsed and its response has not started: the one case an
    // error response can take the place of.
    SendState::Owed => true,
    // Nothing owed and nothing in flight is the malformed-head case — the head
    // failed before it could open an exchange, so the answer belongs to no
    // message this connection ever accepted, which is exactly what a 400 is.
    // With an exchange live, the same state means its response has ALREADY gone
    // out.
    SendState::Idle => !in_flight,
    // A body is part-written or was abandoned mid-way, or a failure was already
    // latched: in none of them is the wire at a message boundary.
    SendState::Sending(_) | SendState::Abandoned | SendState::ErrorOwed => false,
  };
  *lifecycle = Lifecycle::Failed;
  // A client has no response to send, and an EOF has nobody to send one to.
  *send = if answerable && !is_client && unanswered {
    SendState::ErrorOwed
  } else {
    SendState::Idle
  };
  Error::Protocol(error)
}

/// Whether this end's own limit has refused the body of the message in flight.
///
/// THE ONE READER of that fact, and it has to be one, because the fact lives in
/// TWO storage locations covering two contiguous windows:
///
/// - **Window one — [`State::Refused`] inside the decoder**, from the instant
///   `commit_head` writes [`RecvState::Body`] until the step that resolves it.
///   Its writers are enumerated on the VARIANT itself, which is the one
///   authoritative list and is deliberately not repeated here — this reader does
///   not need them, because it keys on the STATE and every writer of that state
///   leaves the identical one.
/// - **Window two — [`Exchange::body_refused`]**, from that step onward,
///   because the receive state that held the decoder is gone by then. One
///   writer: [`refuse`]. Monotone, and it dies with the exchange.
///
/// The windows are contiguous with no gap, and each way INTO window one closes
/// it the same way. A refusal the pump finds: [`refuse`] sets the flag and
/// replaces the receive state in the same step. A refusal a ROUTE causes, by
/// narrowing the ceiling through [`Items::limit_body`]: the narrowing and
/// [`refuse`] run inside that one call, so window one is never observable for it
/// at all. And before window one there is no connection state a driver could act
/// on, since the exchange is minted and the head committed inside a single pump
/// step that has not yielded. The only window-one occupant a driver can OBSERVE
/// is therefore the head's declaration gate — which is exactly the one the pump
/// shape below sits in.
///
/// A send gate reading only ONE of them would be right about one window and
/// wrong about the other — and the window it would miss is the one the
/// recommended pump shape sits in, because a driver that stops at
/// `Item::Head` and drops the iterator has not run the pump step that resolves
/// the refusal. It would then write a `100 (Continue)` inviting content this
/// end has already refused, or spend its one answer on a close-less response
/// and leave the 413 unrepresentable. Reading both is what makes RFC 9112
/// §9.3's close branch hold from the head onwards rather than from the next
/// pull onwards.
///
/// Exhaustive over [`RecvState`], so a receive state added later has to say
/// whether it can hold a refused body rather than defaulting to "no".
///
/// # Every public call whose answer depends on a refused body, and what it does
///
/// The class is "who ANSWERS A QUESTION about this refusal", not "who writes
/// the wire" — a narrower reading of it left the readiness pair out and cost a
/// round, because a driver told the wrong thing about what to do next does not
/// have to write a byte to hang. A call that must NOT consult this says so
/// below with its reason: silence is what let the omissions through.
///
/// | Call | Consults | Why |
/// |---|---|---|
/// | `wants_read` | **yes**, through `BodyDecoder::wants_input` | a refused body cannot be moved by another octet, so advertising read work stalls a driver — fatally against a peer withholding content until it is answered |
/// | `is_awaiting_send` | **yes**, SERVER only | the refusal ends the inbound side, so the one answer RFC 9112 §9.3's close branch owes is due from that moment; a client owes no response and its request body is already stopped |
/// | `handle` / `Items::next` | **produces** it, does not consult | the pump reads the decoder directly through `feed` and is what turns a refusal into `Error::Refused`; consulting a flag it is about to write would be circular |
/// | `Items::limit_body` | **yes**, through `narrow` | a decoder already refused answers `Ok` vacuously — the refusal stands and a narrowing cannot add to it |
/// | `body_progress` | **no** — orthogonal | it reports counts and what the framing declared, all of which stay true of a refused body; `received` is the primitive a driver samples for liveness |
/// | `poll_event`, `handle_eof`, `close` | **no** — connection-scoped | they answer about the CONNECTION's lifecycle, which `refuse` moves through `signal_close` like every other cause rather than through anything read here |
/// | `max_body_bytes`, `max_chunk_framing_bytes` | **no** — constants | written once at construction and never a function of any message |
/// | `send_interim` (General) | **yes** | RFC 9110 §10.1.1 makes a `100` an invitation to send content this end has refused, and a refused exchange owes one final answer and nothing else |
/// | `send_response` | **yes**, inside `check_response_framing` | the answer must state `close` (RFC 9112 §9.3), and this is the call that SPENDS it |
/// | `send_body`, `finish_body` | **yes, on a CLIENT only**, through `body_sendable` | a client's outbound body is the REQUEST, and a refused response leaves it no exchange to complete; a server's outbound body IS the answer and must finish |
/// | `send_error_response` | **no** — vacuous | requires `Lifecycle::Failed` with `SendState::ErrorOwed`, and a refusal never calls [`latch`], so `Failed` is unreachable from it |
/// | `open_request` (client) | **no** — subsumed | refused in BOTH windows by `ONE_REQUEST_AT_A_TIME`, since a refused body means an exchange is outstanding and the receive side is not idle; and by `sendable()` once the refusal has drained the connection |
/// | Tunnel `open_upgrade`, `open_connect`, `send_interim`, `accept`, `reject` | **no** — unreachable | reaching any of them needs `into_tunnel`, refused in window one by `REQUEST_INCOMPLETE` (a server's receive side sits in `Body`, not `AwaitingRearm`) or `EXCHANGE_IN_FLIGHT` (a client's exchange is outstanding), and in window two by `take_over`'s `Lifecycle::Open` gate and its queued-`Event` gate |
///
/// [`State::Refused`]: crate::body::BodyDecoder::is_refused
/// [`Items::limit_body`]: crate::Items::limit_body
pub(crate) const fn body_refused(recv: &RecvState, exchange: &Option<Exchange>) -> bool {
  let in_flight = match recv {
    RecvState::Body { decoder, .. } => decoder.is_refused(),
    RecvState::Idle | RecvState::AwaitingRearm => false,
  };
  let resolved = match exchange {
    Some(exchange) => exchange.body_refused,
    None => false,
  };
  in_flight || resolved
}

/// Everything that follows from "this end refused the body it was being sent".
///
/// ONE routine, deliberately shaped like [`peer_close_effects`], so a
/// consequence added later is added once. Every step reuses an existing
/// single-writer routine rather than re-deriving its rule.
///
/// # Not a failure, and that is the load-bearing choice
///
/// [`Lifecycle`] does not become [`Failed`](Lifecycle::Failed), [`latch`] is not
/// called, and no [`H1Error`] is constructed: nothing on the wire broke a rule.
/// RFC 9110 §15.5.14 names exactly this as a double MAY — "The server MAY
/// terminate the request, if the protocol version in use allows it; otherwise,
/// the server MAY close the connection" — and HTTP/1.1 has no way to terminate
/// one request without the connection, so this core takes the second branch.
/// The connection stays ANSWERABLE, which is the point: a server still owes
/// exactly one response, and a 413 carrying an explanation is still
/// representable.
///
/// # Why the connection cannot be kept
///
/// RFC 9112 §9.3: "A server MUST read the entire request message body or close
/// the connection after sending its response; otherwise, the remaining data on
/// a persistent connection would be misinterpreted as the next request.
/// Likewise, a client MUST read the entire response message body if it intends
/// to reuse the same connection for a subsequent request." Reading the whole
/// body is exactly what the limit refuses, so closing is not the lesser evil —
/// it is the only coherent branch of a MUST with two.
///
/// # The client's own send side
///
/// A client that refuses the RESPONSE it is reading has decided not to read the
/// rest of it, so under §9.3's second sentence this connection cannot be
/// reused; a request body still going out serves no exchange that can complete,
/// and §9.5 lets this end "close the connection at any time". `abandon_send` is
/// therefore right here — but §9.5's other sentence, "If the client sees a
/// response that indicates the server does not wish to receive the message body
/// and is closing the connection, the client SHOULD immediately cease
/// transmitting the body and close its side of the connection", is NOT the
/// authority for it: that one governs a client reacting to a server's refusal
/// of the client's REQUEST body, and no such response exists here. The
/// citation is recorded because `xtask quote-check` proves a quotation
/// verbatim and says nothing about whether it governs.
///
/// # After it
///
/// The driver writes its one response and then closes in STAGES: half-close the
/// write side and keep draining the socket at the transport level until the peer
/// closes or a deadline expires. The peer is mid-transmission of the refused body
/// by construction, so an immediate full close is RFC 9112 §9.6's reset case —
/// "receives additional data from the client on a fully closed connection" — and
/// the reset can erase the very 413 this path exists to deliver. `wants_read()`
/// going false means the CORE needs no more octets, not that the socket should
/// stop being drained. Nothing discarded that way is parsed, so §9.6's "MUST
/// NOT process any further requests" is untouched.
// The disjoint borrows the pump holds, passed as themselves. Bundling them into
// a struct would only re-create `Borrows`, and the two by-VALUE arguments are
// the point rather than an economy: `read_closed` and `is_client` are facts this
// routine reads and must not be able to write — the same argument `signal_close`
// and `latch` are already written to.
#[allow(clippy::too_many_arguments)]
pub(crate) fn refuse(
  recv: &mut RecvState,
  exchange: &mut Option<Exchange>,
  watermark: &mut usize,
  send: &mut SendState,
  lifecycle: &mut Lifecycle,
  pending_cr: &mut bool,
  is_client: bool,
  id: ExchangeId,
  budget: Budget,
) -> Refusal {
  // 1. Read the limit off the decoder still sitting in the receive state,
  //    BEFORE step 5 replaces the state that holds it — so a caller cannot get
  //    the refusal's payload wrong by forgetting to read it first. WHICH limit
  //    is the fault's own discriminant: two budgets refuse through this one
  //    routine and only the comparison that failed knows which it was.
  let limit = match recv {
    RecvState::Body { decoder, .. } => match budget {
      Budget::Payload => decoder.limit(),
      Budget::ChunkFraming => decoder.framing_limit(),
    },
    // Defensive, and unreachable from either caller: both reach here from a
    // decoder that answered, which only `RecvState::Body` holds one of.
    RecvState::Idle | RecvState::AwaitingRearm => 0,
  };
  // 2. Before the settle below, which is what may clear the exchange the flag
  //    lives on.
  if let Some(exchange) = exchange.as_mut() {
    exchange.body_refused = true;
  }
  // 3. RFC 9112 §9.6: keep-alive is over. `signal_close` stays the single
  //    writer of that rule, so the doubled cause — a refusal on a connection
  //    whose peer already closed — is not re-derived here. Nothing is announced:
  //    what a driver should do with the transport follows from the lifecycle
  //    this sets, read by `Connection::transport`.
  signal_close(lifecycle);
  // 4. A client's own request body, released for the reason above.
  if is_client {
    abandon_send(send);
  }
  // 5. The receive side is done with this message: nothing further is decoded,
  //    and the exchange waits on whatever this end still owes.
  *recv = RecvState::AwaitingRearm;
  // 6. RFC 9112 §9.3.2's re-arm gate, asked once: a server that had not yet
  //    answered keeps its exchange and owes its one response; a client, or a
  //    server that had already answered, has nothing left and drains.
  settle(recv, exchange, watermark, send, lifecycle, pending_cr);
  // 7. The limit that refused it, not the observed size: the observed size is
  //    unbounded and unknowable, since the peer may never stop. One arm per
  //    budget, off the same discriminant step 1 read, so the number and the
  //    variant that names it cannot come apart.
  match budget {
    Budget::Payload => Refusal::BodyTooLarge {
      exchange: id,
      limit,
    },
    Budget::ChunkFraming => Refusal::ChunkFramingTooLarge {
      exchange: id,
      limit,
    },
  }
}

/// Abandons a client's outstanding request body, if it has one.
///
// gate-exempt: inbound::commit_head — one of TWO named CALLERS of this
// function (the other is `handle_eof`, linked beside it); `abandon_send`
// itself is called BY both, and calls neither.
/// Not §9.6's "cease sending", which governs requests: what releases this end
/// from finishing a body already in flight is the close-after-reading MUST
/// beside it, and RFC 9112 §9.5 states the same of the body — "the client SHOULD
/// immediately cease transmitting the body and close its side of the
/// connection". ONE rule with two triggers, and they must not drift — the peer's
/// final response ending keep-alive (`inbound::commit_head`) and the transport's
/// read side ending ([`handle_eof`](Connection::handle_eof)) both end the
/// exchange from the receive side while this end may still be mid-body, and both
/// resolve the obligation identically.
///
/// A no-op unless a body is actually in flight, so an idle send side stays
/// [`SendState::Idle`] and keeps its own diagnostics.
pub(crate) fn abandon_send(send: &mut SendState) {
  if matches!(*send, SendState::Sending(_)) {
    *send = SendState::Abandoned;
  }
}

/// Takes the next exchange number.
///
/// Ids are minted HERE and nowhere else, which is what makes them monotone: RFC
/// 9112 §9.3.2 makes their order the only association between a request and its
/// response, and one counter with one taker is what keeps that order true across
/// both of the places an exchange can begin — a request head arriving at a
/// server, and a client opening one of its own.
pub(crate) fn mint(next: &mut u64) -> ExchangeId {
  let id = ExchangeId::new(*next);
  // A connection that opened 2^64 exchanges has other problems; saturating keeps
  // the counter panic-free without wrapping an old id back into circulation.
  *next = next.saturating_add(1);
  id
}

/// Re-arms the connection for the next exchange, if both directions of the
/// current one are through.
///
/// RFC 9112 §9.3.2's rule stated once, for both of the events that can satisfy
/// it: the inbound side finishing a message, and the outbound side finishing its
/// reply. Whichever happens second is what re-arms, and until then the bytes of
/// the next message stay unconsumed in the driver's buffer.
///
/// When keep-alive is over (§9.6) the connection does not re-arm at all: it
/// drains, and no further inbound byte is processed.
pub(crate) fn settle(
  recv: &mut RecvState,
  exchange: &mut Option<Exchange>,
  watermark: &mut usize,
  send: &SendState,
  lifecycle: &mut Lifecycle,
  pending_cr: &mut bool,
) {
  let between_messages = match *recv {
    RecvState::AwaitingRearm => true,
    // A connection that never started an exchange is between messages too,
    // which is what lets a local close take effect immediately.
    RecvState::Idle => exchange.is_none(),
    RecvState::Body { .. } => false,
  };
  // `Abandoned` owes nothing: RFC 9112 §9.6's close-after-reading MUST released
  // this end from writing the rest of its body, so the exchange is through in
  // both directions and the connection may settle. It is kept distinct from
  // `Idle` only so a caller that writes anyway is told why it cannot.
  if !between_messages || !matches!(*send, SendState::Idle | SendState::Abandoned) {
    return;
  }
  // `Closing` and `Closing` alone: a `close` option was stated, so RFC 9112 §9.6
  // forbids processing anything further and the completed exchange is the last.
  //
  // gate-exempt: inbound::no_more_input — names the function that drains the
  // connection once re-arming's buffer turns out exhausted; this block only
  // re-arms the lifecycle, it does not itself drain anything.
  // A closed READ side deliberately does not drain here, and cannot be seen from
  // here either — `settle` is handed the policy state and no transport fact. The
  // requests a peer pipelined before closing are still owed responses in §9.3.2's
  // order, so re-arming is what lets the next of them be read out of the buffer
  // the driver already holds, and `inbound::no_more_input` is what drains the
  // connection once that buffer turns out to be exhausted.
  if matches!(*lifecycle, Lifecycle::Closing) {
    *lifecycle = Lifecycle::Draining;
  }
  *recv = RecvState::Idle;
  *exchange = None;
  // The next head is scanned from its own first byte. Belt and braces: a head
  // that completed cleared this already, since a watermark belongs to ONE head —
  // stating the invariant where the next exchange begins costs less than relying
  // on every path into here having stated it. The same goes for an undecided CR:
  // an exchange boundary is not a place one can still be pending.
  *watermark = 0;
  *pending_cr = false;
}

/// Every field of a [`Connection`], borrowed for comparison.
///
/// What the mode-edge differentials are written against: a transition is
/// correct when the connection it produces is INDISTINGUISHABLE from the one the
/// native path builds, and "indistinguishable" has to mean every field or the
/// claim is only about the fields somebody remembered.
///
/// A named struct rather than a tuple because std's `Debug` and `PartialEq`
/// impls stop at twelve elements, and a borrowing one because [`RecvState`] is
/// not `Copy`.
#[cfg(test)]
#[derive(Debug, PartialEq)]
pub(crate) struct Fingerprint<'a> {
  consumed: &'a usize,
  watermark: &'a usize,
  next_exchange: &'a u64,
  recv: &'a RecvState,
  exchange: &'a Option<Exchange>,
  send: &'a SendState,
  lifecycle: &'a Lifecycle,
  read_closed: &'a bool,
  peer_close: &'a bool,
  aborted: &'a Option<ExchangeId>,
  tail_unresolved: &'a bool,
  tunnel: &'a TunnelPhase,
  pending_cr: &'a bool,
  idle_crlfs: &'a u8,
  max_body: &'a u64,
  opportunistic_upgrade: &'a bool,
  max_chunk_framing: &'a u64,
  /// The derived level, compared BESIDE the fields it is derived from.
  ///
  /// Redundant by construction, and deliberately so: this is the one place two
  /// connections that reached the same state by DIFFERENT routes are compared,
  /// so it is where a derivation that disagreed with its own inputs would show.
  /// By value rather than by reference — the level is `Copy` and is computed,
  /// not stored.
  transport: Transport,
}

#[cfg(test)]
impl<Ro, Mo> Connection<Ro, Mo> {
  /// Every field, bound exhaustively so that adding one is a compile error
  /// rather than a silently uncompared value.
  pub(crate) fn fingerprint(&self) -> Fingerprint<'_> {
    let Self {
      consumed,
      watermark,
      next_exchange,
      recv,
      exchange,
      send,
      lifecycle,
      read_closed,
      peer_close,
      aborted,
      tail_unresolved,
      tunnel,
      pending_cr,
      idle_crlfs,
      max_body,
      opportunistic_upgrade,
      max_chunk_framing,
      // The type-state, which is zero-sized and is the one thing the two sides
      // of a differential are ALLOWED to differ in until the transition runs.
      shape: _,
    } = self;
    Fingerprint {
      transport: self.transport(),
      consumed,
      watermark,
      next_exchange,
      recv,
      exchange,
      send,
      lifecycle,
      read_closed,
      peer_close,
      aborted,
      tail_unresolved,
      tunnel,
      pending_cr,
      idle_crlfs,
      max_body,
      opportunistic_upgrade,
      max_chunk_framing,
    }
  }

  /// Whether [`Limits::opportunistic_upgrade_allowed`] survived
  /// [`with_limits`](Connection::with_limits)'s decomposition.
  ///
  /// Test-only rather than a public accessor: nothing outside this crate reads
  /// the field yet, and code inside `connection` that comes to read it can
  /// reach the private field directly, the way it reaches `max_body`.
  pub(crate) const fn opportunistic_upgrade_allowed_for_test(&self) -> bool {
    self.opportunistic_upgrade
  }
}

#[cfg(test)]
mod tests;
