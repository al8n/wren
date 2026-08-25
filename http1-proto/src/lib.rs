#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![cfg_attr(
  not(test),
  deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::arithmetic_side_effects,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::string_slice
  )
)]

// Aliased so heap-gated modules can name heap items via `std::` on the `std`,
// `no_std + alloc`, and `no-atomic` (a no-`std` heap) tiers. The consumer is
// outbound body storage; every current path encodes into a caller-supplied
// slice, so no tier has a consumer yet and the unused-crate lint is suppressed
// here rather than letting the gate drift between tiers.
#[allow(unused_extern_crates)]
#[cfg(all(not(feature = "std"), any(feature = "alloc", feature = "no-atomic")))]
extern crate alloc as std;

#[cfg(feature = "std")]
extern crate std;

// Must precede any module that uses `cfg_heap!`.
#[macro_use]
mod macros;

/// The inbound body: the RFC 9112 §6.3 framing decision turned into an
/// incremental, zero-copy stream of body items.
pub mod body;
/// The connection state machine: the compile-time role/mode type-state, the
/// General-mode inbound FSM that turns fed transport bytes into borrowed items
/// — the RFC 9110 §7.8 switch a permitted client's own offer brings back
/// included — and its send side, and the Tunnel-mode handshake that builds such
/// a switch from scratch. Either mode hands the byte stream over.
pub mod connection;
/// Grammar-violation detail, advisory response status, and the error split.
pub mod error;
/// The driver vocabulary: the identity that correlates a keep-alive
/// connection's messages, the borrowed inbound items a connection hands out,
/// and the owned notices it queues.
pub mod event;
/// RFC 9110 field grammar, re-exported from [`http_semantics`].
///
/// The items live in `http-semantics` because their rules are RFC 9110's and
/// every HTTP version inherits them; this crate re-exports them because its own
/// documentation and README reference `grammar::` throughout and its public
/// story is a complete HTTP/1.1 core. **`http-semantics` is where the
/// documentation and the RFC citations for these items live** — a change to
/// what any of them means is made there, and this path follows it.
pub use http_semantics::grammar;
/// The message head: the RFC 9112 §3 request-line, the §4 status-line, the
/// bounded scanner over the field lines that follow, and the lazy view of a
/// scanned head.
pub mod head;
/// RFC 9110 media types and `Accept` ranges, re-exported from
/// [`http_semantics`]. See [`grammar`] for why this is a re-export and where
/// the documentation for these items lives.
pub use http_semantics::media;
/// Role-aware semantics over a scanned head: the RFC 9112 §3.2 `Host` and
/// target rules, the §6.3 body-framing decision, and the connection directives
/// a head carries.
pub mod validate;
pub use connection::{
  BodyPlan, BodyProgress, Client, ClientTunnelOutcome, Connection, General, HeadBinding, Limits,
  Mode, NO_TRAILERS, Role, Server, ServerTunnelRequest, TransitionRefused, Transport, Tunnel,
};
pub use error::{Error, H1Error, MalformedDetail, Refusal, SuggestedStatus};
pub use event::{Event, ExchangeId, Item, Items, StartLine};
// `RequestLine`, `StatusLine` and `Version` join the root list with the tunnel
// outcomes that carry them: `ServerTunnelRequest` hands a consumer the parsed
// request-line and `ClientTunnelOutcome::Refused` the parsed status-line, so the
// types those variants are made of have to be nameable where the variants are.
// The start-line CODECS stay crate-private, since a consumer is handed what
// they produced rather than the job of running them.
pub use head::{
  FieldsIter, HeadView, Headers, MAX_HEAD_BYTES, MAX_HEADERS, RequestLine, StatusLine, Target,
  Version,
};
pub use media::{
  MAX_TRACKED_PARAMS, MediaError, MediaRange, MediaType, Weight, accept, media_type, weight_for,
  weight_for_with,
};
// `validate::BodyFraming` is deliberately NOT re-exported here. It is the
// receive side's own RFC 9112 §6.3 decision, and no public signature hands one
// out or takes one: a driver states its outbound framing with `BodyPlan` and
// reads the inbound message off the items the connection yields. It stays
// nameable at `validate::BodyFraming` for a reader following the module docs,
// and promoting it to the root is a non-breaking change on the day a public
// signature needs it.

/// Leaf-path forwarders for the `no-panic` link-time test. Gated behind
/// `test-no-panic`, doc-hidden, and exempt from semver.
// The module name carries the leading-underscore marker `http3-proto` uses for
// this same module; the FILE is named without it, so the path is spelled out.
#[cfg(feature = "test-no-panic")]
#[doc(hidden)]
#[path = "no_panic_internals.rs"]
pub mod __no_panic_internals;
