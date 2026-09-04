//! Where a CALLER-CONTRACT violation goes, and the one place the crate decides
//! what to do about it.
//!
//! # One class may panic, and it is the NARROW one
//!
//! Not "caller misuse" — that class is far too wide, and naming it that way is
//! how a peer-triggerable panic gets in. The panic-eligible class is the
//! **non-peer-triggerable** one: a refusal whose triggering VALUE cannot have
//! come off the wire, and whose triggering STATE cannot be induced by a peer's
//! timing. A `now` that went backwards is the example, and so far the only one
//! routed here. Such an error is a bug in the program, it is reproducible, and
//! there is a well-known argument — TigerBeetle's — that a program which has
//! already violated its own invariants should stop rather than continue on
//! state nobody reasoned about.
//!
//! Everything else **never panics under any feature**, because a
//! peer-triggerable panic is a denial-of-service entrance — one crafted frame
//! and the process is gone. That covers the obvious protocol errors (a
//! malformed header, an unmasked client frame, invalid UTF-8, an oversize
//! payload) and, less obviously, refusals that LOOK like caller misuse:
//! **feeding a terminal connection is not panic-eligible**, because the peer's
//! Close is what makes a connection terminal and it can land between a caller's
//! check and its call.
//!
//! # The criterion is the VALUE, not the caller
//!
//! "The caller broke the API" is the wrong test, and it is wrong in a direction
//! that manufactures exactly the entrance above. The right one is: **could the
//! value that triggers this refusal have come off the wire?** A caller is
//! entitled to forward peer-derived data back into this API — echo a received
//! close code, answer a ping with the payload it carried, relay a subprotocol
//! string — so a refusal keyed on such a value is peer-triggerable no matter
//! who typed the call.
//!
//! The set walked below is **every variant of
//! [`HandleError`](crate::connection::HandleError) and
//! [`EncodeError`](crate::connection::EncodeError)**, `deflate`-gated ones
//! included — not "the crate's whole
//! error set", which would also sweep in the handshake and frame errors this
//! taxonomy has never ruled on. Of that set, the three clock refusals
//! (`ClockWentBackwards` on `HandleError`, `EncodeError` and `TimeoutError` —
//! three error TYPES over four entry points, since `handle` and `observe`
//! share one refusal site) are already routed through this wall; among the
//! REST, **exactly one is a candidate**.
//!
//! | variant | panic-eligible? | why |
//! |---|---|---|
//! | `EncodeError::FragmentSequence` | **yes** | nothing on the wire chooses this endpoint's outbound fragmentation order |
//! | `HandleError::Terminal` | no | the peer's Close makes a connection terminal; peer timing induces it |
//! | `EncodeError::Closing` | no | the same state, one method over |
//! | `EncodeError::ControlTooLong` | no | refuses a VALUE a caller may be relaying from the peer |
//! | `EncodeError::ReasonTooLong` | no | same |
//! | `EncodeError::InvalidCloseCode` | no | a caller echoing a close code it received |
//! | `EncodeError::InvalidUtf8` | no | a caller forwarding peer bytes into a text frame |
//! | `EncodeError::BufferTooSmall` | no | a sizing decision, not a bug |
//! | `EncodeError::CompressionUnavailable` (`deflate`) | no | whether permessage-deflate was negotiated is settled by BOTH peers at the handshake, so the refusal is keyed on peer-decided state |
//! | the three `ClockWentBackwards` | **yes** | routed through this wall already |
//!
//! That split is enforced by WHICH ERRORS REACH
//! [`contract_violation`](crate::contract::contract_violation) rather
//! than by a comment that says so. A protocol error that starts routing through
//! this function acquires a panic, and the diff that does it is the review.
//!
//! # The feature
//!
//! Off (the default),
//! [`contract_violation`](crate::contract::contract_violation) hands the error
//! straight back and
//! the crate's panic-freedom is exactly what `tests/no_panic.rs` proves it to
//! be. On (`assert-contracts`), it panics naming the contract that was broken.
//!
//! The feature is for a **final binary**, not for a library: cargo features are
//! unified across the whole build graph, so a library enabling it decides the
//! question for every dependent, including ones that chose a returned `Err` on
//! purpose. Enable it in the binary crate that owns the process, and typically
//! in tests and staging rather than in a shipped server — though shipping it on
//! is a defensible choice, and is the one TigerBeetle makes.

/// Answers a caller-contract violation: hands `err` back, or — under
/// `assert-contracts` — panics naming the broken `contract`.
///
/// Call it at the refusal, so the `Err` stays visible in the source:
///
/// ```text
/// return Err(contract_violation(
///   HandleError::ClockWentBackwards,
///   CLOCK_IS_MONOTONIC,
/// ));
/// ```
///
/// # Only contract errors
///
/// See the module docs. Nothing a peer's bytes can reach may be routed here.
///
/// # Panics
///
/// Under `assert-contracts`, always. Without it, never.
///
/// # What the lint wall does and does not enforce
///
/// "The `allow` below is the only place in this crate a panic can be written"
/// is too strong a claim, and the shape of what actually holds matters more
/// than the slogan:
///
/// * **Direct panic macros are denied** crate-wide outside `cfg(test)` —
///   `clippy::panic`, `unwrap_used`, `expect_used`, `unreachable`, `todo`,
///   `unimplemented`, plus `indexing_slicing`, `arithmetic_side_effects`,
///   `integer_division` and `string_slice` for the implicit ones. The
///   `cfg_attr`'d `allow` below relaxes exactly one of those, for this
///   function, only when the feature is on.
/// * **`clippy::panic_in_result_fn` sees assertions only in functions that
///   return `Result`, and does not inspect their callees.** An `assert!` in a
///   non-`Result` helper is denied by NOTHING here: verified against this
///   toolchain's `-W help` list, no clippy lint on 1.91 denies a bare `assert!`
///   outside a `Result` function, and `assertions_on_constants` — which the
///   wall now names — catches only `assert!(true)` / `assert!(false)`.
/// * **Callees are covered by the LINK-TIME proof, and only for the shimmed
///   entry points**: `FrameHeader::{decode, encode}`, `mask`,
///   `Utf8Validator::feed`, the internal base64 encoder, and
///   `Connection::{prepare_binary, prepare_text, handle_timeout}`. Everything
///   else — `Connection::handle` and its whole receive tree included — is held
///   by the lint wall alone, which `tests/no_panic.rs` states in as many words.
///
/// So an `assert!` added to a receive helper would be peer-triggerable and pass
/// every gate this crate runs today. The gap is named here rather than papered
/// over; closing it means widening the link proof, not adding a lint.
///
/// # The gap, as a number
///
/// COUNTED, so the next batch has a target rather than an intention: of the
/// **47** public functions in this crate that take a `&[u8]` / `&mut [u8]` /
/// `&str` — the shape peer-supplied bytes arrive in — **7** are covered by a
/// `#[no_panic]` shim and **40** are not. (The first count of this was 36/5/31,
/// from a regex that required an indented `pub fn` and so could not see a
/// free function; `mask` and the UTF-8 validator's `feed` were among the ones
/// it missed. The second was 46/7/39, and `Connection::observe` is the
/// forty-seventh: it shares `handle`'s tree, so it joins the uncovered side.)
/// The uncovered set is headed by `Connection::handle`, whose call tree is the
/// entire inbound state machine, and includes `frame::decode_close_payload`,
/// the whole `handshake::h1` surface (`classify`, `handle`, `encode_response`,
/// `encode_rejection`) and `negotiation`'s three parsers.
///
/// The COMMAND, so the number is re-derivable rather than merely asserted. It
/// counts declarations with UNRESTRICTED `pub` — a `pub(crate)` helper is not
/// part of the surface peer bytes arrive through — whose parameter list names
/// one of the three shapes:
///
/// ```text
/// rg -U --pcre2 --no-filename -o \
///    "pub (?:const |unsafe |async )*fn \w+[^(]*\([^)]*&(?:'\w+ )?(?:mut )?(?:\[u8\]|str)" \
///    websocket-proto/src | grep -c '^pub '
/// ```
///
/// Drop the `grep` to see the names rather than the count; each match begins
/// at its `pub`, and a multi-line signature prints as several lines, which is
/// what the `grep` is counting past. The one thing it approximates is that the
/// byte shape must appear before the parameter list's first `)` rather than
/// anywhere inside a balanced one — true of every signature in this crate
/// today, and cross-checked against a balanced-paren scan that returns the
/// same 47 names.
///
/// Seven of those names are the shimmed ones: `FrameHeader::encode`,
/// `FrameHeader::decode`, `mask`, and the `test-no-panic` surface
/// `base64_encode`, `Utf8Validator::feed`, `Connection::prepare_binary` and
/// `Connection::prepare_text`. `tests/no_panic.rs` shims an eighth entry
/// point, `Connection::handle_timeout`, which takes no bytes and so is not in
/// this population at all — which is why eight shims cover seven of them.
///
/// Widening the proof is deliberately NOT this branch's work: `tests/no_panic.rs`
/// records that the connection tree does not inline into one shim without
/// pervasively annotating the library, and finding the shape that does is a
/// design question, not an edit.
#[cfg_attr(feature = "assert-contracts", allow(clippy::panic))]
#[cfg_attr(docsrs, doc(cfg(feature = "assert-contracts")))]
pub(crate) fn contract_violation<E>(err: E, contract: &'static str) -> E {
  #[cfg(feature = "assert-contracts")]
  {
    let _ = err;
    panic!("websocket-proto: caller contract violated — {contract}");
  }
  #[cfg(not(feature = "assert-contracts"))]
  {
    let _ = contract;
    err
  }
}

/// The contract [`Connection::accept_now`](crate::Connection) enforces, named
/// for the panic message.
pub(crate) const CLOCK_IS_MONOTONIC: &str = "`now` must not go backwards across calls on one `Connection` (an equal \
   instant is fine); this call was given one earlier than the connection has \
   already seen";
