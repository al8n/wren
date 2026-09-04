//! Where a CALLER-CONTRACT violation goes, and the one place the crate decides
//! what to do about it.
//!
//! # Two classes of error, and only one of them may ever panic
//!
//! A **contract** error is the caller breaking this crate's API: a `now` that
//! went backwards, feeding a terminal connection, a send-sequencing mistake. It
//! is a bug in the program, it is reproducible, and there is a well-known
//! argument — TigerBeetle's — that a program which has already violated its own
//! invariants should stop rather than continue on state nobody reasoned about.
//!
//! A **protocol** error is anything a peer's bytes can cause: a malformed
//! header, an unmasked client frame, invalid UTF-8, an oversize payload. Those
//! are not bugs; they are the job. **They never panic under any feature**,
//! because a peer-triggerable panic is a denial-of-service entrance — one
//! crafted frame and the process is gone. If it is not obvious which class an
//! error belongs to, it is a protocol error.
//!
//! That split is the whole design here, and it is enforced by WHICH ERRORS
//! REACH [`contract_violation`] rather than by a comment that says so. A
//! protocol error that starts routing through this function acquires a panic,
//! and the diff that does it is the review.
//!
//! # The feature
//!
//! Off (the default), [`contract_violation`] hands the error straight back and
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
/// Under `assert-contracts`, always. Without it, never — and the crate-wide
/// `deny(clippy::panic)` wall is left standing rather than relaxed, so the
/// `allow` below is the ONLY place in this crate a panic can be written even
/// with the feature on.
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
