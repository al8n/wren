//! The receive state machine: incremental header assembly, policy, in-place
//! unmasking, chunked delivery.

/// Caller-contract errors from `Connection::handle`. Protocol violations
/// are NOT errors — they surface as a final `Event::Closed`.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
#[allow(dead_code)] // activated when Task 2 wires Connection::handle
pub enum HandleError {
  /// The connection is terminal; feeding more input is a caller bug.
  #[error("connection is terminal")]
  Terminal,
}

/// Placeholder receive state (Tasks 2–3 replace this).
#[derive(Debug)]
#[allow(dead_code)] // placeholder until Task 2 wires the real machine
pub(crate) struct RecvState;

impl RecvState {
  pub(crate) const fn new() -> Self {
    Self
  }
}
