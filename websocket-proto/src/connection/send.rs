//! The send path: zero-copy frame encoding into caller-supplied buffers.

/// Placeholder send state (Task 4 replaces this).
#[derive(Debug)]
#[allow(dead_code)] // placeholder until Task 4 wires the real encoders
pub(crate) struct SendState;

impl SendState {
  pub(crate) const fn new() -> Self {
    Self
  }
}
