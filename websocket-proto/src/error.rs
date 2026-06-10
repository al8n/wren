//! Cross-cutting error building blocks shared by multiple modules.
//!
//! Per-module error enums live with their modules; this module holds only the
//! extracted detail payloads that more than one error enum wraps.

use derive_more::Display;

/// Detail payload: an output buffer was too small for the bytes a call
/// needed to write.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[display("output buffer too small: needed {needed} bytes, had {have}")]
pub struct BufferTooSmallDetail {
  needed: usize,
  have: usize,
}

impl BufferTooSmallDetail {
  /// Creates a new detail from the required and available byte counts.
  #[inline(always)]
  pub const fn new(needed: usize, have: usize) -> Self {
    Self { needed, have }
  }

  /// Bytes the call needed to write.
  #[inline(always)]
  pub const fn needed(&self) -> usize {
    self.needed
  }

  /// Bytes the destination had available.
  #[inline(always)]
  pub const fn have(&self) -> usize {
    self.have
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  #[test]
  fn buffer_too_small_detail_accessors_and_display() {
    let d = BufferTooSmallDetail::new(14, 3);
    assert_eq!(d.needed(), 14);
    assert_eq!(d.have(), 3);
    assert_eq!(
      d.to_string(),
      "output buffer too small: needed 14 bytes, had 3"
    );
  }
}
