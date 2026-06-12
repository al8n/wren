//! Monotonic time abstraction for protocol state machines.
//!
//! `websocket-proto` is generic over a custom [`Instant`] trait so it works on
//! `std` (default `Instant = std::time::Instant`), on `no_std` with an
//! ecosystem timekeeping crate (Embassy, fugit, embedded-time), or on bare
//! metal with a user-defined hardware-clock wrapper.
//!
//! The trait surface is intentionally minimal: two checked operations,
//! `Copy + Ord`. No system-clock access, no allocation, no `Display` —
//! the protocol never needs to inspect or format wall-clock times.

use core::time::Duration;

/// Monotonic point-in-time. Protocol state machines schedule and compare
/// deadlines (close timeout, keepalive interval) against this type.
///
/// Implementations must be **monotonic** with respect to the same time
/// source. Mixing instants from different sources is undefined behaviour
/// at the protocol level (deadlines may fire spuriously or never).
///
/// All arithmetic is checked: implementations return `None` on overflow
/// or when subtracting a later instant from an earlier one, rather than
/// panicking. The proto crate is `#![deny(clippy::arithmetic_side_effects)]`
/// and relies on this contract.
pub trait Instant: Copy + Ord + Sized {
  /// Returns `self + dur`, or `None` if the operation would overflow.
  fn checked_add_duration(self, dur: Duration) -> Option<Self>;

  /// Returns `self - earlier`, or `None` if `earlier > self` or the
  /// operation would overflow.
  fn checked_duration_since(self, earlier: Self) -> Option<Duration>;
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl Instant for std::time::Instant {
  #[inline]
  fn checked_add_duration(self, dur: Duration) -> Option<Self> {
    std::time::Instant::checked_add(&self, dur)
  }

  #[inline]
  fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
    std::time::Instant::checked_duration_since(&self, earlier)
  }
}

#[cfg(all(test, feature = "std"))]
pub(crate) mod testing {
  use super::Instant;
  use core::time::Duration;

  /// Deterministic test clock: microseconds since an arbitrary epoch.
  ///
  /// Resolution is 1 µs — sub-microsecond `Duration`s truncate to zero and
  /// do not advance the clock.
  #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
  pub(crate) struct TestInstant(pub(crate) u64);

  impl Instant for TestInstant {
    fn checked_add_duration(self, dur: Duration) -> Option<Self> {
      let micros: u64 = dur.as_micros().try_into().ok()?;
      self.0.checked_add(micros).map(Self)
    }

    fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
      self.0.checked_sub(earlier.0).map(Duration::from_micros)
    }
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::{Instant, testing::TestInstant};
  use core::time::Duration;

  #[test]
  fn test_instant_checked_math() {
    let a = TestInstant(1_000);
    let b = a.checked_add_duration(Duration::from_micros(500)).unwrap();
    assert_eq!(b, TestInstant(1_500));
    assert_eq!(a.checked_add_duration(Duration::ZERO), Some(a));
    assert_eq!(
      b.checked_duration_since(a),
      Some(Duration::from_micros(500))
    );
    // Subtracting a later instant from an earlier one yields None, not a panic.
    assert_eq!(a.checked_duration_since(b), None);
    // Overflow yields None, not a panic.
    assert_eq!(
      TestInstant(u64::MAX).checked_add_duration(Duration::from_micros(1)),
      None
    );
  }

  #[test]
  fn std_instant_implements_instant() {
    let now = std::time::Instant::now();
    let later = Instant::checked_add_duration(now, Duration::from_millis(5)).unwrap();
    assert!(later > now);
    assert_eq!(
      Instant::checked_duration_since(later, now),
      Some(Duration::from_millis(5))
    );
    assert_eq!(Instant::checked_duration_since(now, later), None);
  }
}
