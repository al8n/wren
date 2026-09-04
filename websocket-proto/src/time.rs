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
/// The `now` a caller hands across calls on ONE
/// [`Connection`](crate::Connection) must be non-decreasing, and the crate
/// checks it rather than trusting it. FOUR entry points take a `now` —
/// `handle`, `observe`, `poll_transmit` and `handle_timeout` — over three
/// refusal sites, because `handle` and `observe` share one implementation and
/// so one check. Each compares `now` against the latest instant that
/// connection has been given and refuses a strictly earlier one with a
/// `ClockWentBackwards` error, leaving the connection untouched. An EQUAL
/// instant is accepted, so a driver that reads its clock once per wakeup may
/// hand the same one to every call in a batch.
///
/// The refusal is **returned** — a rewound clock is a bug in the caller's
/// timekeeping, and whether it should kill the process, drop the connection or
/// be logged and retried is the driver's decision. What the crate owes is that
/// the fact is reachable; before the check, a rewound `now` was silently
/// tolerated and deadlines simply fired late.
///
/// **Unless the `assert-contracts` feature is on**, in which case this exact
/// condition panics instead of returning, by design: the refusal routes through
/// `contract::contract_violation`, which is that feature's whole purpose. A
/// binary that enables it has asked for the abort. Nothing a PEER's bytes can
/// cause panics under any feature.
///
/// [`Connection::poll_timeout`](crate::Connection::poll_timeout) takes no `now`
/// and never refuses — but see its own docs before feeding its answer back in:
/// the deadline it returns can be OLDER than the last instant this connection
/// was given, and handing that value to `handle_timeout` is a rewind.
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
