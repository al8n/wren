//! Connection roles, fixed at the type level. The client masks outbound
//! frames with a fresh unpredictable key per frame (RFC 6455 §5.3, §10.3)
//! and requires unmasked inbound; the server is the mirror image. Reserved
//! for this crate: the trait is sealed.

use rand_core::Rng as RngCore;

mod sealed {
  pub trait Sealed {}
}

/// A connection role: [`Client`] or [`Server`]. Sealed — drivers stay
/// role-generic by bounding on this trait.
pub trait Role: sealed::Sealed {
  /// Whether inbound frames MUST be masked (server) or MUST NOT (client).
  const EXPECT_MASKED_INBOUND: bool;

  /// The masking key for the next outbound frame (`None` for servers).
  fn next_mask(&mut self) -> Option<[u8; 4]>;
}

/// The client role: owns the masking-key RNG. RFC 6455 §10.3 requires keys
/// be unpredictable — supply a CSPRNG-quality source for public-internet
/// connections.
#[derive(Debug)]
pub struct Client<R> {
  rng: R,
}

impl<R> Client<R> {
  /// A client role drawing mask keys from `rng`.
  pub const fn new(rng: R) -> Self {
    Self { rng }
  }
}

impl<R> sealed::Sealed for Client<R> {}

impl<R: RngCore> Role for Client<R> {
  const EXPECT_MASKED_INBOUND: bool = false;

  fn next_mask(&mut self) -> Option<[u8; 4]> {
    let mut key = [0u8; 4];
    self.rng.fill_bytes(&mut key);
    Some(key)
  }
}

/// The server role: no RNG, no mask state.
#[derive(Debug, Copy, Clone, Default)]
pub struct Server;

impl Server {
  /// The server role.
  pub const fn new() -> Self {
    Self
  }
}

impl sealed::Sealed for Server {}

impl Role for Server {
  const EXPECT_MASKED_INBOUND: bool = true;

  fn next_mask(&mut self) -> Option<[u8; 4]> {
    None
  }
}
