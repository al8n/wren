//! Borrowed header access for decoded field sections, and the outbound-header
//! supplier trait. Keeps the core WebSocket-agnostic: the driver decides which
//! headers go out (e.g. from websocket-proto's `connect` module) and inspects
//! the ones that come in.

/// An outbound header set the core QPACK-encodes. The driver implements this
/// (typically forwarding a `websocket_proto::handshake::connect` header iterator).
pub trait Headers {
  /// Visits each `(name, value)` pair in order. Returning `Err` aborts encoding.
  fn for_each(&self, f: &mut dyn FnMut(&str, &str)) -> Result<(), crate::Error>;
}

/// Blanket impl for slices of `(name, value)` pairs (convenience + tests).
impl<'a> Headers for [(&'a str, &'a str)] {
  fn for_each(&self, f: &mut dyn FnMut(&str, &str)) -> Result<(), crate::Error> {
    for &(n, v) in self {
      f(n, v);
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests;
