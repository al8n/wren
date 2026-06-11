//! Extra (caller-supplied) handshake headers, shared by both roles.

use crate::handshake::parser::is_token;

/// A borrowed list of additional handshake headers (`(name, value)` pairs):
/// request headers for the client (auth, origin, cookies) and response headers
/// for the server's accept/rejection.
///
/// Header names must be RFC 9110 tokens and values must not contain CR or LF;
/// these checks run at encode time (the client additionally rejects names that
/// collide with the headers it manages itself). The list borrows the caller's
/// storage — keep it alive for the handshake's lifetime.
#[derive(Debug, Copy, Clone, Default)]
pub struct ExtraHeaders<'a> {
  entries: &'a [(&'a str, &'a str)],
}

impl<'a> ExtraHeaders<'a> {
  /// Wraps a borrowed slice of `(name, value)` pairs.
  pub const fn new(entries: &'a [(&'a str, &'a str)]) -> Self {
    Self { entries }
  }

  /// Iterates the `(name, value)` pairs in order.
  pub fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> + '_ {
    self.entries.iter().copied()
  }

  /// Number of header entries.
  pub const fn len(&self) -> usize {
    self.entries.len()
  }

  /// Whether there are no header entries.
  pub const fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }

  /// Validates the checks both roles share: each name is a token and no value
  /// contains CR or LF. Returns the offending reason on the first failure.
  ///
  /// This mirrors the inbound parser's CR/LF rejection but deliberately does
  /// **not** reject the other C0 control bytes the parser screens on receive —
  /// outbound extra-header values have only ever been CR/LF-checked, and this
  /// keeps that contract. The client's managed-name collision check is applied
  /// separately, on the client side only.
  pub(crate) fn validate(&self) -> Result<(), &'static str> {
    for (name, value) in self.entries {
      if !is_token(name) {
        return Err("extra header name is not a token");
      }
      if value.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err("extra header value contains CR/LF");
      }
    }
    Ok(())
  }
}
