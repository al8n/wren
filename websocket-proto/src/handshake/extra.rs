//! Extra (caller-supplied) handshake headers, shared by both roles.

use crate::handshake::parser::is_token;

/// A borrowed list of additional handshake headers (`(name, value)` pairs):
/// request headers for the client (auth, origin, cookies) and response headers
/// for the server's accept/rejection.
///
/// Header names must be RFC 9110 tokens and values must not contain CR or LF;
/// these checks run at encode time (the client additionally rejects names that
/// collide with the headers it manages itself).
///
/// Construct via the `From` conversions — the option builders take
/// `impl Into<ExtraHeaders>`, so call sites pass a slice (or array) directly,
/// or borrow an [`ExtraHeadersBuilder`] for incremental construction:
///
/// ```
/// use websocket_proto::handshake::{ExtraHeadersBuilder, h1::ClientOptions};
///
/// // Static list: pass the pairs directly.
/// let options = ClientOptions::new("example.com", "/chat")
///   .with_extra_headers(&[("Origin", "https://example.com")]);
/// # let _ = options;
///
/// // Incremental: build up, then borrow.
/// let headers = ExtraHeadersBuilder::new()
///   .with_header("Origin", "https://example.com")
///   .with_header("Authorization", "Bearer t0ken");
/// let options = ClientOptions::new("example.com", "/chat").with_extra_headers(&headers);
/// # let _ = options;
/// ```
///
/// The two lifetimes keep the borrows precise: `'s` is the slice storage, `'a`
/// the header strings — a temporary pair list of long-lived strings does not
/// pin the strings down to the list's lifetime.
#[derive(Debug, Copy, Clone)]
pub struct ExtraHeaders<'s, 'a> {
  entries: &'s [(&'a str, &'a str)],
  /// The source builder overflowed its capacity — surfaced as a loud
  /// encode-time validation error instead of silently dropping headers.
  overflowed: bool,
}

impl ExtraHeaders<'_, '_> {
  /// An empty header list.
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      entries: &[],
      overflowed: false,
    }
  }
}

impl Default for ExtraHeaders<'_, '_> {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

impl<'s, 'a> From<&'s [(&'a str, &'a str)]> for ExtraHeaders<'s, 'a> {
  #[inline(always)]
  fn from(entries: &'s [(&'a str, &'a str)]) -> Self {
    Self {
      entries,
      overflowed: false,
    }
  }
}

impl<'s, 'a, const N: usize> From<&'s [(&'a str, &'a str); N]> for ExtraHeaders<'s, 'a> {
  #[inline(always)]
  fn from(entries: &'s [(&'a str, &'a str); N]) -> Self {
    Self {
      entries,
      overflowed: false,
    }
  }
}

impl<'s, 'a, const N: usize> From<&'s ExtraHeadersBuilder<'a, N>> for ExtraHeaders<'s, 'a> {
  #[inline(always)]
  fn from(builder: &'s ExtraHeadersBuilder<'a, N>) -> Self {
    Self {
      entries: builder.entries(),
      overflowed: builder.overflowed(),
    }
  }
}

impl<'s, 'a> ExtraHeaders<'s, 'a> {
  /// Internal `const` construction path (the public surface is the `From`
  /// conversions; `const fn` cannot carry `impl Into` parameters).
  #[inline(always)]
  pub(crate) const fn from_entries(entries: &'s [(&'a str, &'a str)]) -> Self {
    Self {
      entries,
      overflowed: false,
    }
  }

  /// Iterates the `(name, value)` pairs in order. The items borrow the
  /// header strings (`'a`), not this view, so they may outlive it.
  pub fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> + 's {
    self.entries.iter().copied()
  }

  /// Number of header entries.
  #[inline(always)]
  pub const fn len(&self) -> usize {
    self.entries.len()
  }

  /// Whether there are no header entries.
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }

  /// Validates the checks both roles share: each name is a token and each
  /// value fits the RFC 9110 §5.5 field-value grammar (HTAB / SP / VCHAR /
  /// obs-text — no C0 control except HTAB, no DEL). Returns the offending
  /// reason on the first failure.
  ///
  /// This mirrors the inbound parser's screening exactly: a value the crate
  /// refuses to PARSE must not be one it will EMIT, or a conforming peer or
  /// intermediary may reject — or worse, reinterpret — the handshake.
  pub(crate) fn validate(&self) -> Result<(), &'static str> {
    if self.overflowed {
      return Err("extra headers exceeded the builder capacity");
    }
    for (name, value) in self.entries {
      if !is_token(name) {
        return Err("extra header name is not a token");
      }
      if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7F) {
        return Err("extra header value contains control bytes");
      }
    }
    Ok(())
  }

  /// Rejects entries whose names collide with the handshake-managed headers
  /// (minus `exempt`, ASCII case-insensitive). A colliding extra would put
  /// bytes on the wire that contradict the machine's own negotiation state —
  /// e.g. an extra `Sec-WebSocket-Extensions` granting deflate the returned
  /// [`Negotiated`](crate::negotiation::Negotiated) knows nothing about.
  pub(crate) fn validate_no_managed_collision(&self, exempt: &[&str]) -> Result<(), &'static str> {
    for (name, _) in self.entries {
      let managed = MANAGED.iter().any(|m| name.eq_ignore_ascii_case(m));
      let exempted = exempt.iter().any(|e| name.eq_ignore_ascii_case(e));
      if managed && !exempted {
        return Err("extra header collides with a managed header");
      }
    }
    Ok(())
  }
}

/// Headers the handshake machines manage themselves; caller extras must not
/// collide (the wire would contradict the negotiation state). Shared by both
/// roles.
pub(crate) const MANAGED: &[&str] = &[
  "host",
  "upgrade",
  "connection",
  "sec-websocket-key",
  "sec-websocket-version",
  "sec-websocket-protocol",
  "sec-websocket-extensions",
  "sec-websocket-accept",
];

/// An incremental, allocation-free builder for [`ExtraHeaders`]: a bounded
/// inline list of `(name, value)` pairs.
///
/// `N` is the inline capacity (default 16). [`with_header`] chains
/// infallibly; adding past the capacity sets an overflow flag instead of
/// silently dropping, and the handshake then fails loudly at encode time
/// ("extra headers exceeded the builder capacity") through the same
/// validation that checks names and values.
///
/// Keep the builder alive and borrow it where an
/// `impl Into<ExtraHeaders>` is expected:
///
/// ```
/// use websocket_proto::handshake::ExtraHeadersBuilder;
///
/// let headers = ExtraHeadersBuilder::new()
///   .with_header("Origin", "https://example.com")
///   .with_header("X-Trace-Id", "abc123");
/// assert_eq!(headers.len(), 2);
/// ```
///
/// Borrowing the builder is the ONLY conversion path — there is no public
/// slice accessor, so the overflow flag cannot be laundered away by passing
/// raw pairs:
///
/// ```compile_fail
/// use websocket_proto::handshake::ExtraHeadersBuilder;
///
/// let b = ExtraHeadersBuilder::new().with_header("A", "1");
/// let _ = b.entries(); // crate-private — borrow `&b` instead
/// ```
///
/// [`with_header`]: ExtraHeadersBuilder::with_header
#[derive(Debug, Copy, Clone)]
pub struct ExtraHeadersBuilder<'a, const N: usize = 16> {
  entries: [(&'a str, &'a str); N],
  len: usize,
  overflowed: bool,
}

impl ExtraHeadersBuilder<'_> {
  /// An empty builder with the default 16 inline slots. (Constructors on the
  /// defaulted type keep `ExtraHeadersBuilder::new()` inference-friendly —
  /// const-generic defaults do not flow through bare `Self` inference; pick a
  /// custom capacity with [`with_capacity`](Self::with_capacity).)
  #[inline(always)]
  pub const fn new() -> Self {
    Self::with_capacity()
  }
}

impl<'a, const N: usize> ExtraHeadersBuilder<'a, N> {
  /// An empty builder with `N` inline slots:
  /// `ExtraHeadersBuilder::<4>::with_capacity()`.
  #[inline(always)]
  pub const fn with_capacity() -> Self {
    Self {
      entries: [("", ""); N],
      len: 0,
      overflowed: false,
    }
  }

  /// Appends one `(name, value)` pair. Chains infallibly; past the inline
  /// capacity the pair is not stored and the overflow flag is set, failing
  /// the handshake at encode time instead of silently dropping the header.
  #[must_use]
  pub fn with_header(mut self, name: &'a str, value: &'a str) -> Self {
    match self.entries.get_mut(self.len) {
      Some(slot) => {
        *slot = (name, value);
        self.len = self.len.saturating_add(1);
      }
      None => self.overflowed = true,
    }
    self
  }

  /// The pairs added so far. Crate-private on purpose: a public slice
  /// accessor would let `with_extra_headers(builder.entries())` route
  /// through the slice `From` impl and silently launder away the overflow
  /// flag — the ONLY public builder→`ExtraHeaders` path is borrowing the
  /// builder itself, which preserves it.
  pub(crate) fn entries(&self) -> &[(&'a str, &'a str)] {
    self.entries.get(..self.len).unwrap_or(&[])
  }

  /// Number of pairs added.
  #[inline(always)]
  pub const fn len(&self) -> usize {
    self.len
  }

  /// Whether no pairs have been added.
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// The inline capacity `N`.
  #[inline(always)]
  pub const fn capacity(&self) -> usize {
    N
  }

  /// Whether every inline slot is taken (the next `with_header` overflows).
  #[inline(always)]
  pub const fn is_full(&self) -> bool {
    self.len >= N
  }

  /// Whether a header was added past the capacity (the handshake will fail
  /// at encode time).
  #[inline(always)]
  pub const fn overflowed(&self) -> bool {
    self.overflowed
  }
}

impl<const N: usize> Default for ExtraHeadersBuilder<'_, N> {
  #[inline(always)]
  fn default() -> Self {
    Self::with_capacity()
  }
}
