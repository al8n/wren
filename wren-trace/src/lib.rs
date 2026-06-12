#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "tracing")]
pub use tracing::{debug, debug_span, error, info, info_span, trace, trace_span, warn};

/// Token-consuming no-op for all five diagnostic macros when `tracing` is
/// disabled. Every argument expression is type-checked but **never
/// executed**: each value is referenced inside an `if false { }` block,
/// which the compiler eliminates entirely while still seeing the expression
/// as "used" (no `unused_variables` warning, no side effects, no alloc, no
/// panics).
///
/// # Supported forms
///
/// | Form | Example |
/// |------|---------|
/// | Positional format string | `debug!("n={}", n)` |
/// | `key = value` | `debug!(x = val, "msg")` |
/// | `key = %value` (Display) | `debug!(x = %val, "msg")` |
/// | `key = ?value` (Debug) | `debug!(x = ?val, "msg")` |
/// | Bare `%value` / `?value` | `debug!(%val)` |
/// | Bare `ident` shorthand | `debug!(x, "msg")` |
/// | `target: "t", ...` prefix | `debug!(target: "t", x = 1, "m")` |
///
/// # Unsupported forms
///
/// The following `tracing` forms are deliberately **not** supported:
/// `name: "..."`, `parent: span`, dotted field names (`a.b`), and
/// string-literal field keys (`"k" = v`). The codebase stays within the
/// subset above; any violation is caught as a compile error in the default
/// (no-tracing) build.
///
/// # Implementation note
///
/// Each value expression `$val` expands to `if false { let _ = &$val; }`.
/// The compiler eliminates the dead branch during MIR building, so there is
/// zero runtime cost. A plain `let _ = &$val;` would evaluate the expression
/// to produce the reference even though it is discarded, causing side
/// effects (allocs, panics, counter bumps) to run in disabled builds.
#[doc(hidden)]
#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! __wren_trace_noop {
  (target: $tgt:expr, $($rest:tt)*) => {
    { if false { let _ = &$tgt; } $crate::__wren_trace_noop!($($rest)*) }
  };

  ($key:ident = %$val:expr, $($rest:tt)*) => {
    { if false { let _ = &$val; } $crate::__wren_trace_noop!($($rest)*) }
  };
  ($key:ident = %$val:expr) => {
    { if false { let _ = &$val; } }
  };

  ($key:ident = ?$val:expr, $($rest:tt)*) => {
    { if false { let _ = &$val; } $crate::__wren_trace_noop!($($rest)*) }
  };
  ($key:ident = ?$val:expr) => {
    { if false { let _ = &$val; } }
  };

  ($key:ident = $val:expr, $($rest:tt)*) => {
    { if false { let _ = &$val; } $crate::__wren_trace_noop!($($rest)*) }
  };
  ($key:ident = $val:expr) => {
    { if false { let _ = &$val; } }
  };

  // Matches BEFORE the format-string literal arm so that a bare ident that
  // is NOT a string literal is consumed correctly.
  ($key:ident, $($rest:tt)*) => {
    { if false { let _ = &$key; } $crate::__wren_trace_noop!($($rest)*) }
  };
  ($key:ident) => {
    { if false { let _ = &$key; } }
  };

  (%$val:expr, $($rest:tt)*) => {
    { if false { let _ = &$val; } $crate::__wren_trace_noop!($($rest)*) }
  };
  (%$val:expr) => {
    { if false { let _ = &$val; } }
  };

  (?$val:expr, $($rest:tt)*) => {
    { if false { let _ = &$val; } $crate::__wren_trace_noop!($($rest)*) }
  };
  (?$val:expr) => {
    { if false { let _ = &$val; } }
  };

  ($fmt:literal $(, $arg:expr)* $(,)?) => {
    { if false { let _ = ::core::format_args!($fmt $(, $arg)*); } }
  };

  () => {{}};
}

#[cfg(not(feature = "tracing"))]
pub use __wren_trace_noop as trace;
#[cfg(not(feature = "tracing"))]
pub use __wren_trace_noop as debug;
#[cfg(not(feature = "tracing"))]
pub use __wren_trace_noop as info;
#[cfg(not(feature = "tracing"))]
pub use __wren_trace_noop as warn;
#[cfg(not(feature = "tracing"))]
pub use __wren_trace_noop as error;

/// No-op span returned when the `tracing` feature is disabled.
///
/// Implements `.entered()` and `.enter()` so that
/// `wren_trace::info_span!(...).entered()` compiles in both tracing and
/// no-tracing builds.
#[cfg(not(feature = "tracing"))]
#[derive(Debug)]
pub struct NoopSpan;

#[cfg(not(feature = "tracing"))]
impl NoopSpan {
  /// Enters the span (no-op). Returns `self` so it acts as a drop-guard.
  #[inline]
  pub fn entered(self) -> Self {
    self
  }

  /// Borrows the span and returns a new no-op guard (matches tracing's API).
  #[inline]
  pub fn enter(&self) -> Self {
    NoopSpan
  }
}

/// Token-consuming no-op for span macros when `tracing` is disabled.
/// Returns a [`NoopSpan`] so callers may use `.entered()` / `.enter()`
/// without compile errors. Uses the same field-consuming grammar as
/// [`__wren_trace_noop`] so variables passed as span fields are not flagged
/// as unused.
#[doc(hidden)]
#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! __wren_trace_noop_span {
  (target: $tgt:expr, $($rest:tt)*) => {
    { if false { let _ = &$tgt; } $crate::__wren_trace_noop_span!($($rest)*) }
  };

  // Span name only (the required first argument after an optional target).
  // Any remaining tokens are field key=value pairs — consume them via the
  // diagnostic no-op and return the NoopSpan.
  ($name:literal, $($fields:tt)*) => {
    { $crate::__wren_trace_noop!($($fields)*); $crate::NoopSpan }
  };
  ($name:literal) => {
    $crate::NoopSpan
  };

  ($($tt:tt)*) => {
    { $crate::__wren_trace_noop!($($tt)*); $crate::NoopSpan }
  };
}

#[cfg(not(feature = "tracing"))]
pub use __wren_trace_noop_span as trace_span;
#[cfg(not(feature = "tracing"))]
pub use __wren_trace_noop_span as debug_span;
#[cfg(not(feature = "tracing"))]
pub use __wren_trace_noop_span as info_span;

#[cfg(test)]
mod tests;
