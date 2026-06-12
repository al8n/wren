#[test]
fn noop_macros_typecheck_their_arguments() {
  let value = 42u32;
  crate::trace!(value, "message {}", value);
  crate::debug!(x = value, "msg");
  crate::info!(x = %value);
  crate::warn!(?value);
  crate::error!("plain {}", value);
  let span = crate::debug_span!("span", field = value);
  #[cfg(not(feature = "tracing"))]
  {
    let _guard = span.enter();
    let _entered = crate::info_span!("s2").entered();
  }
  #[cfg(feature = "tracing")]
  let _ = span;
}

#[cfg(not(feature = "tracing"))]
#[test]
fn noop_macros_never_evaluate_arguments() {
  fn boom() -> u32 {
    panic!("must never run");
  }
  // One side-effecting expression per macro arm shape.
  crate::trace!(x = boom(), "msg");
  crate::debug!(%boom());
  crate::warn!(?boom());
  crate::info!(x = %boom(), "msg");
  crate::error!("plain {}", boom());
  crate::trace!(target: "t", x = boom(), "msg");
  let _span = crate::debug_span!("span", field = boom());
}
