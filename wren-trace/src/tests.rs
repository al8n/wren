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
  crate::trace!(x = boom(), "msg");
  crate::debug!(%boom());
}
