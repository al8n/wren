// `media_type`, `accept`, and `weight_for` (here and in `Weight`'s own doc
// below) are plain code spans, not intra-doc links: their targets don't exist
// until Tasks 4-6 land, and `-Dwarnings` fails an unresolved link on every
// commit in between, not only once at the end of the feature. Task 7 turns all
// four spans back into links once the public surface is complete.
//! The RFC 9110 §8.3.1 media type and §12.5.1 `Accept` range, over the §5.6.6
//! parameter grammar the crate already walks.
//!
//! Two entry points share one walk: `media_type` reads a single
//! `Content-Type` value and `accept` walks an `Accept` field's lines.
//! `weight_for` composes §12.5.1's precedence with §12.4.2's weight, which is
//! the one derivation those sections settle; choosing a representation from the
//! result is the caller's, and §12.1 says a user agent "cannot rely on
//! proactive negotiation preferences being consistently honored".

/// A `qvalue` (RFC 9110 §12.4.2) in thousandths: `0..=1000`.
///
/// Fixed point rather than a float because the grammar is already fixed point —
/// one digit and at most three decimals — and because this core compares
/// weights exactly, on tiers with no FPU and under a link-time no-panic proof.
///
/// The `Ord` derive is PREFERENCE, not precedence: §12.4.2 says "0.001 is the
/// least preferred and 1 is the most preferred", while which RANGE applies to a
/// candidate is §12.5.1's separate question. Only `weight_for` composes the
/// two, and it composes them in §12.5.1's order.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Weight(u16);

impl Weight {
  /// RFC 9110 §12.4.2: "a value of 0 means "not acceptable"".
  pub const ZERO: Self = Self(0);
  /// RFC 9110 §12.4.2: "If no "q" parameter is present, the default weight is
  /// 1."
  pub const ONE: Self = Self(1000);

  /// The weight in thousandths, `0..=1000`.
  #[inline]
  pub const fn thousandths(self) -> u16 {
    self.0
  }
}

/// Reads RFC 9110 §12.4.2's `qvalue`:
/// `( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`.
///
/// `None` for anything else, INCLUDING a value that is a perfectly good
/// `parameter` value — `q=blah`, `q=1.5`, `q=0.5000`. Note that `0.` and `1.`
/// ARE valid: `[ "." 0*3DIGIT ]` admits zero digits after the dot.
// No non-test caller yet: `#[cfg(test)]` is the only reachable call site
// until Task 5's `range_from` becomes the first one. Task 5 MUST remove this
// attribute and this comment when it adds that call.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_qvalue(v: &[u8]) -> Option<Weight> {
  let (first, rest) = v.split_first()?;
  let one = match *first {
    b'0' => false,
    b'1' => true,
    _ => return None,
  };
  let digits = match rest.split_first() {
    None => return Some(if one { Weight::ONE } else { Weight::ZERO }),
    Some((&b'.', digits)) => digits,
    Some(_) => return None,
  };
  if digits.len() > 3 {
    return None;
  }
  if one {
    // `( "1" [ "." 0*3("0") ] )` — after the 1, only zeros.
    return digits.iter().all(|d| *d == b'0').then_some(Weight::ONE);
  }
  let mut thousandths: u16 = 0;
  for (place, digit) in digits.iter().enumerate() {
    let value = u16::from(digit.checked_sub(b'0')?);
    if value > 9 {
      return None;
    }
    // Position-indexed rather than divided down: `clippy::integer_division` is
    // denied crate-wide, and three places need no loop-carried scale.
    let scale: u16 = match place {
      0 => 100,
      1 => 10,
      2 => 1,
      _ => return None,
    };
    thousandths = thousandths.checked_add(value.checked_mul(scale)?)?;
  }
  Some(Weight(thousandths))
}

#[cfg(test)]
mod tests;
