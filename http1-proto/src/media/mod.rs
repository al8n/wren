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

use crate::grammar::{
  ListError, ListMember, ParamIter, ParamValue, has_bare_comma, is_token, parameterised_list_with,
};

/// Why a media-type or `Accept` walk stopped.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum MediaError {
  /// The member is not RFC 9110 §8.3.1's `type "/" subtype` — no solidus, an
  /// empty half, or a byte §5.6.2's `token` forbids in either half.
  #[error("not a media type: expected type/subtype")]
  NotAMediaType,
  /// An RFC 9110 §5.6.6 `parameters` fault, carrying the walker's own detail.
  #[error(transparent)]
  Parameters(ListError),
  /// A parameter with no `=`, such as `charset` in `text/html;charset`.
  ///
  /// RFC 9110 §5.6.6's `parameter` grammar requires the `=`; the walker
  /// admits a bare name only for fields that define their own parameter
  /// grammar — RFC 6455 §9.1's extension parameters are one such field. A
  /// media type defines no such grammar, so this is the entry points' own
  /// refusal rather than something the walker itself reports as
  /// [`Parameters`](Self::Parameters).
  #[error("parameter has no value")]
  ValuelessParameter,
  /// A parameter named `q` whose value is not RFC 9110 §12.4.2's `qvalue`.
  ///
  /// `accept` and `weight_for` only (plain code spans, not links, because
  /// neither exists yet; Task 7 restores both once they do): `Content-Type`
  /// has no weight grammar, so [`media_type`] yields a parameter named `q`
  /// like any other and never produces this.
  #[error("the q parameter's value is not a qvalue")]
  BadWeight,
  /// A quoted value crosses an RFC 9110 §5.2 field-line join, so it is well
  /// formed and not one contiguous slice. The walker reports this as
  /// [`ListError::ValueSpansFieldLines`]; the entry points LIFT it here, so
  /// [`Parameters`](Self::Parameters) never carries that case.
  #[error("quoted value spans a field-line join and is not one contiguous slice")]
  ValueSpansFieldLines,
  /// [`media_type`] only: a comma outside a quoted-string. `Content-Type` is a
  /// singleton field (RFC 9110 §8.3), so a list is a malformed field rather
  /// than a value to recover from.
  #[error("Content-Type is a singleton field and this value is a list")]
  NotASingleton,
}

impl From<ListError> for MediaError {
  fn from(e: ListError) -> Self {
    match e {
      // One condition, one representation.
      ListError::ValueSpansFieldLines => Self::ValueSpansFieldLines,
      other => Self::Parameters(other),
    }
  }
}

/// Splits `type "/" subtype` on its ONE solidus.
///
/// `None` when there is no solidus. A second solidus is left in the subtype,
/// where `is_token` then refuses it — `/` is not a `tchar`.
#[inline]
pub(crate) fn split_solidus(name: &[u8]) -> Option<(&[u8], &[u8])> {
  let at = name.iter().position(|b| *b == b'/')?;
  match (name.get(..at), name.get(at.saturating_add(1)..)) {
    (Some(ty), Some(subtype)) => Some((ty, subtype)),
    _ => None,
  }
}

/// RFC 9110 §8.3.1's `media-type = type "/" subtype parameters`, where
/// `type = token` and `subtype = token`.
///
/// This is the member-name grammar the media entry points hand the walker, in
/// place of the `token` a transfer-parameter list uses.
pub(crate) fn is_media_name(name: &[u8]) -> bool {
  match split_solidus(name) {
    Some((ty, subtype)) => is_token(ty) && is_token(subtype),
    None => false,
  }
}

/// Interprets ASCII-by-construction bytes as `str`.
///
/// A `token` is ASCII by RFC 9110 §5.6.2's `tchar`, so the `Err` arm is
/// unreachable for anything [`is_media_name`] admitted. It still has to compile
/// to something, and under the crate's link-time no-panic proof that something
/// may not be a panic: hence the checked form with an empty-string arm rather
/// than `unwrap`.
#[inline]
const fn ascii(bytes: &[u8]) -> &str {
  match core::str::from_utf8(bytes) {
    Ok(s) => s,
    Err(_) => "",
  }
}

/// One media type: RFC 9110 §8.3.1's `type "/" subtype parameters`.
///
/// Borrows the value it was parsed from; nothing is copied.
///
/// `Eq`/`PartialEq` compare the SAME bytes [`ListMember`]'s own `PartialEq`
/// does — as written, not as parsed — which is what lets a test assert
/// `media_type(..) == Err(MediaError::..)` without a `MediaType` value on the
/// other side.
///
/// That byte equality does NOT honour §8.3.1's "The type and subtype tokens
/// are case-insensitive" (quoted below, on [`ty`](Self::ty) and
/// [`subtype`](Self::subtype)): a `MediaType` parsed from `TEXT/plain`
/// compares UNEQUAL to one parsed from `text/plain` under this derive. A
/// caller comparing two media types compares [`ty`](Self::ty) and
/// [`subtype`](Self::subtype) with `str::eq_ignore_ascii_case`, not `==` on
/// the whole value.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct MediaType<'a> {
  ty: &'a [u8],
  subtype: &'a [u8],
  member: ListMember<'a>,
}

impl<'a> MediaType<'a> {
  /// The `type` token.
  ///
  /// RFC 9110 §8.3.1: "The type and subtype tokens are case-insensitive." This
  /// hands over the bytes as written; the comparison is the caller's.
  #[inline]
  pub const fn ty(&self) -> &'a str {
    ascii(self.ty)
  }

  /// The `subtype` token, compared case-insensitively for the same reason.
  #[inline]
  pub const fn subtype(&self) -> &'a str {
    ascii(self.subtype)
  }

  /// Every parameter, in wire order — including one named `q`, which carries no
  /// special meaning in a `Content-Type`.
  #[inline]
  pub const fn params(&self) -> ParamIter<'a> {
    self.member.params()
  }
}

/// Reads ONE `Content-Type` value (RFC 9110 §8.3).
///
/// Takes a single value rather than a field's lines. §8.3: "Although
/// Content-Type is defined as a singleton field, it is sometimes incorrectly
/// generated multiple times, resulting in a combined field value that appears
/// to be a list. Recipients often attempt to handle this error by using the
/// last syntactically valid member of the list, leading to potential
/// interoperability and security issues if different implementations have
/// different error handling behaviors." Refusal is the one behaviour that
/// cannot diverge, so a comma outside a quoted-string is refused here.
///
/// # Errors
///
/// [`MediaError::NotASingleton`] for that comma, [`MediaError::NotAMediaType`]
/// when the name is not `type "/" subtype`, [`MediaError::ValuelessParameter`]
/// for a parameter with no `=`, and [`MediaError::Parameters`] for any other
/// §5.6.6 parameter fault. Never [`MediaError::BadWeight`]. Never
/// [`MediaError::ValueSpansFieldLines`] either: that variant needs an
/// RFC 9110 §5.2 join between field LINES to span, and a value walked as a
/// single line has no second line to join with — `accept`, which walks a
/// field's several lines, is where it is reachable.
pub fn media_type(value: &[u8]) -> Result<MediaType<'_>, MediaError> {
  if has_bare_comma(value) {
    return Err(MediaError::NotASingleton);
  }
  let member = parameterised_list_with([value], is_media_name)
    .next()
    .ok_or(MediaError::NotAMediaType)?
    .map_err(|e| match e {
      ListError::NotAToken => MediaError::NotAMediaType,
      other => MediaError::from(other),
    })?;
  let (ty, subtype) = split_solidus(member.name()).ok_or(MediaError::NotAMediaType)?;
  // The media grammar's `parameter` requires its `=` (§5.6.6); the walker
  // admits a bare name for the fields that define their own grammar, so this
  // entry point rejects what those fields keep.
  for param in member.params() {
    let (_, value) = param.map_err(MediaError::from)?;
    if matches!(value, ParamValue::None) {
      return Err(MediaError::ValuelessParameter);
    }
  }
  Ok(MediaType {
    ty,
    subtype,
    member,
  })
}

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
