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
  /// [`accept`] and [`weight_for`] only: `Content-Type` has no weight grammar,
  /// so [`media_type`] yields a parameter named `q` like any other and never
  /// produces this.
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
  /// [`weight_for`] only: the candidate carries more parameter instances than
  /// [`MAX_TRACKED_PARAMS`], and the match would have had to look past the last
  /// one it can record.
  ///
  /// Nothing here is malformed — RFC 9110 §5.6.6 bounds `parameters` nowhere —
  /// so this names a limit of a no-alloc match rather than a fault the sender
  /// committed, which is why it is its own variant rather than a
  /// [`Parameters`](Self::Parameters) detail. One condition, one
  /// representation, the same rule that lifts
  /// [`ValueSpansFieldLines`](Self::ValueSpansFieldLines) out of that variant.
  #[error("candidate carries more parameters than the match can track")]
  TooManyParameters,
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

/// One member of an `Accept` list: RFC 9110 §12.5.1's
/// `media-range = ( "*/*" / ( type "/" "*" ) / ( type "/" subtype ) ) parameters`.
///
/// Borrows the field lines it was parsed from.
///
/// `Eq`/`PartialEq` compare the SAME bytes [`ListMember`]'s own `PartialEq`
/// does — as written, not as parsed — the same rule [`MediaType`]'s derive
/// documents and for the same reason: it lets a test assert
/// `accept(..).next() == Some(Err(MediaError::..))` without a `MediaRange`
/// value on the other side. It does NOT honour §8.3.1's case-insensitive
/// `type`/`subtype` (the same tokens a `media-range` reuses): a caller wanting
/// that compares [`ty`](Self::ty) and [`subtype`](Self::subtype) with
/// `str::eq_ignore_ascii_case`, not `==` on the whole value.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct MediaRange<'a> {
  ty: Option<&'a [u8]>,
  subtype: Option<&'a [u8]>,
  member: ListMember<'a>,
  weight: Weight,
}

impl<'a> MediaRange<'a> {
  /// The `type` token, or `None` for `*/*`.
  ///
  /// RFC 9110 §12.5.1: "The asterisk "*" character is used to group media types
  /// into ranges, with "*/*" indicating all media types and "type/*" indicating
  /// all subtypes of that type." Those two SHAPES are the wildcards; a literal
  /// `*` reached through the `type "/" subtype` alternative — `*/json` — is an
  /// ordinary token and reports `Some("*")`.
  #[inline]
  pub const fn ty(&self) -> Option<&'a str> {
    match self.ty {
      Some(bytes) => Some(ascii(bytes)),
      None => None,
    }
  }

  /// The `subtype` token, or `None` for `*/*` and for `type/*`.
  #[inline]
  pub const fn subtype(&self) -> Option<&'a str> {
    match self.subtype {
      Some(bytes) => Some(ascii(bytes)),
      None => None,
    }
  }

  /// The weight, defaulting to [`Weight::ONE`].
  ///
  /// RFC 9110 §12.4.2: "If no "q" parameter is present, the default weight is
  /// 1."
  #[inline]
  pub const fn weight(&self) -> Weight {
    self.weight
  }

  /// Every parameter EXCEPT `q`, wherever `q` appeared.
  ///
  /// RFC 9110 §12.5.1: "Recipients SHOULD process any parameter named "q" as
  /// weight, regardless of parameter ordering." *Any* means none of them is a
  /// range parameter, so none reaches this iterator.
  #[inline]
  pub fn params(&self) -> impl Iterator<Item = Result<(&'a [u8], ParamValue<'a>), ListError>> {
    self.member.params().filter(|p| match p {
      Ok((name, _)) => !name.eq_ignore_ascii_case(b"q"),
      Err(_) => true,
    })
  }
}

/// Reads a range out of one already-walked member.
fn range_from(member: ListMember<'_>) -> Result<MediaRange<'_>, MediaError> {
  let (ty, subtype) = split_solidus(member.name()).ok_or(MediaError::NotAMediaType)?;
  // Shape, per §12.5.1's two named wildcards. Anything else — `*/json` — is
  // the literal `type "/" subtype` alternative.
  let star = b"*".as_slice();
  let (ty, subtype) = match (ty == star, subtype == star) {
    (true, true) => (None, None),
    (false, true) => (Some(ty), None),
    // `(true, false)` is `*/json`: the literal `type "/" subtype`
    // alternative, whose type happens to be the one-character token `*`.
    // `(false, false)` is the ordinary case. Either way, `subtype` can never
    // surface as `Some("*")` from this function: the two arms above already
    // catch every case where the raw subtype bytes equal the one-character
    // token `*`, regardless of `ty`, so a literal single-asterisk subtype
    // always reads back as the `type/*` wildcard's `None`, never as a token.
    _ => (Some(ty), Some(subtype)),
  };
  // §5.6.6's `parameter` requires the `=`; a media range defines no grammar of
  // its own that admits a bare name (contrast RFC 6455 §9.1's
  // `extension-param`), so a valueless parameter is refused here exactly as
  // `media_type` refuses one. Every parameter named `q` that DOES carry a
  // value is weight, in wire order, last one wins.
  let mut weight = Weight::ONE;
  for param in member.params() {
    let (name, value) = param.map_err(MediaError::from)?;
    // Checked BEFORE the `q`-name check below, deliberately: a bare name
    // fails §5.6.6's `parameter` grammar outright, whatever it is called, and
    // that fault is more fundamental than §12.5.1's weight question — a bare
    // `q` is a missing value, not a bad `qvalue`.
    if matches!(value, ParamValue::None) {
      return Err(MediaError::ValuelessParameter);
    }
    if name.eq_ignore_ascii_case(b"q") {
      // A quoted qvalue is the same value as a bare one (§5.6.6: "The quoted
      // and unquoted values are equivalent."), so unquote before parsing.
      let mut buf = [0u8; 8];
      let written = value
        .unescape_into(&mut buf)
        .map_err(|_| MediaError::BadWeight)?;
      let digits = buf.get(..written).ok_or(MediaError::BadWeight)?;
      weight = parse_qvalue(digits).ok_or(MediaError::BadWeight)?;
    }
  }
  Ok(MediaRange {
    ty,
    subtype,
    member,
    weight,
  })
}

/// Walks an `Accept` field's ranges (RFC 9110 §12.5.1).
///
/// Takes the field's LINES rather than one value, for the reason
/// [`grammar::parameterised_list`](crate::grammar::parameterised_list) does:
/// §5.2 makes a repeated field one comma-joined value and a quoted-string may
/// span the join.
///
/// The walk STOPS at the first faulting member — later well-formed ranges are
/// unreachable. A walker that cannot tell a separator from data cannot say
/// which ranges the field named, and a member that is not a media range cannot
/// be yielded by this entry point at all.
///
/// # Errors
///
/// Each item is [`MediaError`]: [`NotAMediaType`](MediaError::NotAMediaType),
/// [`ValuelessParameter`](MediaError::ValuelessParameter),
/// [`BadWeight`](MediaError::BadWeight),
/// [`Parameters`](MediaError::Parameters) or
/// [`ValueSpansFieldLines`](MediaError::ValueSpansFieldLines).
pub fn accept<'a, I>(lines: I) -> impl Iterator<Item = Result<MediaRange<'a>, MediaError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  parameterised_list_with(lines, is_media_name).map(|member| match member {
    Ok(member) => range_from(member),
    Err(ListError::NotAToken) => Err(MediaError::NotAMediaType),
    Err(other) => Err(MediaError::from(other)),
  })
}

/// The most parameter instances a candidate may carry while a range's own
/// parameters are matched against it.
///
/// RFC 9110 bounds `parameters` nowhere, so this is a bound of the WALK rather
/// than of the grammar. [`weight_for`] matches a range's parameters against a
/// candidate's per INSTANCE, which means remembering which of the candidate's
/// instances it has already spent; a no-alloc core cannot grow that memory, so
/// the record is a fixed array of this many slots. A match that would have to
/// look past the last slot yields [`MediaError::TooManyParameters`] rather than
/// a weight read off the parameters it could see.
///
/// Two things this deliberately does NOT bound. It does not bound a range's own
/// parameters, which are walked without a record. And it does not reach a
/// candidate at all unless the range carries a parameter: `*/*`, `text/*` and
/// `text/plain` spend no slot, so they keep matching a candidate with any
/// number of parameters.
///
/// A parse-constant like [`MAX_HEADERS`](crate::MAX_HEADERS), not a
/// [`Limits`](crate::Limits) knob: the storage is in the binary, so a caller
/// cannot raise it.
pub const MAX_TRACKED_PARAMS: usize = 16;

/// Whether two parameter values are the same value.
///
/// RFC 9110 §5.6.6: "A parameter value that matches the token production can be
/// transmitted either as a token or within a quoted-string." and "The quoted
/// and unquoted values are equivalent." §5.6.4 adds the recipient MUST that
/// removes `quoted-pair` escapes. Byte-exact after both, and NOT case-folded:
/// §8.3.1 says "Parameter values might or might not be case-sensitive,
/// depending on the semantics of the parameter name", which is each
/// registration's business rather than this crate's.
fn same_value(a: ParamValue<'_>, b: ParamValue<'_>) -> bool {
  a.unescaped().eq(b.unescaped())
}

/// How specific a shape is: smaller wins. `type/subtype` 0, `type/*` 1,
/// `*/*` 2 — items 2, 3 and 4 of §12.5.1's printed precedence list.
const fn shape_rank(range: &MediaRange<'_>) -> u8 {
  match (range.ty, range.subtype) {
    (Some(_), Some(_)) => 0,
    (Some(_), None) => 1,
    (None, _) => 2,
  }
}

/// Whether `range` matches `candidate`, and with how many parameter instances.
///
/// `None` for no match. `Some(n)` where `n` counts the range's own parameter
/// instances other than `q`, all of which found their own counterpart.
///
/// # Errors
///
/// A [`MediaError`] the candidate's own parameter walk produced, or
/// [`MediaError::TooManyParameters`] when the match would have to look past
/// [`MAX_TRACKED_PARAMS`] candidate instances.
fn matched_instances(
  range: &MediaRange<'_>,
  candidate: &MediaType<'_>,
) -> Result<Option<usize>, MediaError> {
  // Shape decides the type/subtype test, per §12.5.1's two named wildcards.
  // `MediaType` stores the two tokens as bytes; `ty()`/`subtype()` are the
  // `&str` VIEW of them, so compare the fields, not the accessors.
  match (range.ty, range.subtype) {
    (None, _) => {}
    (Some(ty), None) => {
      if !ty.eq_ignore_ascii_case(candidate.ty) {
        return Ok(None);
      }
    }
    (Some(ty), Some(subtype)) => {
      if !ty.eq_ignore_ascii_case(candidate.ty) || !subtype.eq_ignore_ascii_case(candidate.subtype)
      {
        return Ok(None);
      }
    }
  }

  // Per INSTANCE: each parameter the range carries must find its own
  // counterpart, so a doubled range parameter needs a doubled candidate one.
  // `taken` marks the candidate instances already spent, by position.
  let mut taken = [false; MAX_TRACKED_PARAMS];
  let mut count = 0usize;
  for param in range.params() {
    let (name, value) = param.map_err(MediaError::from)?;
    let mut found = false;
    // First fit, and that is a MAXIMUM matching only because the predicate
    // below is a conjunction of two equivalence relations — name equality
    // ASCII-case-insensitively, value equality after unescaping. Those make the
    // range-to-candidate graph a disjoint union of complete blocks, in which no
    // choice can strand an augmenting path. Fold case for some registered
    // parameter, or admit a prefix or subset match, and the blocks stop being
    // complete: first fit then silently stops being maximum and undercounts.
    for (at, candidate_param) in candidate.params().enumerate() {
      let (candidate_name, candidate_value) = candidate_param.map_err(MediaError::from)?;
      let Some(slot) = taken.get_mut(at) else {
        // Past what this walk can track: refuse rather than answer wrongly.
        return Err(MediaError::TooManyParameters);
      };
      // §5.6.6: "Parameter names are case-insensitive".
      if !*slot && candidate_name.eq_ignore_ascii_case(name) && same_value(value, candidate_value) {
        *slot = true;
        found = true;
        break;
      }
    }
    if !found {
      return Ok(None);
    }
    count = count.saturating_add(1);
  }
  Ok(Some(count))
}

/// The weight an `Accept` field gives `candidate` (RFC 9110 §12.5.1).
///
/// §12.5.1: "The media type quality factor associated with a given type is
/// determined by finding the media range with the highest precedence that
/// matches the type."
///
/// Precedence is a lexicographic key over the ranges that matched: shape
/// (`type/subtype`, then `type/*`, then `*/*`), then matched parameter
/// instances (more first), then field order (first first). The key GENERATES
/// §12.5.1's printed four-item list rather than transcribing it, which is what
/// ranks a parameterised wildcard above its bare form — a pair that list does
/// not contain.
///
/// Three parts of that are READINGS rather than answers §12.5.1 gives, and they
/// ship as implementation-defined determinism — stable, not uniquely
/// conforming. Shape dominating matched-parameter count is one: `text/plain`
/// outranks `text/*;format=flowed`, and §12.5.1 orders that pair nowhere. Field
/// order settling every residual tie is the second. Matching a duplicated
/// parameter name per INSTANCE rather than by set membership is the third — a
/// range naming `a` twice matches only a candidate offering two, so repeating a
/// parameter cannot buy precedence.
///
/// Parameter names compare ASCII-case-insensitively and values compare
/// byte-exact after unescaping. Values are NOT case-folded: §8.3.1 says
/// "Parameter values might or might not be case-sensitive, depending on the
/// semantics of the parameter name", so which of them fold is each
/// registration's business rather than this crate's. The consequence is worth
/// stating rather than leaving to be discovered — a field saying
/// `text/html;charset=UTF-8;q=0.6, */*;q=0.1` gives the candidate
/// `text/html;charset=utf-8` a weight of `0.1`, because the specific range does
/// not match and the walk falls through. A candidate carrying parameters the
/// range does not name DOES still match, which is how `text/*` matches
/// `text/html;level=3`.
///
/// [`Weight::ZERO`] is the answer both for a matching range that says `q=0` and
/// for a candidate nothing matched. §12.4.3: "If no wildcard is present, values
/// that are not explicitly mentioned in the field are considered unacceptable."
///
/// This answers what weight applies to ONE candidate; ranking a caller's
/// candidates is the caller's own loop over this.
///
/// # Errors
///
/// Any [`MediaError`] the walk produces. A malformed field yields `Err` rather
/// than a weight, because a walker that cannot tell a separator from data
/// cannot say which ranges the field named. Also
/// [`MediaError::TooManyParameters`], which is about the CANDIDATE rather than
/// the field: see [`MAX_TRACKED_PARAMS`].
pub fn weight_for<'a, I>(candidate: &MediaType<'_>, accept_lines: I) -> Result<Weight, MediaError>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  let mut best: Option<((u8, usize, usize), Weight)> = None;
  for (at, range) in accept(accept_lines).enumerate() {
    let range = range?;
    let Some(matched) = matched_instances(&range, candidate)? else {
      continue;
    };
    // `usize::MAX - matched` inverts "more is better" into "smaller wins"
    // without a signed key; `saturating_sub` keeps it off the lint wall.
    // `core::cmp::Reverse(matched)` is NOT the simplification it looks like:
    // it makes `best`'s annotation `Option<((u8, Reverse<usize>, usize),
    // Weight)>`, which `clippy::type_complexity` rejects under `-D warnings`.
    // Checked, not assumed.
    //
    // `at` and the strict `<` below are redundant with each other, and both
    // stay. `at` is what makes the key TOTAL — no two ranges can tie — and the
    // strict `<` is what keeps the first of any tie. Dropping either one alone
    // still answers first-in-field-order; dropping both answers LAST, which is
    // a different contract. Neither is dead code because of the other.
    let key = (shape_rank(&range), usize::MAX.saturating_sub(matched), at);
    if best.is_none_or(|(best_key, _)| key < best_key) {
      best = Some((key, range.weight()));
    }
  }
  Ok(best.map_or(Weight::ZERO, |(_, weight)| weight))
}

#[cfg(test)]
mod tests;
