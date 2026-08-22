//! The RFC 9110 §8.3.1 media type and §12.5.1 `Accept` range, over the §5.6.6
//! parameter grammar the crate already walks.
//!
//! Two entry points share one walk: [`media_type`] reads a single
//! `Content-Type` value and [`accept`] walks an `Accept` field's lines.
//! [`weight_for`] composes §12.5.1's precedence with §12.4.2's weight, which is
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
/// single line has no second line to join with — [`accept`], which walks a
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
/// candidate is §12.5.1's separate question. Only [`weight_for`] composes the
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
  // A valueless parameter is refused here exactly as `media_type` refuses one
  // (`MediaError::ValuelessParameter`). Every parameter named `q` that DOES
  // carry a value is weight, in wire order, last one wins.
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
/// unreachable, and every `next` after the `Err` is `None`. A walker that
/// cannot tell a separator from data cannot say which ranges the field named,
/// and a member that is not a media range cannot be yielded by this entry point
/// at all. A caller that processed the suffix of a malformed `Accept` would be
/// the second of two recipients disagreeing about a hostile field.
///
/// EVERY fault stops it, wherever it was found. Some are the list walk's own —
/// a member whose boundaries it cannot resolve, or a name that is not
/// `type "/" subtype` — and it cannot go on past either, so it latches itself.
/// The rest are this entry point's, found while reading an already-delimited
/// member as a range: a `q` that is not a `qvalue`, a parameter with no value, a
/// quoted value that spans the §5.2 join. Those leave the list walk perfectly
/// able to continue, and stopping there is a decision made here rather than one
/// inherited.
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
  Accept {
    members: parameterised_list_with(lines, is_media_name),
    done: false,
  }
}

/// The walk [`accept`] hands out: the delimited members still to come, and
/// whether one of them has already faulted.
///
/// A stateless `map` over the member walk would latch only HALF the faults.
/// The list walk stops itself when a member's own boundaries are unresolved,
/// but a fault [`range_from`] finds is invisible to it — it handed over an
/// `Ok(member)` and is ready with the next one. The `done` flag below is what
/// makes the two kinds stop alike, which is the contract [`accept`] documents.
struct Accept<I> {
  members: I,
  /// An `Err` has been yielded, from either source. Latched, never cleared: an
  /// `Iterator` that has answered `None` may answer `Some` again, and this one
  /// must not.
  done: bool,
}

impl<'a, I> Iterator for Accept<I>
where
  I: Iterator<Item = Result<ListMember<'a>, ListError>>,
{
  type Item = Result<MediaRange<'a>, MediaError>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.done {
      return None;
    }
    let range = match self.members.next()? {
      Ok(member) => range_from(member),
      Err(ListError::NotAToken) => Err(MediaError::NotAMediaType),
      Err(other) => Err(MediaError::from(other)),
    };
    if range.is_err() {
      self.done = true;
    }
    Some(range)
  }
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

/// Whether two parameter values are the same value, folding ASCII case when
/// `fold_case`.
///
/// RFC 9110 §5.6.6: "A parameter value that matches the token production can be
/// transmitted either as a token or within a quoted-string." and "The quoted
/// and unquoted values are equivalent." §5.6.4 adds the recipient MUST that
/// removes `quoted-pair` escapes. Both are done here, on both sides, and what
/// is left is a byte comparison.
///
/// WHETHER to fold is not decided here. §8.3.1: "Parameter values might or
/// might not be case-sensitive, depending on the semantics of the parameter
/// name" — so the decision belongs to whoever knows the parameter, and it
/// arrives as an argument. [`rfc_folds_case`] is what RFC 9110 knows;
/// [`weight_for_with`] is where a caller adds what it knows.
fn same_value(fold_case: bool, a: ParamValue<'_>, b: ParamValue<'_>) -> bool {
  if fold_case {
    return a
      .unescaped()
      .map(|byte| byte.to_ascii_lowercase())
      .eq(b.unescaped().map(|byte| byte.to_ascii_lowercase()));
  }
  a.unescaped().eq(b.unescaped())
}

/// Whether RFC 9110 ITSELF settles this parameter's value as case-insensitive.
///
/// One parameter does: §8.3.2 says "In the fields defined by this document,
/// charset names appear either in parameters (Content-Type), or, for
/// Accept-Encoding, in the form of a plain token. In both cases, charset names
/// are matched case-insensitively." §8.3.1's own next sentence points the same
/// way, calling four spellings of one media type equivalent because "the
/// `charset` parameter value is defined as being case-insensitive in
/// [RFC2046], Section 4.1.2".
///
/// And only that one. Every other case rule RFC 9110 states is about a NAME —
/// field names, parameter names, connection options, content codings, range
/// units, auth schemes, protocol names — or about `q`, which §12.5.1 takes as
/// weight before a value reaches a comparison. `boundary` in particular is
/// given no case rule by RFC 9110 at all: RFC 2046 §4.1.2 grants that exemption
/// to `charset` alone, and a `boundary` is matched against the literal octets of
/// a delimiter line (RFC 2046 §5.1.1).
///
/// This is the floor rather than the whole rule. A parameter whose own
/// registration gives it other semantics is a case RFC 9110 does not settle and
/// this crate does not know; [`weight_for_with`] is how a caller supplies it.
/// It cannot be turned OFF, because §8.3.2 is not a default anyone may
/// disagree with.
///
/// `name` has already been matched ASCII-case-insensitively by the caller
/// (§5.6.6: "Parameter names are case-insensitive"), so `Charset` selects this
/// exactly as `charset` does.
fn rfc_folds_case(name: &[u8]) -> bool {
  name.eq_ignore_ascii_case(b"charset")
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
fn matched_instances<F>(
  range: &MediaRange<'_>,
  candidate: &MediaType<'_>,
  fold: &F,
) -> Result<Option<usize>, MediaError>
where
  F: Fn(&[u8], &[u8], &[u8]) -> bool,
{
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
    // choice can strand an augmenting path. Admit a prefix or a subset match
    // and the blocks stop being complete, because neither of those is
    // symmetric: first fit then silently stops being maximum and undercounts.
    //
    // Case FOLDING is not in that class and is not what this rules out,
    // whether it comes from `rfc_folds_case` or from the caller's `fold`. Name
    // equality is already a precondition of the comparison, so a per-name
    // folding rule is still an equivalence on the pairs and the blocks stay
    // complete. What breaks it is a predicate that is not an equivalence at
    // all — and a `fold` that answered differently for the same name would be
    // exactly that, which is why it is asked ONCE per range parameter, here,
    // rather than once per candidate instance inside the loop.
    //
    // `fold` receives the CANDIDATE's type/subtype, not the range's — see
    // `weight_for_with`'s doc for why.
    let fold_case = rfc_folds_case(name) || fold(candidate.ty, candidate.subtype, name);
    for (at, candidate_param) in candidate.params().enumerate() {
      let (candidate_name, candidate_value) = candidate_param.map_err(MediaError::from)?;
      let Some(slot) = taken.get_mut(at) else {
        // Past what this walk can track: refuse rather than answer wrongly.
        return Err(MediaError::TooManyParameters);
      };
      // §5.6.6: "Parameter names are case-insensitive".
      if !*slot
        && candidate_name.eq_ignore_ascii_case(name)
        && same_value(fold_case, value, candidate_value)
      {
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
/// Parameter names compare ASCII-case-insensitively (§5.6.6) and values compare
/// byte-exact after unescaping, with `charset` the one exception: §8.3.2 says
/// "In both cases, charset names are matched case-insensitively", so a field
/// saying `text/html;charset=UTF-8;q=0.6, */*;q=0.1` gives the candidate
/// `text/html;charset=utf-8` a weight of `0.6` and not the wildcard's `0.1`.
/// Every OTHER value stays byte-exact, because §8.3.1 leaves it so — a field
/// saying `text/html;boundary=A;q=0.6, */*;q=0.1` gives
/// `text/html;boundary=a` the wildcard's `0.1`, since the specific range does
/// not match and the walk falls through. §8.3.1 says "Parameter values might or
/// might not be case-sensitive, depending on the semantics of the parameter
/// name", and `charset` is the one whose semantics RFC 9110 states, so the
/// split is the RFC's rather than this crate's. A candidate carrying parameters
/// the range does not name DOES still match, which is how `text/*` matches
/// `text/html;level=3`.
///
/// That leaves a case worth stating outright, because its failure mode is a
/// SAFE-looking wrong answer. A parameter whose own registration gives its
/// value semantics other than byte equality — RFC 9782 §6.3 registers
/// `eat_profile` for `application/eat+cwt` with a case-insensitive value, one
/// of many — is not something RFC 9110 settles and not something this crate
/// knows. Here, such a parameter compares byte-exact, so a range spelling it
/// differently does NOT match, INCLUDING a range that says `q=0`: the refusal
/// is missed, the walk falls through to whatever coarser range sits behind it,
/// and a representation the client refused comes back acceptable. Use
/// [`weight_for_with`] to supply what your caller knows about its own
/// parameters.
///
/// [`Weight::ZERO`] is the answer both for a matching range that says `q=0` and
/// for a candidate nothing matched. §12.4.3: "If no wildcard is present, values
/// that are not explicitly mentioned in the field are considered unacceptable."
///
/// An ABSENT field is neither of those, and it answers differently. NO lines at
/// all is how a caller spells a request that carried no `Accept`, and §12.4.1 —
/// titled Absence — settles that input on its own: "For each of the content
/// negotiation fields, a request that does not contain the field implies that
/// the sender has no preference on that dimension of negotiation." No preference
/// is not a refusal, so every candidate keeps [`Weight::ONE`], §12.4.2's default
/// weight, and no matching is done at all. §12.4.1's next sentence confirms the
/// reading by reserving the 406 for a field that IS present: "If a content
/// negotiation header field is present in a request and none of the available
/// representations for the response can be considered acceptable according to
/// it, the origin server can either honor the header field by sending a 406 (Not
/// Acceptable) response or disregard the header field by treating the response
/// as if it is not subject to content negotiation for that request header
/// field."
///
/// ONE line that happens to be empty is a different input and keeps
/// [`Weight::ZERO`]. `Accept` is `#( media-range [ weight ] )`, and §5.6.1.1
/// expands that to `#element => [ 1#element ]` — the list may be empty — so such
/// a field WAS sent and named no range, which is §12.4.3's unmentioned value
/// once more. Three inputs, two answers:
///
/// | lines | the field | answer |
/// |---|---|---|
/// | none | never sent | [`Weight::ONE`] |
/// | one empty line | sent, list empty | [`Weight::ZERO`] |
/// | ranges, none matching | sent, candidate unmentioned | [`Weight::ZERO`] |
///
/// The iterator already carries that distinction — zero items against one empty
/// item — so this reads presence off the input rather than taking a flag for it.
/// A caller holding an absent field passes no lines and a caller holding an empty
/// one passes its empty value, each of which is what they already have.
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
///
/// Never for an ABSENT field: with no lines there is nothing to walk and no
/// candidate parameter to track, so [`Weight::ONE`] is unconditional there.
pub fn weight_for<'a, I>(candidate: &MediaType<'_>, accept_lines: I) -> Result<Weight, MediaError>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  // The empty policy: this crate adds nothing to what RFC 9110 itself settles.
  // `rfc_folds_case` still applies inside — see `weight_for_with`.
  weight_for_with(candidate, accept_lines, |_: &[u8], _: &[u8], _: &[u8]| {
    false
  })
}

/// [`weight_for`], with the caller's own rule for which parameter VALUES
/// compare ASCII-case-insensitively.
///
/// Everything [`weight_for`] documents holds here — §12.5.1's precedence,
/// §12.4.1's absence, the three-way rule for an absent, empty or unmatching
/// field. What this adds is `fold`.
///
/// `fold(ty, subtype, name)` answers whether that parameter's value compares
/// ASCII-case-insensitively. `ty` and `subtype` are the CANDIDATE's, because a
/// parameter is registered per media type rather than globally, and because the
/// candidate is always a concrete `type/subtype` while the range it is being
/// matched against may be `*/*`. `name` is the parameter's name as written; it
/// has already been matched ASCII-case-insensitively (§5.6.6: "Parameter names
/// are case-insensitive"), so a `fold` that compares it should do the same.
///
/// It is asked ONCE per range parameter, before that parameter is matched
/// against the candidate's instances, so it must be a function of its three
/// arguments and nothing else. It is not asked at all for a range that carries
/// no parameters, nor for `q`, which §12.5.1 takes as weight first.
///
/// `fold` ADDS to RFC 9110's own rule and cannot subtract from it. `charset`
/// folds whatever `fold` answers, because §8.3.2 settles that one and it is not
/// a default a caller may disagree with; returning `false` for everything —
/// which is what [`weight_for`] passes — therefore reproduces [`weight_for`]
/// exactly.
///
/// # Why this is a hook and not a table
///
/// §8.3.1: "Parameter values might or might not be case-sensitive, depending on
/// the semantics of the parameter name." That makes the answer a property of a
/// registration, and the registry is knowledge this crate deliberately does not
/// carry. What it does carry is §12.5.1's selection — so a caller that needs
/// `eat_profile` (RFC 9782 §6.3, case-insensitive for `application/eat+cwt`)
/// compared correctly supplies that one fact rather than re-implementing the
/// ranking around it. Re-implementing it is the failure this exists to prevent:
/// a second reader of the same field, deciding differently.
///
/// ```
/// use http1_proto::media::{media_type, weight_for, weight_for_with, Weight};
///
/// let candidate = media_type(b"application/eat+cwt;eat_profile=\"tag:evidence.example,2022\"")?;
/// let field = b"application/eat+cwt;eat_profile=\"TAG:EVIDENCE.EXAMPLE,2022\";q=0, */*;q=1";
///
/// // Byte-exact: the `q=0` range misses, and the wildcard behind it answers.
/// assert_eq!(weight_for(&candidate, [field.as_slice()])?, Weight::ONE);
///
/// // With the registration's own rule, the refusal is seen.
/// let weight = weight_for_with(&candidate, [field.as_slice()], |ty, subtype, name| {
///   ty.eq_ignore_ascii_case(b"application")
///     && subtype.eq_ignore_ascii_case(b"eat+cwt")
///     && name.eq_ignore_ascii_case(b"eat_profile")
/// })?;
/// assert_eq!(weight, Weight::ZERO);
/// # Ok::<(), http1_proto::media::MediaError>(())
/// ```
///
/// # Errors
///
/// The same [`MediaError`]s [`weight_for`] produces, for the same reasons.
/// `fold` cannot fail: it answers a question about a name, and a caller with
/// nothing to say about a name says `false`.
pub fn weight_for_with<'a, I, F>(
  candidate: &MediaType<'_>,
  accept_lines: I,
  fold: F,
) -> Result<Weight, MediaError>
where
  I: IntoIterator<Item = &'a [u8]>,
  F: Fn(&[u8], &[u8], &[u8]) -> bool,
{
  let mut lines = accept_lines.into_iter();
  // §12.4.1's absence vs. §5.6.1.1's empty list (see `weight_for`'s doc for the
  // full rule): peeling the first line reads that distinction off the input
  // itself, without a second parameter to say what the input already says, and
  // the peeled line is handed straight back to the walk below.
  let Some(first) = lines.next() else {
    return Ok(Weight::ONE);
  };
  let mut best: Option<((u8, usize), Weight)> = None;
  for range in accept(core::iter::once(first).chain(lines)) {
    let range = range?;
    let Some(matched) = matched_instances(&range, candidate, &fold)? else {
      continue;
    };
    // `usize::MAX - matched` inverts "more is better" into "smaller wins"
    // without a signed key; `saturating_sub` keeps it off the lint wall.
    // `core::cmp::Reverse(matched)` is NOT the simplification it looks like:
    // it makes `best`'s annotation `Option<((u8, Reverse<usize>), Weight)>`,
    // which `clippy::type_complexity` rejects under `-D warnings`. Checked,
    // not assumed.
    //
    // The strict `<` is what answers first-in-field-order, and it does so
    // alone: a later range whose key TIES the incumbent's fails the test and
    // leaves it standing. A positional counter in the key would decide nothing
    // the strict comparison has not already decided — every tie it could break
    // is a tie `<` has kept — while carrying a way to be wrong. `enumerate`'s
    // index is a `usize` over a CALLER-supplied iterator, and a 16-bit `usize`
    // holds fewer ranges than an `Accept` field may name; overflowing it panics
    // with checks on and WRAPS without them, and a wrapped index hands a later
    // range a smaller key, which displaces the earlier one. That is a silently
    // wrong weight on exactly the release profiles the link-time no-panic proof
    // does not speak for. So there is no counter, and the comparison carries
    // the contract.
    //
    // Relaxing `<` to `<=` is what WOULD change that contract: with nothing
    // positional left in the key, every tie would go to the LAST range instead
    // of the first.
    let key = (shape_rank(&range), usize::MAX.saturating_sub(matched));
    if best.is_none_or(|(best_key, _)| key < best_key) {
      best = Some((key, range.weight()));
    }
  }
  Ok(best.map_or(Weight::ZERO, |(_, weight)| weight))
}

#[cfg(test)]
mod tests;
