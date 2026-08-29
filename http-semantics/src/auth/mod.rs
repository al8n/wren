//! RFC 9110 §11.2's two forms of authentication data: the `auth-param` every
//! authentication field in §11 is built out of, and the `token68` a credential
//! may carry in place of a whole list of them.
//!
//! ```text
//! token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
//! auth-param = token BWS "=" BWS ( token / quoted-string )
//! ```
//!
//! §11.2 says in prose which of the two follows a scheme: "either a
//! comma-separated list of parameters or a single sequence of characters
//! capable of holding base64-encoded information". Nothing in
//! `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` orders the
//! alternatives, so a recipient is the one that decides. This module writes
//! that decision down in its own `token68` reading and reports the answer at
//! [`Credential::token68`].
//!
//! Removing the `BWS` is this module's own work rather than a courtesy to the
//! sender. §5.6.3: "A recipient MUST parse for such bad whitespace and remove
//! it before interpreting the protocol element." So `realm = "x"` and
//! `realm="x"` are one parameter spelled two ways, and both are read.
//!
//! # Why this walks its own parameter grammar
//!
//! The crate already has a §5.6.6 `parameter` walker, and an `auth-param` is
//! not one of those. Two differences, either alone enough to settle it:
//!
//! - **The whitespace.** `parameter = parameter-name "=" parameter-value` admits
//!   none, and §5.6.6's closing note says so outright: "Parameters do not allow
//!   whitespace" around the `=`, bad whitespace included. `auth-param` puts
//!   `BWS` on both sides of its own.
//! - **The separator.** `parameters = *( OWS ";" OWS [ parameter ] )` hangs a
//!   member's parameters off semicolons, while §11.2 spells its lists
//!   `#auth-param` — §5.6.1's comma-separated construct.
//!
//! [`crate::grammar::parameterised_list`] would therefore refuse `realm = "x"`,
//! which §11.2 requires be accepted, and
//! `a_bws_parameter_is_what_the_semicolon_walker_refuses` is that sentence made
//! executable rather than merely written down.
//!
//! What is NOT rewritten here is anything below the parameter. An
//! `auth-param`'s value is a real §5.6.4 quoted-string, `quoted-pair` included
//! — unlike §8.8.3's `opaque-tag`, the case that forced [`crate::validator`] to
//! carry a walk of its own — so §5.6.4's scanner, §5.6.2's `token`, §5.6.3's
//! whitespace skip and [`crate::grammar::ParamValue`] are the ones this crate
//! already holds.
//!
//! # A challenge is not always one field line
//!
//! §11.3's `challenge` and §11.4's `credentials` are one production, and
//! [`Credential`] is it. What makes it more than a pair of slices is §5.2: a
//! repeated field is one value, its field line values "concatenated in order,
//! with each field line value separated by a comma", so a sender may split one
//! challenge's parameter list at any element boundary in it and the pieces
//! arrive as separate lines. [`Credential`] therefore names a region per line,
//! [`MAX_CHALLENGE_LINES`] bounds how many, and [`AuthParamIter`] reads the
//! boundary between two of them as the comma §5.2 put there.
// gate-exempt: realm = "x" — one field value shown in prose, carrying the BWS
// this module accepts; not a production of any RFC.
// gate-exempt: crate::validator — named for contrast: §8.8.3's `opaque-tag` is
// what forced a walk of its own there, and an `auth-param` value having a real
// `quoted-pair` is why none is forced here.

use crate::grammar::{
  Delim, ParamValue, QuotedScan, eq_ignore_ascii, scan_quoted, scan_quoted_after_join,
  scan_to_delim, skip_ows, token_end,
};

/// How many field lines one [`Credential`]'s body may be spread over.
///
/// RFC 9110 §5.2 makes a repeated field one value — the field line values
/// "concatenated in order, with each field line value separated by a comma" —
/// and §5.3 is what lets a sender write it that way in the first place: it
/// forbids repeating a field name "unless that field's definition allows
/// multiple field line values to be recombined as a comma-separated list",
/// which `#challenge` is. One challenge's parameter list may therefore arrive
/// split at any element boundary in it, and a reader that borrows rather than
/// joining has to name every line it landed on at once.
///
/// Sixteen, and the measurement behind the number is the storage: an entry is
/// a `&[u8]`, 16 bytes on a 64-bit target, so the array is 256 of a
/// [`Credential`]'s bytes — what a caller holding one on the stack pays. It
/// sits well above the shapes that occur: the largest challenge in wide use is
/// a Digest one at roughly nine parameters, which a sender writing one
/// parameter per line spreads over ten.
///
/// # A refusal, and not a cap
///
/// A sender that splits one challenge across seventeen field lines has written
/// something the grammar allows and this recipient will not read, and
/// [`AuthError::ChallengeSpansTooManyLines`] says so rather than reading the
/// first sixteen. A challenge is chosen by its scheme and answered with its
/// parameters, so part of one is not a smaller answer but a wrong one — the
/// trade [`MAX_TAGS`](crate::validator::MAX_TAGS) already made in this crate,
/// and named there in the same words.
///
/// # What it does not count
///
/// A field line carrying no element BYTES — only `OWS`, commas, and the empty
/// elements between them — spends no entry, so this bounds a challenge's
/// content rather than the number of lines a sender merged around it. RFC 9110
/// §5.6.1.2 opens "Empty elements do not contribute to the count of elements
/// present.", and a slot-per-spanned-line rule would count them anyway.
///
/// A parse-constant rather than a caller-set knob: the storage is in the
/// binary, so a caller cannot raise it.
pub const MAX_CHALLENGE_LINES: usize = 16;

/// Why an RFC 9110 §11 authentication field could not be read.
///
/// One type for all six of them. §11.3's `challenge` and §11.4's `credentials`
/// are the same production written twice, and §11.6.3's field is the
/// `#auth-param` list both of those end in, so the faults a recipient can meet
/// are one set rather than three — the shape [`RangeError`](crate::range::RangeError)
/// already takes across four roles.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
  /// A list element that has bytes and does not open with a `token`, so
  /// nothing in it can be the `auth-scheme` a challenge starts with.
  ///
  /// An EMPTY element is not this. RFC 9110 §5.6.1.2: "A recipient MUST parse
  /// and ignore a reasonable number of empty list elements", so an element with
  /// no bytes in it is skipped rather than reported.
  #[error("a challenge element carries no auth-scheme")]
  MissingScheme,
  /// A leading `token` that the challenge grammar cannot continue from.
  ///
  /// Two shapes, and the general one does not subsume the named one:
  ///
  /// - The token is followed by neither `1*SP` nor the end of its element.
  ///   RFC 9110 §11.3 spells the field's grammar
  ///   `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, which
  ///   admits nothing after the scheme without that `1*SP`, so an element
  ///   reading `type=1` is a scheme with an `=` glued to it, not a parameter.
  /// - The token IS followed by `1*SP`, and what fails is the section behind
  ///   it. `1*SP` is SP alone; §5.6.1.2 expands a list as
  ///   `#element => [ element ] *( OWS "," OWS [ element ] )`, which attaches
  ///   every `OWS` it has to a comma, so a HTAB standing where the first
  ///   element should be is derived by nothing.
  #[error("an auth-scheme is followed by something the challenge grammar does not admit")]
  MalformedScheme,
  /// A `token BWS "=" BWS ( token / quoted-string )` that does not complete: no
  /// leading token, no `=`, no value behind it, or a value that is neither a
  /// whole `token` nor a whole `quoted-string`.
  #[error("not a valid auth-param")]
  MalformedParameter,
  /// A §5.6.4 quoted-string still open when the LAST field line ended, so it
  /// never closed.
  ///
  /// A string open at a JOIN is not this. §5.2 makes repeated field lines one
  /// comma-joined value and a comma inside a quoted-string is data, so such a
  /// string continues onto the next line — and the pending escape goes to that
  /// comma, which is the next character of the string, rather than to the next
  /// line's first byte. A DQUOTE arriving first on that line therefore CLOSES
  /// the string; one that is data has the backslash escaping it on its own
  /// line. `the_escape_pending_at_a_join_is_spent_on_the_join_comma` is that
  /// pair, and an earlier revision of this doc had it the other way round.
  #[error("quoted-string is never closed")]
  UnterminatedQuotedString,
  /// A byte RFC 9110 §5.6.4's `qdtext` / `quoted-pair` grammar forbids appeared
  /// inside a quoted-string.
  ///
  /// Kept apart from
  /// [`UnterminatedQuotedString`](Self::UnterminatedQuotedString) because the
  /// two say different things about what may follow. An open string is the end
  /// of the input and nothing follows it; a forbidden byte leaves a walker
  /// unable to tell a separating comma from data, and every boundary behind it
  /// is a guess.
  #[error("byte forbidden inside a quoted-string")]
  InvalidQuotedString,
  /// One challenge's bytes are spread over more than [`MAX_CHALLENGE_LINES`]
  /// field lines, which is more than a borrowing, non-allocating reader can
  /// name at once.
  ///
  /// §5.3 lets a sender split a `#challenge` list at any element boundary and
  /// §5.2 joins the lines back into one value, so a challenge legally spans as
  /// many lines as the sender chose to use. This is therefore a refusal that
  /// can meet conforming input, and it is the honest answer where reading part
  /// of a challenge is not one. That constant carries the bound's own
  /// argument, including which lines it declines to count.
  #[error("a challenge spans more field lines than this recipient can name")]
  ChallengeSpansTooManyLines,
  /// RFC 9110 §11.2's MUST, reported at the second occurrence: "Authentication
  /// parameters are name/value pairs, where the name token is matched
  /// case-insensitively and each parameter name MUST only occur once per
  /// challenge."
  #[error("a parameter name occurs more than once")]
  DuplicateParameter,
  /// More parameters in one list than the names a duplicate check can hold, so
  /// the list is refused rather than left unchecked past the last one it could
  /// record.
  ///
  /// Nothing here is malformed — §11.2 bounds the list nowhere — so this names
  /// a limit of a no-alloc reader rather than a fault the sender committed.
  #[error("more parameters than this recipient can track")]
  TooManyParameters,
}

/// An [`AuthParam`]'s value crosses an RFC 9110 §5.2 field-line join, so it is
/// well formed and is not one contiguous slice.
///
/// Deliberately NOT an [`AuthError`] variant. §5.2's join is a fact about this
/// walk rather than about the field: the parameter's boundaries are still
/// correct, so are every other parameter's beside it, and so is the scheme in
/// front of them. §11.4 has a user agent choose among challenges by their
/// schemes, and failing a whole challenge over one value a caller may never
/// read would hide the scheme that choice turns on. The fact surfaces where it
/// is true instead — at [`AuthParam::value`], with [`AuthParam::name`] still
/// answering.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[error("the parameter's value spans a field-line join and is not one contiguous slice")]
pub struct ValueSpansFieldLines;

/// One RFC 9110 §11.2 `auth-param`: a name, and the value written after its
/// `=`.
///
/// # There is no `PartialEq`
///
/// This type derives neither `PartialEq` nor `Eq`, and there are three ways a
/// derive would answer `false` about bytes the specification calls the same.
/// §11.2 matches the name token case-insensitively; §5.6.6 makes a
/// `token` value and the same value written as a `quoted-string` equivalent;
/// and the value below keeps its `quoted-pair` escapes exactly as the sender
/// spelled them. A caller compares [`name`](Self::name) with
/// [`crate::grammar::eq_ignore_ascii`] and the value as [`ParamValue`]'s own
/// doc directs.
#[derive(Debug, Copy, Clone)]
pub struct AuthParam<'a> {
  /// The `token` in front of the `=`.
  name: &'a [u8],
  /// The value exactly as written — a bare `token`, or a `quoted-string` with
  /// its DQUOTEs still on — over the bytes of ONE field line.
  /// [`value`](Self::value) re-derives everything else from these, so nothing
  /// about the walk that produced them is stored beside them.
  value: &'a [u8],
}

impl<'a> AuthParam<'a> {
  /// The parameter's name, as the sender wrote it.
  ///
  /// Infallible, and it stays infallible for a parameter whose VALUE could not
  /// be handed over: what §5.2's join can break is a value's contiguity, not
  /// the boundaries either side of the name.
  ///
  /// RFC 9110 §11.2: "Authentication parameters are name/value pairs, where
  /// the name token is matched case-insensitively and each parameter name MUST
  /// only occur once per challenge." The fold is the caller's to apply, over
  /// the sender's own bytes; [`crate::grammar::eq_ignore_ascii`] is the
  /// comparison this crate offers for it.
  #[inline]
  pub const fn name(&self) -> &'a [u8] {
    self.name
  }

  /// The parameter's value, in whichever of §11.2's two alternatives the
  /// sender took.
  ///
  /// Never [`ParamValue::None`]. That variant is for the fields that define a
  /// bare-name parameter of their own — RFC 6455 §9.1 is one — and
  /// `auth-param` requires the `=` and a value behind it, so this parser
  /// produces one alternative or refuses the parameter. It is said here rather
  /// than modelled away, because [`ParamValue`] is the crate's one parameter
  /// value and keeps one shape for every field spelling a value this way.
  ///
  /// Both spellings are read, and RFC 9110 §11.2 gives the reason in its own
  /// words: "Authentication scheme definitions need to accept both notations,
  /// both for senders and recipients, to allow recipients to use generic
  /// parsing components regardless of the authentication scheme." A generic
  /// parsing component is exactly what this is, so `realm=x` is read as
  /// `realm="x"` is.
  ///
  /// # Errors
  ///
  /// [`ValueSpansFieldLines`] when the value is a quoted-string whose closing
  /// DQUOTE is not among the bytes this parameter holds. §5.2 joins repeated
  /// field lines into one value with a comma, and a comma inside a
  /// quoted-string is data, so a value may legally open on one line and close
  /// on the next — which a borrowing reader cannot hand back as one slice.
  pub fn value(&self) -> Result<ParamValue<'a>, ValueSpansFieldLines> {
    if self.value.first() != Some(&b'"') {
      return Ok(ParamValue::Token(self.value));
    }
    match scan_quoted(self.value, 1, false) {
      QuotedScan::Closed(end) if end == self.value.len() => Ok(ParamValue::Quoted(
        self.value.get(1..end.saturating_sub(1)).unwrap_or_default(),
      )),
      // The close is not among these bytes, and for a parameter this module
      // produced that leaves one shape: a value §5.2's join split over two
      // field lines, which is what this error names. The other two arms cannot
      // arrive — `auth_param` refuses a string that ends open, one carrying a
      // byte §5.6.4 forbids, and one with bytes behind its close — and are
      // answered here rather than asserted away.
      QuotedScan::Closed(_) | QuotedScan::Open { .. } | QuotedScan::Invalid => {
        Err(ValueSpansFieldLines)
      }
    }
  }
}

/// What became of a §5.6.4 quoted-string still open when the field line an
/// `auth-param` began on ran out.
///
/// The parameter's own bytes cannot answer it: RFC 9110 §5.2 joins the lines
/// of one field with a comma, that comma is data inside an open string, and
/// the close may therefore be on a line this parameter does not hold. Only the
/// walk that crossed the join knows, so it says. [`crate::grammar::ParamIter`]
/// carries the same fact for a §5.6.6 `parameter`, under its own name.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum ValueTail {
  /// Nothing was open where the line ended, or what was open never closed on
  /// any later one. Either way the parameter's bytes are all there is of it.
  Ends,
  /// It closed on a later field line, across §5.2's join — so the value is
  /// real, and is not one contiguous slice.
  Continues,
}

/// Reads one RFC 9110 §11.2 `auth-param` out of `element`.
///
/// `element` is one list element with §5.6.1's `OWS` already off both ends: the
/// whitespace that separates elements belongs to the list, and the `BWS` read
/// here belongs to the production. All of `element` must be the parameter —
/// bytes left over behind the value are a parameter that does not parse, since
/// `( token / quoted-string )` is one alternative taken whole.
///
/// `tail` says what a §5.2 join did with a quoted value this element leaves
/// open, and it is the caller's to supply for the reason [`ValueTail`] gives.
///
/// # Errors
///
/// [`AuthError::MalformedParameter`] when `element` is not
/// `token BWS "=" BWS ( token / quoted-string )`;
/// [`AuthError::UnterminatedQuotedString`] when a quoted value is still open
/// where `element` ends and `tail` says nothing closed it;
/// [`AuthError::InvalidQuotedString`] when one carries a byte §5.6.4 forbids.
fn auth_param(element: &[u8], tail: ValueTail) -> Result<AuthParam<'_>, AuthError> {
  let Some(name_end) = token_end(element, 0) else {
    return Err(AuthError::MalformedParameter);
  };
  let eq = skip_ows(element, name_end);
  if element.get(eq) != Some(&b'=') {
    return Err(AuthError::MalformedParameter);
  }
  let name = element.get(..name_end).unwrap_or_default();
  let at = skip_ows(element, eq.saturating_add(1));
  let value = element.get(at..).unwrap_or_default();
  match value.first() {
    // `auth-param` has no bare-name form: the production names a value, and
    // the `=` is not one.
    None => Err(AuthError::MalformedParameter),
    Some(&b'"') => match scan_quoted(value, 1, false) {
      QuotedScan::Closed(end) if end == value.len() => Ok(AuthParam { name, value }),
      QuotedScan::Closed(_) => Err(AuthError::MalformedParameter),
      QuotedScan::Open { .. } => match tail {
        // The string closed on a later field line, so the value exists and is
        // well formed — it is simply not one slice to hand back, which is what
        // [`AuthParam::value`] reports over these same bytes.
        ValueTail::Continues => Ok(AuthParam { name, value }),
        ValueTail::Ends => Err(AuthError::UnterminatedQuotedString),
      },
      QuotedScan::Invalid => Err(AuthError::InvalidQuotedString),
    },
    Some(_) => match token_end(value, 0) {
      Some(end) if end == value.len() => Ok(AuthParam { name, value }),
      _ => Err(AuthError::MalformedParameter),
    },
  }
}

/// RFC 9110 §11.2's `token68` alphabet: one byte of the run its production
/// opens with.
///
/// ALPHA, DIGIT and `-`, `.`, `_`, `~` are RFC 3986's 66 unreserved URI
/// characters; `+` and `/` are the two behind them, and §11.2 gives the reason
/// in as many words — the syntax is sized "so that it can hold a base64,
/// base64url (URL and filename safe alphabet), base32, or base16 (hex)
/// encoding, with or without padding, but excluding whitespace".
///
/// Neither this set nor §5.6.2's `tchar` contains the other, so a run of these
/// bytes is not thereby a `token` and a `token` is not thereby one of these:
/// `/` is here and is no `tchar`, while `!`, `#`, `$`, `%`, `&`, `'`, `*`, `^`,
/// `` ` `` and `|` are `tchar`s and are not here.
#[inline]
const fn is_token68_byte(b: u8) -> bool {
  matches!(b,
    b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// The end of the RFC 9110 §11.2 `token68` starting at `at`, or `None` when
/// there is not one.
///
/// ```text
/// token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
/// ```
///
/// Two runs, in that order, with no way back to the first: the alphabet's,
/// which `1*` gives a floor of one byte, and the `=` pad, which `*` lets be
/// empty. So `====` is not a token68 whose run happens to be empty — it is not
/// a token68 — and `a=b` ends at the `b` rather than reading it as more of the
/// alphabet.
///
/// This is the RUN, and not the reading. Whether the bytes it names are taken
/// as a `token68` at all is [`token68`]'s question, and the answer is `no` for
/// every run that stops short of its element's end.
// No dead-code allowance of its own, unlike its one caller below: the
// allowance on `token68` makes that function a root the lint walks out from,
// and this is reachable from there.
fn token68_end(value: &[u8], at: usize) -> Option<usize> {
  let mut end = at;
  while value.get(end).copied().is_some_and(is_token68_byte) {
    end = end.saturating_add(1);
  }
  if end == at {
    return None;
  }
  while value.get(end) == Some(&b'=') {
    end = end.saturating_add(1);
  }
  Some(end)
}

/// Which of RFC 9110 §11.2's two forms the credential body at `at` takes,
/// answered as the `token68` when that is the one and `None` when the bytes are
/// to be read as `#auth-param` instead.
///
/// `at` is the first byte after a scheme's `1*SP`. §11.2 puts the choice in
/// prose — the scheme is followed by "either a comma-separated list of
/// parameters or a single sequence of characters capable of holding
/// base64-encoded information" — and §11.3 puts it in the grammar as
/// `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, which §11.4
/// writes again as `credentials`. ABNF's `/` is an unordered choice, so nothing
/// there orders the two and a recipient decides.
///
/// # The rule
///
/// The `token68` is taken when its run reaches the end of its own list element:
/// the end of `value`, or the comma §5.6.1 puts between elements, with the
/// `OWS` that comma may carry skipped on the way. Anything else is the other
/// form. `dGVzdA==` and `mF_9.B5f-4.1JqM` are `token68`s by that rule, and
/// `foo=bar` is not — its pad has token bytes behind it, so the run stops
/// inside the element instead of ending it.
///
/// The end of `value` and that comma are one terminator rather than two: §5.2
/// joins repeated field lines into one value with a comma, so a run that
/// reaches the end of ONE line meets the comma next and is read the same way
/// either way.
///
/// At that comma the element is closed and nothing reopens it. A `#challenge`
/// walk tells a parameter of the CURRENT challenge from the scheme of the next
/// one by looking past the comma, and asking that question here instead could
/// change the answer only for an element both forms refuse: `Basic dGVzdA==,
/// realm=x` has no derivation either way, since `realm=x` is no challenge
/// without `1*SP` behind its token and `dGVzdA==` is no parameter. What such a
/// walk is left deciding is therefore which fault to report, never whether a
/// conforming value is read.
///
/// # Why taking it greedily steals nothing
///
/// No element this returns `Some` for is an `auth-param`, so answering the run
/// first can take no reading away from the other form. A run that reaches the
/// end of its element leaves nothing but `=` behind its first `=`, and
/// `auth-param = token BWS "=" BWS ( token / quoted-string )` needs a `token`
/// or a `quoted-string` there: `=` is neither, and the production names a value
/// rather than admitting nothing at all. `the_two_branches_are_never_both_derivable`
/// is that argument executed.
///
/// The shape worth saying it out loud for is `Scheme foo=`, which reads like a
/// parameter whose value went missing. It is not one — only the `token68`
/// derives it — so this answers `foo=` and no fault is reported. An element
/// that is NEITHER form is left to the parameter reading and refused there,
/// which is why no `MalformedToken68` exists to report.
///
/// One element is all this decides. Whether the element it ends also ends the
/// whole credential is [`Credential`]'s question, and the answer is `no` for a
/// value with more of its body behind that comma — where the other branch is
/// then the reading, and reports the fault.
fn token68(value: &[u8], at: usize) -> Option<&[u8]> {
  let end = token68_end(value, at)?;
  match value.get(skip_ows(value, end)) {
    // Nothing behind the run inside its own element, so the run IS the
    // element and the first form is the one taken.
    None | Some(&b',') => value.get(at..end),
    Some(_) => None,
  }
}

/// One RFC 9110 §11.3 `challenge`, which §11.4 spells again as `credentials`.
///
/// ```text
/// challenge   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// One production written twice, so one type reads both and each entry point
/// names which field it is for — the shape
/// [`RangeError`](crate::range::RangeError) already takes across four roles.
///
/// # Why the bytes are an array
///
/// A challenge is not always one field line. RFC 9110 §5.2 makes a repeated
/// field one value, the field line values "concatenated in order, with each
/// field line value separated by a comma", so `Basic a=1` followed by `b=2` is
/// `Basic a=1,b=2` — ONE challenge whose parameter list a sender split at an
/// element boundary. §11.6.1 says a parser has to be ready for both readings
/// of such a comma: "it might contain more than one challenge, and each
/// challenge can contain a comma-separated list of authentication parameters".
///
/// A borrowing reader cannot hand that back as one slice and this crate
/// allocates nothing, so the bytes are held as the regions they occupy on each
/// line, in wire order, with the boundary between two of them standing for the
/// comma §5.2 puts there. [`MAX_CHALLENGE_LINES`] is how many, and carries the
/// argument for the number.
///
/// A field line that carries no element BYTES spends no entry — only `OWS`,
/// commas, and the empty elements between them. The rule is written on bytes
/// rather than on elements because a line can begin no element and still be
/// load-bearing: given `Basic a="long` and `tail"`, the second line starts
/// nothing, yet it holds the DQUOTE that closes the value and every element
/// behind it. Dropping it would lose them.
///
/// # There is no `PartialEq`
///
/// Three ways a derive would answer `false` about bytes the specification
/// calls the same. §11.1 identifies a scheme with "a case-insensitive token";
/// §11.2 matches a parameter name case-insensitively; and a value written as a
/// `token` is the same value written as a `quoted-string`. A `Credential` also
/// holds the `BWS` spans no rule makes significant, and which line each region
/// came from — a property of how the value arrived rather than of what the
/// sender said. [`scheme_is`](Self::scheme_is) is the scheme comparison this
/// type offers, and [`AuthParam`] says what to do with a parameter.
#[derive(Debug, Copy, Clone)]
pub struct Credential<'a> {
  /// The `auth-scheme` token, always on the credential's first line: a `token`
  /// carries no comma, so nothing can hold a scheme open across §5.2's join.
  scheme: &'a [u8],
  /// What follows the `1*SP`, per field line.
  body: BodyLines<'a>,
  /// The `token68` reading, when that is the one §11.2's choice takes.
  token68: Option<&'a [u8]>,
}

impl<'a> Credential<'a> {
  /// Reads §11.3's production over a scheme and the body regions behind it,
  /// validating the whole of it before the value exists.
  ///
  /// Validation is eager so that [`params`](Self::params) cannot fail: a
  /// `Credential` a caller holds has already been walked to its end, which is
  /// what lets [`AuthParamIter`] yield an [`AuthParam`] rather than a
  /// `Result`. The `#challenge` walk needs that anyway — it reports one error
  /// per challenge and goes on to the next, so it has to know a challenge is
  /// good before it hands one over.
  ///
  /// # Errors
  ///
  /// Whatever the parameter list carries: [`AuthError::MalformedParameter`],
  /// [`AuthError::UnterminatedQuotedString`] or
  /// [`AuthError::InvalidQuotedString`].
  fn read(scheme: &'a [u8], body: BodyLines<'a>) -> Result<Self, AuthError> {
    // §11.2's two alternatives are exclusive, and the `token68` is taken only
    // when it is the WHOLE body. `token68` answers for one element, where a
    // comma is a terminator; a credential is complete at the end of its body,
    // so a run that ends its element with more of the body behind it has left
    // bytes `auth-scheme [ 1*SP ( token68 / #auth-param ) ]` does not derive.
    // Those bytes are then read as the other alternative and refused there,
    // which is where §11.2 has a fault to name.
    let token = match body.len {
      1 => match token68(body.line(0), 0) {
        Some(run) if skip_ows(body.line(0), run.len()) == body.line(0).len() => Some(run),
        _ => None,
      },
      _ => None,
    };
    if token.is_none() {
      let mut walk = ParamWalk::over(body);
      while let Some(param) = walk.step() {
        param?;
      }
    }
    Ok(Self {
      scheme,
      body,
      token68: token,
    })
  }

  /// The `auth-scheme` token, exactly as the sender wrote it.
  ///
  /// RFC 9110 §11.1: "It uses a case-insensitive token to identify the
  /// authentication scheme". The bytes are kept as they arrived and
  /// [`scheme_is`](Self::scheme_is) is the fold.
  #[inline]
  pub const fn scheme(&self) -> &'a [u8] {
    self.scheme
  }

  /// Whether the scheme is `name`, compared as §11.1's case-insensitive token.
  #[inline]
  pub fn scheme_is(&self, name: &str) -> bool {
    eq_ignore_ascii(self.scheme, name)
  }

  /// The RFC 9110 §11.2 `token68` this credential carries, or `None` when its
  /// body is a `#auth-param` list instead.
  ///
  /// ```text
  /// token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
  /// ```
  ///
  /// §11.2 puts the choice in prose — the scheme is followed by "either a
  /// comma-separated list of parameters or a single sequence of characters
  /// capable of holding base64-encoded information" — and the grammar's `/`
  /// does not order the two, so a recipient decides. This is `Some` exactly
  /// when the run is the whole body; [`params`](Self::params) is then empty,
  /// and the two are never both non-empty.
  #[inline]
  pub const fn token68(&self) -> Option<&'a [u8]> {
    self.token68
  }

  /// The credential's `#auth-param` list, in the order the sender wrote it.
  ///
  /// Infallible: every parameter was read once already, when this value was
  /// built. Empty when [`token68`](Self::token68) is `Some`, since §11.2's two
  /// alternatives are exclusive.
  ///
  /// The walk crosses each §5.2 field-line join, so a list split across lines
  /// yields the same parameters as the same list written on one. What a join
  /// can still take away is one VALUE's contiguity, and
  /// [`AuthParam::value`] is where that is reported.
  #[inline]
  pub const fn params(&self) -> AuthParamIter<'a> {
    AuthParamIter {
      walk: ParamWalk {
        body: self.body,
        line: 0,
        at: 0,
        done: self.token68.is_some(),
      },
    }
  }
}

/// The field-line regions one credential's body occupies, in wire order.
///
/// Each entry is already sliced to the credential's own bytes on that line —
/// the first from where the body begins, the last to where the credential ends
/// — so the walk over them needs no offsets, and the boundary between two
/// entries is the comma RFC 9110 §5.2 joins field lines with.
#[derive(Debug, Copy, Clone)]
struct BodyLines<'a> {
  /// Empty past `len`.
  lines: [&'a [u8]; MAX_CHALLENGE_LINES],
  /// How many entries the credential spent.
  len: usize,
}

impl<'a> BodyLines<'a> {
  /// An empty body: a challenge that is a bare `auth-scheme` has one.
  const fn new() -> Self {
    Self {
      lines: [&[]; MAX_CHALLENGE_LINES],
      len: 0,
    }
  }

  /// Takes what one field line contributes to this credential.
  ///
  /// A region of nothing but `OWS` and commas spends no entry, and that is
  /// checked BEFORE the bound: RFC 9110 §5.6.1.2 says "Empty elements do not
  /// contribute to the count of elements present.", so a sender that merged a
  /// run of empty lines into the middle of one challenge has not made it
  /// longer. Counting them would put a number on the empty elements the same
  /// paragraph asks a recipient to "parse and ignore".
  ///
  /// The test is on the region's BYTES. A line that begins no element still
  /// spends an entry when it carries any other byte, because those bytes may
  /// be the ones that close a quoted value — and every element behind it is
  /// reached through them.
  ///
  /// # Errors
  ///
  /// [`AuthError::ChallengeSpansTooManyLines`] past [`MAX_CHALLENGE_LINES`]
  /// entries, which is a refusal and not a cap; that constant says why.
  fn push(&mut self, region: &'a [u8]) -> Result<(), AuthError> {
    if region
      .iter()
      .all(|&byte| byte == b' ' || byte == b'\t' || byte == b',')
    {
      return Ok(());
    }
    let Some(slot) = self.lines.get_mut(self.len) else {
      return Err(AuthError::ChallengeSpansTooManyLines);
    };
    *slot = region;
    self.len = self.len.saturating_add(1);
    Ok(())
  }

  /// The region at `at`, or no bytes when there is not one.
  fn line(&self, at: usize) -> &'a [u8] {
    self.lines.get(at).copied().unwrap_or_default()
  }
}

/// The `#auth-param` list of one [`Credential`], walked across the field lines
/// it arrived on.
///
/// Yields an [`AuthParam`] rather than a `Result`, because the list was
/// validated when the [`Credential`] was built — see
/// [`Credential::params`]. A caller therefore reads a parameter list without
/// deciding what to do about a fault that has already been reported once.
#[derive(Debug, Clone)]
pub struct AuthParamIter<'a> {
  walk: ParamWalk<'a>,
}

impl<'a> Iterator for AuthParamIter<'a> {
  type Item = AuthParam<'a>;

  fn next(&mut self) -> Option<Self::Item> {
    // The `Err` this discards is unreachable over a `Credential` that exists:
    // the same walk ran to its end before that value was built, and every
    // fault it can meet was returned there instead. Dropping it ends the walk,
    // which is the answer a fault would deserve anyway — a walker that met one
    // can no longer say which of the commas behind it were separators — so
    // this is an answer rather than an assertion that it cannot happen.
    self.walk.step()?.ok()
  }
}

/// One walk of a credential's `#auth-param` list, as far as the next element.
///
/// Fallible here and infallible at [`AuthParamIter`]: the same steps read
/// twice, once to validate the credential and once to hand its parameters
/// over. Writing it once is what keeps the two readings from disagreeing.
#[derive(Debug, Clone)]
struct ParamWalk<'a> {
  body: BodyLines<'a>,
  /// Which region the cursor is in.
  line: usize,
  /// Where in that region.
  at: usize,
  done: bool,
}

impl<'a> ParamWalk<'a> {
  /// A walk of `body` from its first byte.
  const fn over(body: BodyLines<'a>) -> Self {
    Self {
      body,
      line: 0,
      at: 0,
      done: false,
    }
  }

  /// The next `auth-param`, or `None` at the end of the list.
  fn step(&mut self) -> Option<Result<AuthParam<'a>, AuthError>> {
    loop {
      if self.done {
        return None;
      }
      let line = self.body.line(self.line);
      self.at = skip_ows(line, self.at);
      match line.get(self.at) {
        // This region is spent OUTSIDE a quoted-string, so RFC 9110 §5.2's
        // join comma is the separator it looks like and the next region opens
        // a new element.
        None => {
          if self.line.saturating_add(1) >= self.body.len {
            self.done = true;
            return None;
          }
          self.line = self.line.saturating_add(1);
          self.at = 0;
        }
        // RFC 9110 §5.6.1.2: "A recipient MUST parse and ignore a reasonable
        // number of empty list elements".
        Some(&b',') => self.at = self.at.saturating_add(1),
        Some(_) => return Some(self.element()),
      }
    }
  }

  /// Takes the element at the cursor, leaving the cursor on whatever ended it
  /// — which may be in a LATER region than the element began in.
  fn element(&mut self) -> Result<AuthParam<'a>, AuthError> {
    let head = self.body.line(self.line);
    let start = self.at;
    // What the element occupies in the region it starts in — all a borrowing
    // walk can hand out — plus, when a quoted-string held it open at that
    // region's end, the escape state to continue that string with.
    let (head_end, mut open) = match scan_to_delim(head, start, b',') {
      // The element ends here, so the `OWS` RFC 9110 §5.6.1.2 hangs on the
      // comma in front of it belongs to the list rather than to the value.
      Delim::At(end) => (trim_ows_end(head, end), None),
      Delim::Open(escape) => (head.len(), Some(escape)),
      Delim::Invalid => {
        self.done = true;
        return Err(AuthError::InvalidQuotedString);
      }
    };
    self.at = head_end;

    // A quoted-string still open where a region ends does NOT end the element:
    // §5.2 joins the lines with a comma and §5.6.4 makes that comma data
    // inside the string, so the element runs on and ends wherever the string
    // closes. `scan_quoted_after_join` is this crate's one implementation of
    // that rule, and it feeds the join's comma THROUGH any pending escape
    // before the next region's first byte — so the escape is spent on the
    // comma, and a DQUOTE arriving first on that line closes the string.
    let mut tail = ValueTail::Ends;
    while let Some(escape) = open.take() {
      let next_line = self.line.saturating_add(1);
      if next_line >= self.body.len {
        // No further region, so the combined value ends inside the string.
        // Whatever closed on an earlier line does not change that: what is
        // still open is what the element ends in, and `auth_param` reports it.
        tail = ValueTail::Ends;
        break;
      }
      self.line = next_line;
      let next = self.body.line(next_line);
      self.at = next.len();
      match scan_quoted_after_join(next, escape) {
        QuotedScan::Closed(end) => {
          tail = ValueTail::Continues;
          // Past the string, the rest of this region is the element's like any
          // other, up to the comma that ends it.
          match scan_to_delim(next, end, b',') {
            Delim::At(at) => self.at = at,
            Delim::Open(escape) => open = Some(escape),
            Delim::Invalid => {
              self.done = true;
              return Err(AuthError::InvalidQuotedString);
            }
          }
        }
        QuotedScan::Open { escape } => open = Some(escape),
        QuotedScan::Invalid => {
          self.done = true;
          return Err(AuthError::InvalidQuotedString);
        }
      }
    }

    let element = head.get(start..head_end).unwrap_or_default();
    let param = auth_param(element, tail);
    if param.is_err() {
      self.done = true;
    }
    param
  }
}

/// Where `value` ends once the RFC 9110 §5.6.1.2 `OWS` behind its last byte is
/// off it.
///
/// `#element => [ element ] *( OWS "," OWS [ element ] )` puts `OWS` on BOTH
/// sides of every comma, so the whitespace in front of one belongs to the list
/// and not to the element it follows. [`auth_param`] is handed an element with
/// that whitespace already off both ends, and a walk that left the trailing
/// half on would refuse `Basic a=1 , b=2` — §11.2's
/// `( token / quoted-string )` is one alternative taken whole, and a token
/// with a space behind it is neither.
///
/// Only ever called where the element ENDED on this line. A line that runs out
/// inside a §5.6.4 quoted-string ends no element, and a space there is data the
/// string carries rather than the list's.
fn trim_ows_end(value: &[u8], end: usize) -> usize {
  let mut end = end;
  while end > 0 && matches!(value.get(end.saturating_sub(1)), Some(b' ' | b'\t')) {
    end = end.saturating_sub(1);
  }
  end
}

/// Skips RFC 9110 §11.3's `1*SP` from `at`.
///
/// SP alone, which is why §5.6.3's `OWS` skip is the wrong one here:
/// `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` writes `1*SP`
/// and no `OWS`, and the two differ by HTAB.
fn skip_sp(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while value.get(at) == Some(&b' ') {
    at = at.saturating_add(1);
  }
  at
}

/// Reads one whole credential out of the field lines carrying it, with no
/// challenge-boundary lookahead: every comma outside a quoted-string separates
/// `auth-param`s, and the whole value is one credential.
///
/// That is RFC 9110 §11.4's reading, which §11.6.2 gives `Authorization`:
/// `Authorization = credentials` is singular, so no comma in it can end a
/// credential and start another. §11.6.1's `WWW-Authenticate = #challenge` is
/// the field where a comma has two possible meanings, and telling them apart
/// is that walk's own work — it finds each challenge's regions and this reads
/// what they hold.
///
/// `lines` are the field's lines in wire order (§5.2). An EMPTY first line is
/// [`AuthError::MissingScheme`] rather than an element to skip: `credentials`
/// is one production and not a list, so a leading comma is derived by nothing.
///
/// # Errors
///
/// [`AuthError::MissingScheme`] with no leading `token`;
/// [`AuthError::MalformedScheme`] where the scheme is followed by neither
/// `1*SP` nor the end of the credential, or where `1*SP` is followed by the
/// HTAB no rule puts there; [`AuthError::ChallengeSpansTooManyLines`] past
/// [`MAX_CHALLENGE_LINES`]; and whatever the parameter list carries.
fn read_credential<'a, I>(lines: I) -> Result<Credential<'a>, AuthError>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  let mut lines = lines.into_iter();
  let head = lines.next().unwrap_or_default();
  let Some(scheme_end) = token_end(head, 0) else {
    return Err(AuthError::MissingScheme);
  };
  let scheme = head.get(..scheme_end).unwrap_or_default();
  // The byte after the scheme is decisive and is read before anything is
  // trimmed: `[ 1*SP ( token68 / #auth-param ) ]` has no other entrance, so a
  // scheme not followed by SP takes no body at all.
  let (body_at, section) = match head.get(scheme_end) {
    Some(&b' ') => {
      let at = skip_sp(head, scheme_end);
      // `1*SP` has taken every SP there was. RFC 9110 §5.6.1.2 expands a list
      // as `#element => [ element ] *( OWS "," OWS [ element ] )`, which hangs
      // every OWS it has on a comma — so a HTAB standing where the first
      // element should be is derived by nothing, and the section cannot start.
      if head.get(at) == Some(&b'\t') {
        return Err(AuthError::MalformedScheme);
      }
      (at, true)
    }
    // The scheme ends its line. It is a whole credential when it ends the
    // value too, which the loop below is what settles.
    None => (head.len(), false),
    Some(_) => return Err(AuthError::MalformedScheme),
  };
  let mut body = BodyLines::new();
  body.push(head.get(body_at..).unwrap_or_default())?;
  for line in lines {
    if !section {
      // §5.2 joins this line on with a comma, and a comma is not `1*SP`.
      return Err(AuthError::MalformedScheme);
    }
    body.push(line)?;
  }
  Credential::read(scheme, body)
}

/// Reads RFC 9110 §11.6.2's `Authorization` and §11.7.2's
/// `Proxy-Authorization` — the two authentication fields whose value is one
/// credential rather than a list of challenges.
///
/// ```text
/// Authorization = credentials
/// Proxy-Authorization = credentials
/// credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// `value` is the field's value, and §11.6.2 says what is in it: "Its value
/// consists of credentials containing the authentication information of the
/// user agent for the realm of the resource being requested." §11.7.2 says
/// the same of the proxy's field, for its own client. The reader beneath this
/// takes field LINES, because a [`Credential`] is the one production
/// [`challenges`] also finds across §5.2's joins; this field carries one
/// value, and this hands it the one it was given.
///
/// # The comma that cannot end a credential
///
/// `credentials` is singular. Neither field is a `#`-list, so there is no list
/// at the top of either value for a comma to be a separator of, and every
/// comma in one belongs to the `#auth-param` list the production ends in. The
/// question [`challenges`] has to answer at each comma — another `auth-param`
/// of the challenge already open, or the `auth-scheme` of the next one — has
/// no second reading to choose between here, and this path asks it nowhere.
///
/// A sender that writes two credentials into one value is therefore read as
/// the field is defined rather than as it was meant. `Basic x=1, Digest y=2`
/// puts `Digest y` where a parameter's name and its `=` belong, and RFC 9110
/// §11.2's `auth-param = token BWS "=" BWS ( token / quoted-string )` admits
/// only §5.6.3's `BWS` between those two, so a second token there is derived
/// by nothing. [`AuthError::MalformedParameter`] is the answer and it is the
/// right one: the field admits one credential, and reporting a malformed one
/// is not the same as silently taking the first of two.
///
/// # A trailing comma, which needs a list to be an empty element of
///
/// `Basic dGVzdA==,` is a valid `WWW-Authenticate` and is not a valid
/// `Authorization`, and the asymmetry is the grammar's rather than this
/// module's. There the comma is an empty element of `#challenge`, and RFC 9110
/// §5.6.1.2 is what skips it: "A recipient MUST parse and ignore a reasonable
/// number of empty list elements". Here `token68` has matched `dGVzdA==`, the
/// production is complete, and no list is left for an empty element to sit in
/// — nor is `,` one of the bytes `token68` is made of, so nothing derives it
/// at all. The body is then read as the other alternative and refused there,
/// which is where §11.2 has a fault to name.
///
/// Where the credential took the `#auth-param` branch instead —
/// `Newauth realm="x",` — the trailing comma IS an empty element of that list,
/// and is skipped in this singular field exactly as in the plural one.
///
/// # Errors
///
/// [`AuthError::MissingScheme`] for a value with no leading `token`;
/// [`AuthError::MalformedScheme`] where the scheme is followed by neither
/// `1*SP` nor the end of the value, or where `1*SP` is followed by the HTAB no
/// rule puts there; and whatever the body carries —
/// [`AuthError::MalformedParameter`],
/// [`AuthError::UnterminatedQuotedString`] or
/// [`AuthError::InvalidQuotedString`]. One `Result` and nothing behind it:
/// there is one credential in the field, so there is nothing to continue to.
#[inline]
pub fn credentials(value: &[u8]) -> Result<Credential<'_>, AuthError> {
  read_credential([value])
}

/// Reads RFC 9110 §11.6.1's `WWW-Authenticate` and §11.7.1's
/// `Proxy-Authenticate` — the two authentication fields whose value is a list
/// of challenges rather than one credential.
///
/// ```text
/// WWW-Authenticate = #challenge
/// Proxy-Authenticate = #challenge
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// `lines` are the field's lines in wire order. §11.6.1 says the field "can
/// occur multiple times", and §5.2 makes those lines one value with a comma at
/// each join, so a challenge and even one of its values may cross a line the
/// way [`Credential`] describes.
///
/// # The comma that ends a challenge, and the one that does not
///
/// §11.6.1 states the problem this walk exists for: the value "might contain
/// more than one challenge, and each challenge can contain a comma-separated
/// list of authentication parameters". Both levels are the same §5.6.1
/// construct, one inside the other — Appendix A writes the nesting out as
/// `challenge = auth-scheme [ 1*SP ( token68 / [ auth-param *( OWS "," OWS auth-param ) ] ) ]`
/// — so at a comma the next element is either another `auth-param` of the
/// challenge already open or the `auth-scheme` of the next one. Three rules
/// decide it, in this order, and the order is the substance.
///
/// **The SP after the scheme token is what admits a parameter section at
/// all**, and it is read before anything is trimmed. `1*SP` is the only
/// entrance the production has, so a scheme not followed by SP takes no
/// parameters and the comma behind it is a boundary: `Basic , type=1` is ONE
/// challenge with one parameter, and `Basic, type=1` is TWO, the second of
/// which nothing derives. The two values differ by one byte, and a walker that
/// split on commas with the `OWS` §5.6.1.2 hangs on them already trimmed off
/// would have destroyed the byte that separates them.
///
/// **At a comma an empty element is skipped first.** §5.6.1.2: "A recipient
/// MUST parse and ignore a reasonable number of empty list elements". The skip
/// comes before the boundary question because `Basic a=1,,b=2` is one
/// challenge with two parameters, and a rule that read the empty element as an
/// element with no leading token — and therefore as a boundary — would split
/// it.
///
/// **Then the next element's leading `token` and the first non-`BWS` byte
/// behind it decide.** `auth-param = token BWS "=" BWS ( token / quoted-string )`
/// opens with exactly those two, so an `=` there makes the element a parameter
/// of the CURRENT challenge and anything else — a different byte, the
/// element's end, or no leading token at all — makes it the scheme of the
/// next.
///
/// A challenge then closes at the end of its last VALUE, not at the end of the
/// element that question was asked about, so nothing of the next challenge is
/// ever inside the one before it.
///
/// # What follows an error
///
/// One `Result` per challenge, and the walk continues exactly while the comma
/// structure is still trustworthy. Every boundary it finds is a comma OUTSIDE
/// a quoted-string, so [`AuthError::InvalidQuotedString`] ends it: once a
/// quoted-string scan has failed, no later comma can be told from data. Every
/// other fault leaves the boundaries known and the walk goes on, because
/// §11.4 has a user agent choose among challenges by "selecting the challenge
/// with what it considers to be the most secure auth-scheme that it
/// understands" — and one unreadable challenge must not hide the readable one
/// behind it. That is a deliberate divergence from
/// [`crate::grammar::parameterised_list`], which poisons on any `Err`: a
/// parameter list is not a list a caller searches.
///
/// A failed challenge is reported ONCE. The walk then seeks the next boundary
/// over the same clean scan and does not re-read what is left of the failed
/// challenge as challenges of its own, so in `Basic a=1, =x, type=b, Newauth
/// c=1` the `type=b` is part of the failure already reported rather than a
/// second one. A `QuotedScan::Invalid` met during that seek reports
/// [`AuthError::InvalidQuotedString`] and stops the walk, exactly as it does
/// anywhere else; one that never closes consumes the rest of the input, and
/// the walk ends there.
///
/// Validation is eager — a challenge is walked to its end before it is yielded
/// — which is what lets [`Credential::params`] be infallible and what lets one
/// walk go on after a fault at all.
#[inline]
pub fn challenges<'a, I>(lines: I) -> impl Iterator<Item = Result<Credential<'a>, AuthError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  Challenges {
    lines: lines.into_iter(),
    // The walk starts with no line in hand, which is the same position as a
    // line that has been spent: the next element comes from the next one.
    line: &[],
    at: 0,
    exhausted: false,
    done: false,
    seeking: false,
  }
}

/// Where a `#challenge` walk stands once it has been moved to the next element
/// of the value RFC 9110 §5.2 joined the field lines into.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Step {
  /// The cursor is on the element's first byte.
  Element {
    /// Whether a comma — one the sender wrote, or the one §5.2 puts at a join
    /// — was crossed to reach it, which is what makes §11.6.1's boundary
    /// question apply at all. The FIRST element of a parameter section is
    /// admitted by the `1*SP` in front of it and is asked nothing.
    after_comma: bool,
  },
  /// The value has no more elements.
  End,
}

/// One challenge's body as it is collected, across the field lines RFC 9110
/// §5.2 joined into one value.
struct Section<'a> {
  /// The regions taken so far.
  body: BodyLines<'a>,
  /// Where the current line's region begins.
  start: usize,
  /// Where the challenge ends in the current line: the end of the last element
  /// read there. A region is cut HERE rather than at the line's end, because
  /// what lies behind it is the next challenge and the commas and `OWS`
  /// §5.6.1.2 puts between elements — and the boundary between two regions
  /// already stands for the one comma §5.2 put there.
  end: usize,
  /// A region did not fit in [`MAX_CHALLENGE_LINES`].
  ///
  /// Recorded rather than returned at once, because the walk still has a
  /// challenge boundary to find: stopping here would leave the cursor inside
  /// the refused challenge, and the elements behind it would then be read as
  /// challenges of their own — which is the one thing
  /// [`challenges`] promises not to do after a fault. What was collected is no
  /// longer the whole challenge, so [`AuthError::ChallengeSpansTooManyLines`]
  /// is the answer rather than whatever a partial body happens to parse as.
  overrun: bool,
}

impl<'a> Section<'a> {
  /// A body that begins at `at` on the line its scheme was read from.
  const fn opening_at(at: usize) -> Self {
    Self {
      body: BodyLines::new(),
      start: at,
      end: at,
      overrun: false,
    }
  }

  /// Takes what the line being left behind contributes, up to `end`, and opens
  /// a region at the start of the next one.
  fn spend(&mut self, line: &'a [u8], end: usize) {
    if self
      .body
      .push(line.get(self.start..end).unwrap_or_default())
      .is_err()
    {
      self.overrun = true;
    }
    self.start = 0;
    self.end = 0;
  }
}

/// The walk [`challenges`] hands out: the field lines still to come, the one
/// being walked, and where in it the next element starts.
struct Challenges<'a, I> {
  lines: I,
  line: &'a [u8],
  at: usize,
  /// `lines` answered `None` once. An `Iterator` is not required to keep doing
  /// so, and RFC 9110 §5.2's value ends at the last line either way.
  exhausted: bool,
  done: bool,
  /// A challenge failed with the cursor still inside it, so where it ends has
  /// to be found before another challenge can be read there.
  seeking: bool,
}

impl<'a, I> Iterator for Challenges<'a, I>
where
  I: Iterator<Item = &'a [u8]>,
{
  type Item = Result<Credential<'a>, AuthError>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.done {
      return None;
    }
    if self.seeking {
      self.seeking = false;
      if let Err(fault) = self.seek() {
        self.done = true;
        return Some(Err(fault));
      }
    }
    match self.open_element(None) {
      Step::End => {
        self.done = true;
        None
      }
      Step::Element { .. } => {
        let read = self.challenge();
        // Every boundary this walk finds is a comma outside a quoted-string,
        // so a scan that failed inside one leaves every comma behind it a
        // guess. Nothing further is read.
        if matches!(read, Err(AuthError::InvalidQuotedString)) {
          self.done = true;
        }
        Some(read)
      }
    }
  }
}

impl<'a, I> Challenges<'a, I>
where
  I: Iterator<Item = &'a [u8]>,
{
  /// The next field line of the value, or `None` once there are none left.
  fn next_line(&mut self) -> Option<&'a [u8]> {
    if self.exhausted {
      return None;
    }
    let next = self.lines.next();
    if next.is_none() {
      self.exhausted = true;
    }
    next
  }

  /// Moves the cursor to the first byte of the next element of the value,
  /// skipping the empty ones and crossing RFC 9110 §5.2's joins.
  ///
  /// `region` is the body being collected, when there is one; a walk that is
  /// only looking for a boundary passes `None` and takes nothing.
  fn open_element(&mut self, mut region: Option<&mut Section<'a>>) -> Step {
    let mut after_comma = false;
    loop {
      self.at = skip_ows(self.line, self.at);
      match self.line.get(self.at) {
        // RFC 9110 §5.6.1.2: "A recipient MUST parse and ignore a reasonable
        // number of empty list elements".
        Some(&b',') => {
          self.at = self.at.saturating_add(1);
          after_comma = true;
        }
        // This line is spent OUTSIDE a quoted-string, so §5.2's join comma is
        // the separator it looks like and the next line opens a new element.
        None => {
          let Some(next) = self.next_line() else {
            return Step::End;
          };
          let spent = self.line;
          self.line = next;
          self.at = 0;
          after_comma = true;
          if let Some(section) = region.as_deref_mut() {
            // The cursor moves BEFORE the region is taken, so a body that
            // cannot hold this one leaves the walk standing on the new line
            // rather than losing it with the error.
            let end = section.end;
            section.spend(spent, end);
          }
        }
        Some(_) => return Step::Element { after_comma },
      }
    }
  }

  /// Walks the element at the cursor to its end, leaving the cursor on the
  /// comma that ends it or at the end of the line the value runs out on.
  ///
  /// A field line's end does not end the element when a RFC 9110 §5.6.4
  /// quoted-string is still open there: §5.2's join comma is data inside one,
  /// so the element runs on to wherever the string closes.
  /// `scan_quoted_after_join` is this crate's one implementation of that rule
  /// and feeds the join's comma THROUGH any pending escape, so the escape is
  /// spent on the comma and a DQUOTE arriving first on the next line closes
  /// the string.
  ///
  /// # Errors
  ///
  /// [`AuthError::InvalidQuotedString`] for a byte §5.6.4 forbids inside a
  /// quoted-string — the one fault that leaves the commas behind it unreadable
  /// and so is the one this walk cannot continue past.
  fn skip_element(&mut self, mut region: Option<&mut Section<'a>>) -> Result<(), AuthError> {
    let mut open = match scan_to_delim(self.line, self.at, b',') {
      Delim::At(end) => {
        self.at = end;
        None
      }
      Delim::Open(escape) => {
        self.at = self.line.len();
        Some(escape)
      }
      Delim::Invalid => return Err(AuthError::InvalidQuotedString),
    };
    while let Some(escape) = open.take() {
      let Some(next) = self.next_line() else {
        // Nothing left to close the string on, so the element ends inside it.
        // `auth_param` reports that over the same bytes, once the whole
        // challenge has been collected.
        self.at = self.line.len();
        break;
      };
      let spent = self.line;
      self.line = next;
      self.at = next.len();
      if let Some(section) = region.as_deref_mut() {
        // The element is still open here, so ALL of the line being left is the
        // challenge's — including the bytes that begin no element of their own
        // but carry the close of this one.
        section.spend(spent, spent.len());
      }
      match scan_quoted_after_join(next, escape) {
        QuotedScan::Closed(end) => match scan_to_delim(next, end, b',') {
          Delim::At(at) => self.at = at,
          Delim::Open(escape) => open = Some(escape),
          Delim::Invalid => return Err(AuthError::InvalidQuotedString),
        },
        QuotedScan::Open { escape } => open = Some(escape),
        QuotedScan::Invalid => return Err(AuthError::InvalidQuotedString),
      }
    }
    if let Some(section) = region {
      section.end = self.at;
    }
    Ok(())
  }

  /// Whether the element at the cursor is the `auth-scheme` of the NEXT
  /// challenge rather than another `auth-param` of the one already open.
  ///
  /// RFC 9110 §11.2's `auth-param = token BWS "=" BWS ( token / quoted-string )`
  /// opens with a `token` and an `=`, with only §5.6.3's `BWS` between them, so
  /// those two are the whole question — and the `=` is looked for on THIS
  /// element's line, because a `token` carries no comma and §5.2 puts one at
  /// every join.
  ///
  /// An element with no leading token is not a parameter either, and this
  /// answers `true` for it: it opens a challenge, where
  /// [`AuthError::MissingScheme`] names what is wrong with it. Reporting a
  /// malformed parameter instead would blame a production the element was
  /// never being read by.
  fn opens_a_challenge(&self) -> bool {
    match token_end(self.line, self.at) {
      None => true,
      Some(end) => self.line.get(skip_ows(self.line, end)) != Some(&b'='),
    }
  }

  /// Reads the challenge at the cursor, leaving the cursor on the first byte
  /// of the next one — or at the end of the value.
  ///
  /// Eager: the challenge is walked to its end and every parameter in it read
  /// before the [`Credential`] exists. That is what lets
  /// [`Credential::params`] be infallible, and what lets this walk report one
  /// fault per challenge and still go on to the next.
  ///
  /// # Errors
  ///
  /// [`AuthError::MissingScheme`] and [`AuthError::MalformedScheme`] leave the
  /// cursor INSIDE the challenge that failed, so `seeking` is set and the next
  /// boundary is found before another challenge is read there. Every other
  /// fault is met with the challenge's own extent already walked, so the
  /// cursor is on that boundary already.
  fn challenge(&mut self) -> Result<Credential<'a>, AuthError> {
    let head = self.line;
    let Some(scheme_end) = token_end(head, self.at) else {
      self.seeking = true;
      return Err(AuthError::MissingScheme);
    };
    let scheme = head.get(self.at..scheme_end).unwrap_or_default();
    self.at = scheme_end;
    // The byte after the scheme is decisive and is read before anything is
    // trimmed: `[ 1*SP ( token68 / #auth-param ) ]` has no other entrance, so
    // a scheme not followed by SP takes no body at all.
    let body_at = match head.get(scheme_end) {
      Some(&b' ') => {
        let at = skip_sp(head, scheme_end);
        self.at = at;
        // `1*SP` has taken every SP there was. RFC 9110 §5.6.1.2 expands a
        // list as `#element => [ element ] *( OWS "," OWS [ element ] )`,
        // which hangs every OWS it has on a comma — so a HTAB standing where
        // the first element should be is derived by nothing.
        if head.get(at) == Some(&b'\t') {
          self.seeking = true;
          return Err(AuthError::MalformedScheme);
        }
        at
      }
      // The scheme ends its element — on a comma, or at a line end where
      // §5.2's join comma is the next character of the value. Either way it is
      // a whole challenge that took no parameters.
      None | Some(&b',') => return Credential::read(scheme, BodyLines::new()),
      Some(_) => {
        self.seeking = true;
        return Err(AuthError::MalformedScheme);
      }
    };

    let mut section = Section::opening_at(body_at);
    loop {
      match self.open_element(Some(&mut section)) {
        Step::End => break,
        Step::Element { after_comma } => {
          if after_comma && self.opens_a_challenge() {
            break;
          }
          self.skip_element(Some(&mut section))?;
        }
      }
    }
    // The challenge closes at the end of its last element, and the region it
    // is in is cut there: the bytes behind it are the next challenge's, or the
    // empty elements between the two.
    let (line, end) = (self.line, section.end);
    section.spend(line, end);
    if section.overrun {
      return Err(AuthError::ChallengeSpansTooManyLines);
    }
    Credential::read(scheme, section.body)
  }

  /// Finds where the challenge that just failed ends, without reading what is
  /// left of it as challenges of its own.
  ///
  /// The same boundary rule as the walk itself, run over a scan that collects
  /// nothing: at each comma the next element's leading `token` and the byte
  /// behind it say whether it still belongs to the failed challenge. RFC
  /// 9110 §11.6.1's ambiguity is resolved once per challenge, so `type=b` in
  /// `Basic a=1, =x, type=b, Newauth c=1` is part of the fault already
  /// reported rather than a second one.
  ///
  /// # Errors
  ///
  /// [`AuthError::InvalidQuotedString`], which makes the commas behind it
  /// unreadable during a seek exactly as it does anywhere else. A
  /// quoted-string that never closes is the benign case and no error at all:
  /// it consumes the rest of the input, and the walk ends where the value
  /// does.
  fn seek(&mut self) -> Result<(), AuthError> {
    loop {
      self.skip_element(None)?;
      match self.open_element(None) {
        Step::End => return Ok(()),
        // A comma was crossed by construction: the element just skipped ended
        // on one, or at the line end RFC 9110 §5.2 puts one at.
        Step::Element { .. } => {
          if self.opens_a_challenge() {
            return Ok(());
          }
        }
      }
    }
  }
}

#[cfg(test)]
mod tests;
