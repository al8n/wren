//! The RFC 9110 §8.3.1 media type and §12.5.1 `Accept` range, over the §5.6.6
//! parameter grammar the crate already walks — and RFC 2045 §5.1's media type,
//! which is a different grammar for the same value.
//!
//! Two entry points share one walk: [`media_type`] reads a single
//! `Content-Type` value and [`accept`] walks an `Accept` field's lines.
//! [`weight_for`] composes §12.5.1's precedence with §12.4.2's weight, which is
//! the one derivation those sections settle; choosing a representation from the
//! result is the caller's, and §12.1 says a user agent "cannot rely on
//! proactive negotiation preferences being consistently honored".
//!
//! A third entry point, `mime_content_type`, is crate-internal and answers
//! RFC 2045 §5.1's `content` for `range::multipart` — the one place in this
//! crate that is inside a MIME body part. It lives HERE, and not there, because
//! reading a media type is this module's work whichever grammar spells it, and
//! because the two walks belong in one file for anyone comparing them. The
//! dependency runs one way: `range::multipart` names this module, and nothing
//! here names `range`.
//!
//! # The MIME grammar and the HTTP grammar disagree, and here is where
//!
//! A body part's `Content-Type` is not an HTTP field. RFC 9110 §14.6 hands the
//! framing of a `multipart/byteranges` body to RFC 2046, RFC 2046 §5.1 gives a
//! body part its own header fields, and RFC 2045 §5.1 gives that field its own
//! grammar — RFC 822's structured-field lexing over RFC 2045's `token` — which
//! is not RFC 9110 §8.3.1's. So `mime_content_type` reads the field in the
//! grammar of the place the field is, and [`media_type`] stays exactly as
//! strict as §8.3.1 makes it, for the HTTP field sections it is for.
//!
//! The two are not one grammar with a lenience bolted on. **Do not try to unify
//! them**: each row below is a value one accepts and the other must not.
//!
//! | value | RFC 2045 §5.1, a body part | RFC 9110 §8.3.1 + §5.6.6, a field section |
//! | --- | --- | --- |
//! | `text / plain` | a media type: RFC 5322 §3.2.2 puts white space between lexical tokens | not one: `text ` is no `token` |
//! | `text (c) /plain` | a media type: §5.1 admits RFC 822 comments | not one: §8.3.1 has no comment production |
//! | `text/plain; charset = us-ascii` | one parameter: the `=` is a symbol like any other | no parameter: `charset ` is no `parameter-name` |
//! | `text/plain; charset=us-ascii (c)` | value `us-ascii`, the comment discarded | value `us-ascii (c)`, which is no `token` — refused |
//! | `application/x-{foo}` | a media type: `{` and `}` are no `tspecials` | not one: neither is a `tchar` |
//! | `text/plain;charset="a<DEL>b"` | a media type: DEL is RFC 822 `qtext` | not one: DEL is no §5.6.4 `qdtext` |
//! | `text/plain;` | refused: `*(";" parameter)` brackets nothing | a media type with no parameters: `*( OWS ";" OWS [ parameter ] )` |
//! | `x-/plain`, `text/x-` | refused: `x-` is a `token` and is no `x-token`, so it names no `type` and no `subtype` | media types: §8.3.1 spells both halves `token` and has no `extension-token` |
//! | `text/plain, text/html` | refused: `,` is a `tspecials` and `content` holds no list | refused: §8.3 makes `Content-Type` a singleton |
//!
//! The first four rows are white space and comments around a SYMBOL — the `/`,
//! the `;`, the `=`. `;` is the narrow one of those three: §5.6.6 already puts
//! `OWS` around it, so only a COMMENT parts the two there, while `/` and `=`
//! admit no HTTP whitespace at all. The fifth and sixth rows are the two
//! ALPHABETS, and each is a set difference in its own lexical class: RFC 2045's
//! `token` is `%x21-7E` minus fifteen `tspecials` and §5.6.2's `tchar` is that
//! set minus `{` and `}`, while RFC 822's `qtext` is `CHAR` minus three
//! characters and §5.6.4's `qdtext` also excludes the CTLs and DEL. Those two
//! quoted-string classes are not orderable in either direction, since `qdtext`
//! admits the `obs-text` `CHAR` has no room for. The seventh and eighth rows
//! are the two where HTTP admits what MIME refuses, which is what keeps either
//! grammar from containing the other: HTTP's parameter carries a bracket
//! RFC 2045 does not write, and §8.3.1 spells `type` and `subtype` as a bare
//! `token` each, where §5.1 builds a `type` out of `discrete-type /
//! composite-type` and a `subtype` out of `extension-token / iana-token` —
//! productions whose `X-` half is `x-token`, which a bare `x-` is not. That
//! eighth row is why [`encode_part_header`](crate::range::multipart::encode_part_header)
//! refuses a [`MediaType`] that [`media_type`] returned: the writer puts the
//! value where RFC 2045 governs. The last row is a value both refuse, on two
//! different sentences.
//!
//! Both parsers produce one [`MediaType`], so a caller meets one type and
//! [`encode_part_header`](crate::range::multipart::encode_part_header) takes one
//! argument. What that writer spells back is §8.3.1's preferred tight form
//! either way — `text / plain` re-frames as `text/plain` — which is the same
//! media type and not the same bytes, exactly as a parameter's `OWS` has always
//! been.

use crate::grammar::{
  ListError, ListMember, ParamIter, ParamSyntax, ParamValue, ValuelessParameter, has_bare_comma,
  is_token, parameterised_list_with,
};

/// The `parameter` production RFC 9110 §8.3.1's `media-type` carries.
///
/// `media-type = type "/" subtype parameters`, and those `parameters` are
/// §5.6.6's, which admits no whitespace around a `parameter`'s `=` —
/// "Parameters do not allow whitespace (not even "bad" whitespace) around the
/// "=" character." §12.5.1's `media-range` inherits the same ones, so both
/// entry points in this module walk with this and neither may widen it, for two
/// reasons rather than one.
///
/// Reading §10.1.4's `BWS` here would admit a quoted-string where §5.6.6 puts
/// none, and a comma inside it would stop being the §5.6.1.2 separator
/// `Content-Type`'s singleton rule is asked about.
///
/// And §5.6.6's parameter slot is OPTIONAL where §10.1.4's is not —
/// `parameters = *( OWS ";" OWS [ parameter ] )` against
/// `transfer-coding = token *( OWS ";" OWS transfer-parameter )` — so widening
/// would refuse `text/plain;`, `text/plain;;charset=utf-8` and
/// `text/plain;charset=utf-8;`, each of which RFC 9110 §8.3.1 admits by
/// inheriting those brackets.
const MEDIA_PARAMETERS: ParamSyntax = ParamSyntax::Parameter;

/// What a media parameter with no value is, declared to the walk rather than
/// applied to what the walk hands back.
///
/// `media-type = type "/" subtype parameters` (RFC 9110 §8.3.1) puts no grammar
/// of this module's own over §5.6.6's `parameter`, and that production requires
/// its `=` — `parameter = parameter-name "=" parameter-value`. So `text/html;charset`
/// is no media type, and the two entry points here have always said so.
///
/// Saying it HERE rather than over the pairs the walk yields is what makes it
/// true at every entrance. A parameter that stands behind an RFC 9110 §5.2
/// field-line join is not one of those pairs — it lies on a line the member
/// hands no slice of — so a refusal made out here would hold for
/// `text/plain;charset` and not for `text/plain;p="a` + `";charset`, which is
/// §5.2's join turned into a way past §5.6.6's `=`.
const MEDIA_VALUELESS: ValuelessParameter = ValuelessParameter::Refused;

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
  /// RFC 9110 §5.6.6's `parameter` grammar requires the `=`; the walker admits
  /// a bare name only for fields that define their own parameter grammar — RFC
  /// 6455 §9.1's extension parameters are one such field. A media type defines
  /// no such grammar, and this module says so to the walker once
  /// (`MEDIA_VALUELESS`) rather than refusing the shapes it hands back. That is
  /// what makes the refusal reach a parameter standing behind an RFC 9110 §5.2
  /// field-line join, which this module is never shown. It arrives as
  /// [`ListError::MissingParameterValue`] and is lifted out of
  /// [`Parameters`](Self::Parameters) here, so that one condition keeps one
  /// representation — the same rule that lifts
  /// [`ValueSpansFieldLines`](Self::ValueSpansFieldLines).
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
      // The refusal `MEDIA_VALUELESS` asked the walk for, named in this
      // module's own words on the way back out.
      ListError::MissingParameterValue => Self::ValuelessParameter,
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
/// place of the `token` a transfer-coding list uses. The other half of what
/// they hand it is [`MEDIA_PARAMETERS`], since a field picks its name grammar
/// and its `parameter` grammar separately.
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

/// One media type: RFC 9110 §8.3.1's `type "/" subtype parameters`, or
/// RFC 2045 §5.1's `type "/" subtype *(";" parameter)`.
///
/// Borrows the value it was parsed from; nothing is copied.
///
/// # Two grammars, one type
///
/// [`media_type`] is §8.3.1's parser, for the grammar of an HTTP field section.
/// RFC 2045 §5.1's is the grammar of a MIME body part's header block, and
/// `mime_content_type` beside it in this module is that one — a different
/// grammar for the same value, tabulated row by row in this module's own
/// summary. Both produce THIS type, so a caller holding a `Content-Type` meets
/// one thing whichever context it came out of, and
/// [`encode_part_header`](crate::range::multipart::encode_part_header) takes one
/// argument rather than two.
///
/// What travels with the value is which grammar its PARAMETERS are spelled in,
/// because the two disagree about the bytes between them —
/// `text/plain; charset = us-ascii` carries one parameter in MIME's grammar and
/// none at all in HTTP's. [`params`](Self::params) walks each in its own grammar
/// and yields the same pairs, so nothing downstream of it has to know which it
/// is holding.
///
/// The accessors below are stated in §8.3.1's words because the two grammars
/// agree on everything they say. Where the grammars differ is what each admits
/// INSIDE a lexical token — `application/x-{foo}` is a MIME media type and is
/// not an HTTP one, and `charset="a<DEL>b"` is a MIME parameter and is not an
/// HTTP one — so a value read in the MIME context can hold a byte §5.6.2's
/// `tchar` or §5.6.4's `qdtext` does not, and putting one into an HTTP field
/// section is the caller's decision rather than this type's promise. It runs the
/// other way once: `obs-text` is `qdtext` and is no RFC 822 `CHAR`.
///
/// # There is no `PartialEq`, and there is no right one
///
/// This type deliberately derives neither `PartialEq` nor `Eq`. A derive over
/// the bytes as written answers a question media-type equivalence does not
/// ask. Three probes, all of them `false` under such a derive and all of them
/// one media type:
///
/// - `media_type(b"text/plain")` against `media_type(b"TEXT/PLAIN")`. §8.3.1:
///   "The type and subtype tokens are case-insensitive."
/// - `media_type(b"text/plain;charset=utf-8")` against
///   `media_type(b"text/plain; charset=utf-8")`, whose only difference is the
///   `OWS` §5.6.6 puts there.
/// - A value from [`media_type`] against one `range::multipart` read out of a
///   body part, since the parameter section carries the grammar it is spelled
///   in and the two spellings are two variants.
///
/// The first two hold with or without the third; the MIME parser only adds a
/// second route to the same wrong answer. The precedent for removing rather
/// than repairing is in this crate and it is the same reasoning:
/// [`ContentRange`](crate::range::ContentRange) derives no `PartialEq` either,
/// because its `range-unit` is stored as the sender wrote it and §14.1's "All
/// range unit names are case-insensitive" makes a derived equality contradict
/// the section the value comes from.
///
/// **And a semantic `PartialEq` is not the fix.** Media-type equivalence needs
/// answers this crate does not have — whether parameter order matters, what a
/// duplicate parameter means, which parameter values are case-sensitive — and
/// inventing them would be a contract nobody asked for. The specific clause is
/// §5.6.6's rather than §8.3.1's, and it settles only the first half: "Parameter
/// names are case-insensitive.  Parameter values might or might not be
/// case-sensitive, depending on the semantics of the parameter name." So the
/// values are the parameter's own question and the ORDER is nobody's. A caller
/// comparing two media types compares [`ty`](Self::ty) and
/// [`subtype`](Self::subtype) with
/// [`eq_ignore_ascii`](crate::grammar::eq_ignore_ascii) or
/// `str::eq_ignore_ascii_case`, and walks [`params`](Self::params) itself under
/// whatever rule its own field defines. That is a question a caller can state.
#[derive(Debug, Copy, Clone)]
pub struct MediaType<'a> {
  ty: &'a [u8],
  subtype: &'a [u8],
  params: MediaParams<'a>,
}

/// A media type's parameter section, kept with the grammar it is spelled in.
///
/// Not a `&[u8]` and a flag: the HTTP arm carries a whole [`ListMember`],
/// because that is what §5.6.6's walk needs to resume — the parameters' bytes
/// and what became of a quoted-string still open when the member's first field
/// line ended. The MIME arm needs neither, since RFC 2045 §5.1's `content` is
/// one field's value and this crate refuses a body part's folded field before a
/// media type is read out of it.
///
/// No `PartialEq`: this discriminant records which grammar spelled the
/// parameters, so a derive here makes a §8.3.1-parsed `text/plain` compare
/// unequal to a §5.1-parsed one.
#[derive(Debug, Copy, Clone)]
enum MediaParams<'a> {
  /// RFC 9110 §5.6.6's `*( OWS ";" OWS [ parameter ] )`, as [`media_type`] read
  /// it.
  Http(ListMember<'a>),
  /// RFC 2045 §5.1's `*(";" parameter)` under RFC 822's structured-field
  /// lexing, as `mime_content_type` read it: everything the value had left
  /// after its `subtype`.
  Mime(&'a [u8]),
}

/// The iterator [`MediaType::params`] hands back: one media type's parameters,
/// in wire order, whichever of the two grammars the value was read in.
///
/// One `Item` for both, because the pairs are the same pairs — RFC 2045 §5.1's
/// `parameter := attribute "=" value` and RFC 9110 §5.6.6's
/// `parameter = parameter-name "=" parameter-value` name a token and either a
/// token or a quoted-string, and only what may sit BETWEEN those pieces differs.
#[derive(Debug, Clone)]
pub struct MediaTypeParams<'a>(MediaTypeParamsInner<'a>);

/// Which walk a [`MediaTypeParams`] is driving.
#[derive(Debug, Clone)]
enum MediaTypeParamsInner<'a> {
  /// The crate's RFC 9110 §5.6.6 walk.
  Http(ParamIter<'a>),
  /// This module's own RFC 2045 §5.1 walk.
  Mime(MimeParams<'a>),
}

impl<'a> Iterator for MediaTypeParams<'a> {
  type Item = Result<(&'a [u8], ParamValue<'a>), ListError>;

  #[inline]
  fn next(&mut self) -> Option<Self::Item> {
    match &mut self.0 {
      MediaTypeParamsInner::Http(params) => params.next(),
      MediaTypeParamsInner::Mime(params) => params.next(),
    }
  }
}

impl<'a> MediaType<'a> {
  /// The `type` token.
  ///
  /// RFC 9110 §8.3.1: "The type and subtype tokens are case-insensitive." This
  /// hands over the bytes as written; the comparison is the caller's. RFC 2045
  /// §5.1 says the same of the MIME grammar's two tokens: "The type, subtype,
  /// and parameter names are not case sensitive.  For example, TEXT, Text, and
  /// TeXt are all equivalent top-level media types."
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
  ///
  /// Walked in the grammar the value was read in, which is the whole of what
  /// this type stores alongside its two tokens; the pairs are the same pairs
  /// either way. See [`MediaTypeParams`] for the two walks.
  #[inline]
  pub const fn params(&self) -> MediaTypeParams<'a> {
    MediaTypeParams(match self.params {
      MediaParams::Http(member) => MediaTypeParamsInner::Http(member.params()),
      MediaParams::Mime(params) => MediaTypeParamsInner::Mime(MimeParams::new(params)),
    })
  }

  /// Builds a media type out of pieces RFC 2045 §5.1's parser has already
  /// established.
  ///
  /// **Crate-internal, and deliberately not a second public media-type type.**
  /// §5.1's `content` is a different grammar from §8.3.1's `media-type`, but the
  /// VALUE it produces is a media type like any other — a type, a subtype and a
  /// list of parameters — so a caller reading a body part meets the same type it
  /// meets reading an HTTP field, and one writer can spell either back.
  ///
  /// `ty` and `subtype` must each be a §5.1 `token` and `params` must be that
  /// grammar's parameter section, already walked. Nothing is re-checked here:
  /// [`params`](Self::params) will walk `params` again in §5.1's grammar, and
  /// `mime_content_type` — the one caller, further down this file — is what has
  /// established they agree.
  #[inline]
  pub(crate) const fn from_mime_parts(ty: &'a [u8], subtype: &'a [u8], params: &'a [u8]) -> Self {
    Self {
      ty,
      subtype,
      params: MediaParams::Mime(params),
    }
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
  if has_bare_comma(value, MEDIA_PARAMETERS, MEDIA_VALUELESS) {
    return Err(MediaError::NotASingleton);
  }
  let member = parameterised_list_with([value], is_media_name, MEDIA_PARAMETERS, MEDIA_VALUELESS)
    .next()
    .ok_or(MediaError::NotAMediaType)?
    .map_err(|e| match e {
      ListError::NotAToken => MediaError::NotAMediaType,
      other => MediaError::from(other),
    })?;
  let (ty, subtype) = split_solidus(member.name()).ok_or(MediaError::NotAMediaType)?;
  // Every parameter is read here rather than left to `MediaType::params`,
  // because this entry point promises a value that parsed. The bare-name
  // refusal among them is `MEDIA_VALUELESS`, declared once and applied by the
  // walk at every entrance it has.
  for param in member.params() {
    param.map_err(MediaError::from)?;
  }
  Ok(MediaType {
    ty,
    subtype,
    params: MediaParams::Http(member),
  })
}

/// RFC 2045 §5.1's `Content-Type` value, read where THAT grammar is the one in
/// force.
///
/// ```text
/// content := "Content-Type" ":" type "/" subtype
///            *(";" parameter)
///
/// parameter := attribute "=" value
///
/// attribute := token
///
/// value := token / quoted-string
/// ```
///
/// The field name and its colon belong to whoever split the header block: the
/// `multipart` reader under `range`, which is this function's one caller. What
/// stands here is the value behind that colon, on the one line RFC 2046 §5.1.1
/// leaves it on.
///
/// # Which context this is, and why one parser cannot be both
///
/// A body part's header block is not an HTTP field section. RFC 9110 §14.6
/// frames a `multipart/byteranges` body by RFC 2046, RFC 2046 §5.1 gives a body
/// part its own header fields, and RFC 2045 §1 says what those fields inherit:
/// "All of the header fields defined in this document are subject to the general
/// syntactic rules for header fields specified in RFC 822.  In particular, all
/// of these header fields except for Content-Disposition can include RFC 822
/// comments, which have no semantic content and should be ignored during MIME
/// processing." §5.1 says the same about this field in particular — "In
/// addition, comments are allowed in accordance with RFC 822 rules for
/// structured header fields." — and prints the case, calling two spellings
/// "completely equivalent":
///
/// ```text
/// Content-type: text/plain; charset=us-ascii (Plain text)
///
/// Content-type: text/plain; charset="us-ascii"
/// ```
///
/// This module's own summary tabulates every place the two grammars part
/// company. [`media_type`] stays exactly as strict as §8.3.1 makes it, because
/// an HTTP field section is where that strictness is right; the difference lives
/// in [`MimeParams`] and the lexical predicates below it.
///
/// # Every span is still borrowed
///
/// RFC 5322 §3.2.2: "Runs of FWS, comment, or CFWS that occur between lexical
/// tokens in a structured header field are semantically interpreted as a single
/// space character." BETWEEN lexical tokens — so white space and comments never
/// sit inside one, every token and every `quoted-string` this reads is a
/// contiguous run of the caller's own bytes, and [`MediaType`] borrows each the
/// way an HTTP-parsed one does. A no-alloc reader can read this grammar whole.
///
/// That is why the answer for `text/plain; (c) charset=us-ascii` is a media type
/// rather than a refusal for a value in two pieces: the comment there is in a
/// comment position, so nothing has to be joined. RFC 822's line fold really is
/// two spans, and the caller refuses one before a value reaches this; and
/// `charset=a(c)b` never was one, because RFC 5322 §3.2.3's
/// `atom = [CFWS] 1*atext [CFWS]` puts the comment position outside the token
/// and never inside it.
///
/// # What the caller must have established
///
/// **That `value` is the body of one RFC 822 `field`**, which is to say that it
/// carries no bare CR and no bare LF. The three productions this walk is built
/// on do not settle that between them: `qtext` and `ctext` exclude the CR by
/// name, but the LF is a `CHAR` neither production mentions, so this walk admits
/// `charset="a<LF>b"` and would hand the LF back inside a parameter's span. What
/// forbids it is the grammar one level up —
/// `field = field-name ":" [ field-body ] CRLF`, whose
/// `field-body = field-body-contents [CRLF LWSP-char field-body]` admits a
/// line-break octet only as the CRLF of a fold — and the caller is where that
/// grammar is: `range::multipart` splits a body part's header block at every
/// CRLF, refuses the fold, and refuses any line with one of those two octets
/// left inside it.
///
/// The rule has ONE entrance today. A second caller that skipped it would put a
/// line break into a borrowed span, and
/// [`encode_part_header`](crate::range::multipart::encode_part_header) copies a
/// quoted interior into a body part's header block verbatim, checking only that
/// it is US-ASCII — which a CR and an LF both are.
///
/// # `None`, and only `None`
///
/// Every fault this grammar has is one refusal to its one caller, so an error
/// type here would be a distinction nothing reads: a value that is not §5.1's
/// `content` — no `/`, an empty `type` or `subtype` (§5.1: "Note also that a
/// subtype specification is MANDATORY -- it may not be omitted from a
/// Content-Type header field.  As such, there are no default subtypes."), a byte
/// outside §5.1's `token` where a token belongs, a `type` or a `subtype` in the
/// `X-` namespace that is not an `x-token` ([`keeps_x_token`], which
/// [`mime_type_and_subtype`] holds each half to), a `;` with no `parameter`
/// behind it, a parameter with no `=` or no value, a comment or a
/// `quoted-string` the value ends inside of, or anything at all where only a `;`
/// or the end of the value may be — every one of them reaches
/// `range::multipart` as the same `None`, and that module turns it into the one
/// [`RangeError::MalformedMultipart`](crate::range::RangeError::MalformedMultipart)
/// its `# Errors` promises.
pub(crate) fn mime_content_type(value: &[u8]) -> Option<MediaType<'_>> {
  let (ty, subtype, params) = mime_type_and_subtype(value)?;
  // Walked HERE, before the value exists, so that every parameter has been read
  // by the time a caller can ask for one. `MimeParams` is the only walk of this
  // grammar, so what it refuses is what this refuses and there is no second
  // opinion to drift from; and because it has already refused everything it can,
  // a re-walk through `MediaType::params` yields `Ok` for every parameter of
  // every value this function returns.
  for param in MimeParams::new(params) {
    if param.is_err() {
      return None;
    }
  }
  Some(MediaType::from_mime_parts(ty, subtype, params))
}

/// `[CFWS] type [CFWS] "/" [CFWS] subtype`, and what the value has left behind
/// it.
///
/// The `[CFWS]`s are RFC 822's, which RFC 5322 §3.2.2 restates as
/// `CFWS = (1*([FWS] comment) [FWS]) / FWS` and admits "between many elements in
/// header field bodies". The `/` is a delimiter rather than a token byte because
/// RFC 2045 §5.1 put it there: "Note that the definition of "tspecials" is the
/// same as the RFC 822 definition of "specials" with the addition of the three
/// characters "/", "?", and "=", and the removal of "."." A `token` therefore
/// stops at a `/` on its own, and [`mime_token`] needs no special case for it.
///
/// `None` for anything that is not this shape, which [`mime_content_type`]
/// reports as one refusal — the pieces are not separable faults, since a value
/// with no `/` in it has no `type` either.
///
/// # A `token` in each position is the alphabet and not the production
///
/// RFC 2045 §5.1 does not spell either half as `token`. Outside its seven
/// literals a `type` is an `extension-token` and a `subtype` is an
/// `extension-token` or an `iana-token`, and both of those offer `x-token`,
/// whose tail §5.1 requires to be a `token` and therefore non-empty. So `x-` is
/// a `token` in both positions and is a `type` in neither and a `subtype` in
/// neither — [`keeps_x_token`] is that rule, and it is the same call §6.1's
/// `mechanism` reader makes about the same namespace.
///
/// Reading it here rather than at [`mime_content_type`] keeps the whole of
/// §5.1's `type "/" subtype` in one function: a caller of this gets the two
/// spans only when both are what the grammar says they are. Everything else is
/// out of reach of bytes — an unregistered `example/foo` is a well-formed
/// `ietf-token` as far as anything here can see, and `range::multipart`'s
/// `TopLevelType` is where that undecidability is reported rather than refused.
fn mime_type_and_subtype(value: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
  let (ty, rest) = mime_token(skip_cfws(value)?)?;
  let rest = skip_cfws(rest)?.strip_prefix(b"/")?;
  let (subtype, rest) = mime_token(skip_cfws(rest)?)?;
  (keeps_x_token(ty) && keeps_x_token(subtype)).then_some((ty, subtype, rest))
}

/// Walks RFC 2045 §5.1's `*(";" parameter)` under RFC 822's lexing, one
/// parameter at a time.
///
/// ```text
/// parameter := attribute "=" value
///
/// attribute := token
///
/// value := token / quoted-string
/// ```
///
/// with `[CFWS]` admitted around each of the three symbols — the `;`, the `=`,
/// and the DQUOTEs a `quoted-string` is delimited by — on RFC 5322 §3.2.2's
/// statement that runs of comments and white space "occur between lexical
/// tokens in a structured header field".
///
/// # Two things this refuses that RFC 9110 §5.6.6's walk admits
///
/// **An empty element.** §5.6.6 spells `parameters = *( OWS ";" OWS [ parameter
/// ] )` with the parameter BRACKETED, so `text/plain;` is one media type and no
/// parameters there. RFC 2045 §5.1's `*(";" parameter)` brackets nothing, so a
/// `;` with nothing behind it is not this grammar and the value is refused.
///
/// **A parameter with no `=`.** §5.1's `parameter := attribute "=" value` has no
/// alternative without one, so [`ParamValue::None`] is a value this walk never
/// yields. [`media_type`] reaches the same answer for its own grammar by a
/// different route — the walker admits the bare-name form for the fields that
/// define it, and `MEDIA_VALUELESS` tells it that this module is not one of
/// them.
///
/// # Its `Err` is a fault this crate refuses whole
///
/// The item type is [`ListError`]'s so that one iterator can carry either
/// grammar's parameters to [`MediaType::params`], and that vocabulary is
/// RFC 9110's: `UnterminatedQuotedString` and `InvalidQuotedByte` name exactly
/// what happened, and every structural refusal of MIME's own — a missing `;`, a
/// missing `=`, an empty element, a comment the value ends inside of — is
/// reported as [`ListError::NotAToken`], the walker's nearest word for *what
/// stands here is not the token that belongs here*.
///
/// The imprecision does not reach a caller. [`mime_content_type`] is the one
/// constructor of a MIME-parsed [`MediaType`], it drives this walk to the end
/// before returning, and it turns any `Err` into a refusal of the whole value —
/// so what a caller sees is that refusal, and a re-walk of a value that survived
/// it yields only `Ok`.
#[derive(Debug, Clone)]
struct MimeParams<'a> {
  /// What is left of the value: `*( [CFWS] ";" [CFWS] parameter ) [CFWS]`.
  rest: &'a [u8],
  /// Set by the walk that ended it, whether it ended at the value's end or at a
  /// fault — nothing behind a `;` this walk could not read is a parameter it
  /// could.
  done: bool,
}

impl<'a> MimeParams<'a> {
  /// Opens a walk over everything a value had left after its `subtype`.
  #[inline]
  const fn new(params: &'a [u8]) -> Self {
    Self {
      rest: params,
      done: false,
    }
  }

  /// One `[CFWS] ";" [CFWS] parameter`, and what is left behind it.
  ///
  /// `Ok(None)` is the end of the value — `[CFWS]` and then nothing — which is
  /// §5.1's `*( … )` matching zero more times.
  fn step(rest: &'a [u8]) -> Result<Option<MimeParam<'a>>, ListError> {
    let rest = skip_cfws(rest).ok_or(ListError::NotAToken)?;
    let Some(rest) = rest.strip_prefix(b";") else {
      // The repetition is over. Either the value ended, or a byte stands where
      // only a `;` or the end may — `text/plain x`, where `x` is a second token
      // §5.1's `content` has no room for.
      return if rest.is_empty() {
        Ok(None)
      } else {
        Err(ListError::NotAToken)
      };
    };
    let rest = skip_cfws(rest).ok_or(ListError::NotAToken)?;
    // `attribute := token`, and a `token` is `1*<…>`: there is no empty
    // parameter to skip past here, which is the whole of what `text/plain;`
    // fails.
    let (name, rest) = mime_token(rest).ok_or(ListError::NotAToken)?;
    let rest = skip_cfws(rest).ok_or(ListError::NotAToken)?;
    let rest = rest.strip_prefix(b"=").ok_or(ListError::NotAToken)?;
    let rest = skip_cfws(rest).ok_or(ListError::NotAToken)?;
    // `value := token / quoted-string`, and the DQUOTE is what tells them apart:
    // §5.1's `tspecials` holds it, so no `token` can begin with one.
    match rest.first() {
      Some(b'"') => {
        let (interior, tail) = mime_quoted_string(rest)?;
        Ok(Some(MimeParam {
          name,
          value: ParamValue::Quoted(interior),
          rest: tail,
        }))
      }
      _ => {
        let (token, tail) = mime_token(rest).ok_or(ListError::NotAToken)?;
        Ok(Some(MimeParam {
          name,
          value: ParamValue::Token(token),
          rest: tail,
        }))
      }
    }
  }
}

/// One RFC 2045 §5.1 `parameter`, and where the walk resumes behind it.
///
/// A struct rather than a nested tuple: a `((name, value), rest)` puts two
/// different things at the same nesting level and tells them apart by position
/// alone.
struct MimeParam<'a> {
  /// `attribute := token`.
  name: &'a [u8],
  /// `value := token / quoted-string`, the quoted form's DQUOTEs already off.
  value: ParamValue<'a>,
  /// What the value has left: the next `[CFWS] ";"`, or the trailing `[CFWS]`.
  rest: &'a [u8],
}

impl<'a> Iterator for MimeParams<'a> {
  type Item = Result<(&'a [u8], ParamValue<'a>), ListError>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.done {
      return None;
    }
    match Self::step(self.rest) {
      Ok(Some(param)) => {
        self.rest = param.rest;
        Some(Ok((param.name, param.value)))
      }
      Ok(None) => {
        self.done = true;
        None
      }
      Err(e) => {
        self.done = true;
        Some(Err(e))
      }
    }
  }
}

/// The RFC 2045 §5.1 `token` at the front of `value`, and what follows it.
///
/// ```text
/// token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
///             or tspecials>
/// ```
///
/// `None` when the next byte is not a token byte, the empty token included —
/// `1*` names at least one character, which is what makes `text/plain;` and
/// `text//plain` faults rather than values with an empty piece in them.
///
/// This is where the two grammars differ INSIDE a lexical token rather than
/// between two of them: `{` and `}` are ordinary `token` characters here and are
/// not RFC 9110 §5.6.2 `tchar`s, so `application/x-{foo}` is a media type in a
/// body part and is not one in an HTTP field section. The module's own table
/// says which side each test pins.
fn mime_token(value: &[u8]) -> Option<(&[u8], &[u8])> {
  let end = value
    .iter()
    .position(|byte| !is_mime_token_char(*byte))
    .unwrap_or(value.len());
  let (token, tail) = value.split_at_checked(end)?;
  (!token.is_empty()).then_some((token, tail))
}

/// Whether `name` keeps RFC 2045 §5.1's `x-token` rule: a name in the `X-`
/// namespace is an `x-token`, or it is nothing at all.
///
/// ```text
/// x-token := <The two characters "X-" or "x-" followed, with
///             no intervening white space, by any token>
/// ```
///
/// **This is the workspace's only spelling of those two characters.** RFC 2045
/// offers `x-token` at THREE productions — §5.1's `type` and `subtype`, through
/// `extension-token`, and §6.1's `mechanism` — and each of them has the same
/// question to decide about the same namespace:
///
/// ```text
/// type := discrete-type / composite-type
///
/// discrete-type := "text" / "image" / "audio" / "video" /
///                  "application" / extension-token
///
/// composite-type := "message" / "multipart" / extension-token
///
/// extension-token := ietf-token / x-token
///
/// subtype := extension-token / iana-token
///
/// mechanism := "7bit" / "8bit" / "binary" /
///              "quoted-printable" / "base64" /
///              ietf-token / x-token
/// ```
///
/// Teaching the rule to one of the three in a copy of its own leaves the other
/// two admitting a bare `x-` — `x-/plain` and `text/x-` read out of a body part
/// and handed over as media types. A rule written once and called from three
/// places cannot drift that way: a fourth production would call this too, and a
/// correction to it reaches every caller.
///
/// # `true` for a name outside the namespace, and that is not an admission
///
/// This decides ONE alternative. A `name` that does not open `X-` is not an
/// `x-token`, and this says nothing at all about it — whether it is one of
/// §5.1's or §6.1's literals, an `ietf-token`, or an `iana-token` is the
/// caller's own production to ask, and every caller asks it separately. What
/// this settles is the half all three share.
///
/// # Why an `X-` name that is not an `x-token` matches nothing else either
///
/// The tail is a `token`, which §5.1 spells `1*<…>` — NON-EMPTY — so a bare
/// `x-` fails the one production it looks like it belongs to. Every remaining
/// alternative of all three is a registry, and the registries are closed to this
/// namespace from both sides:
///
/// - **Media types.** RFC 2046 §6: "A media type value beginning with the
///   characters "X-" is a private value, to be used by consenting systems by
///   mutual agreement." and, in the sentence behind it, "Any format without a
///   rigorous and public definition must be named with an "X-" prefix, and
///   publicly specified values shall never begin with "X-"." That is a rule
///   about a media type VALUE, and the same section names the top-level case
///   outright — "In general, the use of "X-" top-level types is strongly
///   discouraged." — so it reaches `type` and `subtype` alike. RFC 2045 §5.1
///   states it of a subtype from the registry's own side: "Private values
///   (starting with "X-") may be defined bilaterally between two cooperating
///   agents without outside registration or standardization. Such values cannot
///   be registered or standardized."
/// - **Mechanisms.** RFC 2045 §6.3: "all content-transfer-encoding namespace
///   except that beginning with "X-" is explicitly reserved to the IETF for
///   future use".
///
/// So `ietf-token` — "An extension token defined by a standards-track RFC and
/// registered with IANA." — and `iana-token` — "A publicly-defined extension
/// token. Tokens of this form must be registered with IANA as specified in
/// RFC 2048." — are both out of reach of an `X-` name. Such a name is admitted
/// by `x-token` or by nothing at all, and `x-` is admitted by nothing at all.
pub(crate) fn keeps_x_token(name: &[u8]) -> bool {
  match name {
    // The two characters §5.1 spells both ways, and then the whole of what is
    // behind them as ONE `token`. `mime_token` answers `None` for an empty tail,
    // which is the `1*` the production requires, and hands back whatever was not
    // a token byte — so an empty remainder is what says the tail is a token and
    // is nothing else besides.
    [b'x' | b'X', b'-', tail @ ..] => matches!(mime_token(tail), Some((_, []))),
    _ => true,
  }
}

/// One byte of RFC 2045 §5.1's `token`: `%x21-7E` minus the fifteen
/// [`TSPECIALS`].
///
/// The alphabet as one predicate, so that the two things that need it ask the
/// same question. [`mime_token`] wants it byte by byte, because a `Content-Type`
/// arrives undelimited — there the token ends where the alphabet does, at the
/// `/`, the `;`, the `=`, a SPACE or a `(` — and the `Content-Transfer-Encoding`
/// reader in `range::multipart` wants it of a whole slice, because that value
/// arrives already delimited. It is crate-visible for that second caller alone.
///
/// The byte set is RFC 822's grammar arithmetic done once. Its `CHAR` is
/// US-ASCII 0-127 and its `CTL` is 0-31 and 127, so `CHAR` minus the CTLs minus
/// SPACE is `%x21-7E`, and `tspecials` removes fifteen of those.
pub(crate) fn is_mime_token_char(byte: u8) -> bool {
  matches!(byte, 0x21..=0x7E) && !TSPECIALS.contains(&byte)
}

/// RFC 2045 §5.1's fifteen `tspecials`, in the order that production lists
/// them.
///
/// The set [`is_mime_token_char`] subtracts, written out as a byte string so
/// that it can be READ against the RFC's own line — fifteen `|`-separated
/// character literals is a shape a reader checks by counting rather than by
/// comparing. §5.1's own note under the production says these must sit inside a
/// quoted-string to be used within a parameter value, and a `mechanism` is a
/// bare token with nowhere to put one.
const TSPECIALS: &[u8] = b"()<>@,;:\\\"/[]?=";

/// RFC 822's `CHAR`, which every MIME lexical class below is carved out of.
///
/// ```text
/// CHAR        =  <any ASCII character>        ; (  0-177,  0.-127.)
/// ```
///
/// The octal and decimal ranges in that comment are the whole definition, so
/// this is `u8::is_ascii` under the name the grammar gives it. It is not the
/// bound RFC 9110 §5.5 puts on an HTTP field value: that one admits `obs-text`,
/// `%x80-FF`, and RFC 822 has no such production. Nothing is lost by the
/// difference — `range::multipart` holds a body part's whole header block to
/// RFC 2046 §5.1.1's US-ASCII rule before any of this runs — but the predicate
/// is written from RFC 822 rather than inherited, because the grammar in force
/// here is RFC 822's.
const fn is_mime_char(byte: u8) -> bool {
  byte.is_ascii()
}

/// RFC 822's `qtext`: what may stand unescaped between a `quoted-string`'s
/// DQUOTEs.
///
/// ```text
/// qtext       =  <any CHAR excepting <">,     ; => may be folded
///                 "\" & CR, and including
///                 linear-white-space>
/// ```
///
/// Three exclusions and no more. **This is not RFC 9110 §5.6.4's `qdtext`**, and
/// the difference is not a lenience to be tidied away later:
/// `qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text` excludes every CTL
/// and DEL. So `charset="a<DEL>b"` — a conforming MIME parameter, since DEL is a
/// `CHAR` and is none of the three — was read with §5.6.4's scanner and refused,
/// and that refusal cost the whole part and every part behind it in the body.
/// The two exclusion lists are not orderable: RFC 822 admits the CTLs §5.6.4
/// forbids and forbids the `obs-text` §5.6.4 admits.
///
/// The DQUOTE and the backslash are excluded here and reached through their own
/// arms in [`mime_quoted_string`], which is what makes `"a\"b"` one string
/// containing a quote. The CR is excluded outright, and the production's own
/// comment says why that does not forbid folding: a fold is
/// `linear-white-space =  1*([CRLF] LWSP-char)`, so the CR of one arrives as
/// part of THAT production rather than as `qtext`. This crate never sees a fold
/// — the caller refuses a folded body-part field before a value reaches here —
/// so what the exclusion catches is a bare CR, which is no fold at all.
const fn is_mime_qtext(byte: u8) -> bool {
  is_mime_char(byte) && byte != b'"' && byte != b'\\' && byte != b'\r'
}

/// RFC 822's `ctext`: what may stand unescaped inside a comment.
///
/// ```text
/// ctext       =  <any CHAR excluding "(",     ; => may be folded
///                 ")", "\" & CR, & including
///                 linear-white-space>
/// ```
///
/// The same shape as [`is_mime_qtext`] with the comment's own delimiters
/// excluded in place of the DQUOTE, and the CR excluded for the same reason —
/// this production excludes it in as many words, so [`skip_comment`] must not
/// admit one.
const fn is_mime_ctext(byte: u8) -> bool {
  is_mime_char(byte) && byte != b'(' && byte != b')' && byte != b'\\' && byte != b'\r'
}

/// RFC 822's `quoted-pair`, as the test on the byte BEHIND the backslash.
///
/// ```text
/// quoted-pair =  "\" CHAR                     ; may quote any char
/// ```
///
/// So the escaped byte is any `CHAR` whatever, which is broader than RFC 9110
/// §5.6.4's `quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )`: that one
/// excludes every other CTL, and this one excludes none of them. §3.4.1 states
/// the rule in prose as well — "To quote a character, precede it with a
/// backslash" — with no character set attached.
const fn is_mime_quoted_char(byte: u8) -> bool {
  is_mime_char(byte)
}

/// The interior of the RFC 822 `quoted-string` that opens at the front of
/// `value`, and what follows its closing DQUOTE.
///
/// ```text
/// quoted-string = <"> *(qtext/quoted-pair) <">; Regular qtext or
///                                             ;   quoted chars.
/// ```
///
/// RFC 2045 §5.1: "Note that the value of a quoted string parameter does not
/// include the quotes.  That is, the quotation marks in a quoted-string are not
/// a part of the value of the parameter, but are merely used to delimit that
/// parameter value." So the interior is what comes back, with its escapes
/// untouched — the same shape the HTTP walk hands back, and the shape
/// `range::multipart`'s writer puts the DQUOTEs back around.
///
/// The cursor is an index into `value` rather than a re-slice, so the interior
/// can be cut out of the caller's own bytes at the end; every step of it is
/// saturating and every read of it is a checked one.
///
/// # Errors
///
/// [`ListError::UnterminatedQuotedString`] when `value` ends with the string
/// still open, the dangling backslash of a `quoted-pair` included.
/// [`ListError::InvalidQuotedByte`] for a byte neither [`is_mime_qtext`] nor
/// [`is_mime_quoted_char`] admits. [`ListError::NotAToken`] for a `value` that
/// does not open with a DQUOTE — a caller error rather than a fact about the
/// input — and for the two slices of the closing arm, which the cursor makes
/// unreachable and which are answered rather than unwrapped because this crate's
/// leaves are proved panic-free at link time.
fn mime_quoted_string(value: &[u8]) -> Result<(&[u8], &[u8]), ListError> {
  if value.first() != Some(&b'"') {
    return Err(ListError::NotAToken);
  }
  // Past the opening DQUOTE, which is what the interior starts behind.
  let mut at: usize = 1;
  loop {
    let Some(&byte) = value.get(at) else {
      return Err(ListError::UnterminatedQuotedString);
    };
    at = at.saturating_add(1);
    match byte {
      b'"' => {
        let (Some(interior), Some(tail)) = (value.get(1..at.saturating_sub(1)), value.get(at..))
        else {
          return Err(ListError::NotAToken);
        };
        return Ok((interior, tail));
      }
      b'\\' => {
        let Some(&escaped) = value.get(at) else {
          return Err(ListError::UnterminatedQuotedString);
        };
        if !is_mime_quoted_char(escaped) {
          return Err(ListError::InvalidQuotedByte);
        }
        at = at.saturating_add(1);
      }
      b if is_mime_qtext(b) => {}
      _ => return Err(ListError::InvalidQuotedByte),
    }
  }
}

/// Walks past RFC 5322 §3.2.2's `CFWS` at the front of `value`, or `None` for a
/// comment that never closes or that carries a byte RFC 822's `ctext` and
/// `quoted-pair` do not admit.
///
/// `CFWS = (1*([FWS] comment) [FWS]) / FWS`, with `FWS` here reduced to the SP
/// and HTAB of one unfolded line.
///
/// Crate-visible for the second RFC 2045 field in this crate. §6.1 defines
/// `Content-Transfer-Encoding` as structured too, so the same `CFWS` sits around
/// its `mechanism`, and the `multipart` reader under `range` strips it with this
/// rather than with a second walk that could disagree about what a comment is.
pub(crate) fn skip_cfws(value: &[u8]) -> Option<&[u8]> {
  let mut rest = value;
  loop {
    match rest.split_first() {
      Some((b' ' | b'\t', tail)) => rest = tail,
      Some((b'(', tail)) => rest = skip_comment(tail)?,
      _ => return Some(rest),
    }
  }
}

/// Walks past the interior and the closing `)` of a comment whose opening `(`
/// has already been read, or `None` if the value ends first or a byte the
/// grammar excludes stands inside.
///
/// ```text
/// comment     =  "(" *(ctext / quoted-pair / comment) ")"
/// ```
///
/// so comments NEST. The depth is a counter rather than recursion: a recursive
/// walk over attacker-chosen input is a stack this crate cannot bound, and a
/// `no_std` target has no room to spare for one.
///
/// Three of the four arms are the three alternatives the repetition offers — a
/// nested comment, a `quoted-pair`, and `ctext` — and the fourth is the refusal
/// that makes this a walk of a grammar rather than a search for the matching
/// paren. A `\)` does not close a comment because the backslash opens a
/// [`quoted-pair`](is_mime_quoted_char), which makes the `)` behind it comment
/// text; RFC 5322 §3.2.1 states the same rule for its own `quoted-pair`.
fn skip_comment(value: &[u8]) -> Option<&[u8]> {
  let mut rest = value;
  let mut depth: usize = 1;
  loop {
    let (byte, tail) = rest.split_first()?;
    rest = tail;
    match *byte {
      b'(' => depth = depth.checked_add(1)?,
      b')' => {
        depth = depth.checked_sub(1)?;
        if depth == 0 {
          return Some(rest);
        }
      }
      b'\\' => {
        let (escaped, tail) = rest.split_first()?;
        if !is_mime_quoted_char(*escaped) {
          return None;
        }
        rest = tail;
      }
      byte if is_mime_ctext(byte) => {}
      _ => return None,
    }
  }
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
///
/// Crate-private: [`weight_for`] is the public derivation §12.5.1 and §12.4.2
/// settle between them, and a caller reading a bare `q` parameter out of a
/// field it walked itself is reading one member of a list this module already
/// walks. The link-time panic proof reaches it through
/// `__no_panic_internals`, which is what keeps it from having to be `pub`.
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
/// # No `PartialEq`
///
/// A derive here compares the SAME bytes this type holds a [`ListMember`] of —
/// as written, not as parsed — and that type carries no derive of its own for
/// the identical reason. Two probes, both `false` under such a derive and both
/// one media range:
///
/// - `accept([b"text/html".as_slice()]).next()` against
///   `accept([b"TEXT/HTML".as_slice()]).next()`. §8.3.1: "The type and subtype
///   tokens are case-insensitive" — the same tokens a `media-range` reuses.
/// - `accept([b"text/html;level=3".as_slice()]).next()` against
///   `accept([b"text/html; level=3".as_slice()]).next()`, whose only
///   difference is the `OWS` §5.6.6 puts around a parameter's `;`.
///
/// [`MediaType`] is in exactly this position — the same case-insensitive
/// tokens, the same `OWS`, the same [`ListMember`] this type also holds one
/// of — so the two get the same answer, and a ruling that reached only one of
/// them would have answered a type rather than the claim underneath it. A
/// semantic `PartialEq` is not the fix either, for the
/// reason [`MediaType`]'s own doc gives at length: media-range equivalence
/// needs answers this crate does not have — whether parameter order matters,
/// what a duplicate parameter means, which parameter values are
/// case-sensitive. A caller compares [`ty`](Self::ty) and
/// [`subtype`](Self::subtype) with `str::eq_ignore_ascii_case`, and walks
/// [`params`](Self::params) itself under whatever rule its own field defines.
#[derive(Debug, Copy, Clone)]
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
  // A valueless parameter is refused exactly as `media_type` refuses one
  // (`MediaError::ValuelessParameter`), and by the same declaration —
  // `MEDIA_VALUELESS`, which the walk applies at every entrance it has and
  // reports as `ListError::MissingParameterValue`. It arrives through the `?`
  // below, ahead of §12.5.1's weight question, because a bare name fails
  // §5.6.6's `parameter` grammar outright whatever it is called: a bare `q` is a
  // missing value, not a bad `qvalue`. Every parameter named `q` that DOES carry
  // a value is weight, in wire order, last one wins.
  //
  // # Why a weight is never judged behind RFC 9110 §5.2's field-line join
  //
  // `MediaError::BadWeight` is this function's, and this function is only ever
  // shown the parameters on the line the member BEGAN on. A weight standing
  // behind that join is therefore reported as `ValueSpansFieldLines` — the
  // fault of the parameter that crossed — rather than as the bad `qvalue` it
  // may be. That is settled rather than open. RFC 9110 §12.4.2 writes
  // `weight = OWS ";" OWS "q=" qvalue` and
  // `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`, which name
  // no quoted-string and no OWS inside the value — so a weight cannot itself
  // span the comma §5.2 inserts, and only a DIFFERENT parameter's quoted value
  // can, which is then the parameter the walk refuses. What is left is a
  // conforming `q=0.5` standing behind such a parameter, and the reason it is
  // not read is not this rule but the contiguous-borrow one: the crossing value
  // is not one slice, so `ParamValue` cannot hand it over and the parameter
  // walk ends at it. Reading the weight behind it would need a segmented or
  // streaming `ParamValue`, or a lending visitor in place of the iterator — a
  // public change, bought for a weight on a field line whose earlier parameter
  // is already unreadable. The harm is bounded meanwhile: `accept` latches on
  // the first fault, so no range is handed over and nothing malformed is
  // accepted.
  let mut weight = Weight::ONE;
  for param in member.params() {
    let (name, value) = param.map_err(MediaError::from)?;
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
/// A weight standing BEHIND that join is reported as the crossing parameter's
/// `ValueSpansFieldLines` rather than as [`MediaError::BadWeight`], and that is
/// settled rather than open: RFC 9110 §12.4.2's `qvalue` holds no
/// quoted-string, so a weight cannot itself span the comma §5.2 inserts, and a
/// conforming one behind a parameter that does is unread for the
/// contiguous-borrow reason instead. `range_from`'s own comment carries the
/// argument and what reading it would cost.
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
    members: parameterised_list_with(lines, is_media_name, MEDIA_PARAMETERS, MEDIA_VALUELESS),
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
/// A parse-constant rather than a caller-set knob: the storage is in the
/// binary, so a caller cannot raise it.
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
///
/// The `[RFC2046]` in §8.3.1's sentence is RFC 9110's own citation mark and is
/// quoted verbatim, brackets and all. The definition below is what keeps it
/// from dangling as an unresolved intra-doc link — escaping the brackets would
/// resolve that too, and would put a `\` where the RFC has none, which
/// `quote-check` reads as a character the quotation does not have.
///
/// [RFC2046]: https://www.rfc-editor.org/rfc/rfc2046
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
/// use http_semantics::media::{media_type, weight_for, weight_for_with, Weight};
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
/// # Ok::<(), http_semantics::media::MediaError>(())
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
