//! An independent reading of RFC 9110 §11.6.1's `#challenge` value, written
//! from the RFC rather than from `http_semantics::auth`.
//!
//! It exists to grade one axis and one only: **does the reader under test hide
//! a challenge that a conforming reading would have shown?** RFC 9110 §11.4
//! has a user agent answer a response by "selecting the challenge with what it
//! considers to be the most secure auth-scheme that it understands", which it
//! cannot do over a challenge it was never handed.
//!
//! # What it does NOT model, deliberately
//!
//! `MAX_CHALLENGE_LINES` and `MAX_PARAMS_PER_CREDENTIAL` are the reader's own
//! bounds and not the grammar's. An oracle carrying them would be grading the
//! module against itself, so this one has neither: a challenge spread over
//! twenty field lines derives here exactly as one spread over two.
//!
//! # The ambiguity, resolved as "there EXISTS a derivation"
//!
//! RFC 9110 §11.6.1 states the problem: the field value "might contain more
//! than one challenge, and each challenge can contain a comma-separated list
//! of authentication parameters". Both levels are the same §5.6.1 construct,
//! one inside the other, so at a comma the next element may be either another
//! parameter of the challenge already open or the scheme of the next one. A
//! recipient picks one reading; this oracle enumerates all of them, because a
//! challenge is hidden only when NO reading shows it.
//!
//! The enumeration is a walk over states `(element start, context)`, where the
//! context is the parameter list still open. RFC 9110 §11.2's "each parameter
//! name MUST only occur once per challenge" is enforced along each derivation,
//! so a reading that repeats a name is not one.
//!
//! # The three questions it answers
//!
//! - **Derives.** A whole challenge derives from the probe's offset to the end
//!   of the value, asked of those bytes alone. Nothing is hidden where nothing
//!   stands.
//! - **Excused.** A §11.2 value position stands somewhere in front of the
//!   probe, holds a DQUOTE, and the bytes between that DQUOTE and the probe are
//!   ones §5.6.4 admits inside a quoted-string with none of them closing it. The
//!   bytes are that value's data under the reading that opens it, so a reader
//!   that showed no challenge among them is not hiding one.
//!
//!   **Asked of the POSITION and not of a derivation that reaches it**, which is
//!   the correction al8n/wren#77 forced. Asking whether the whole value derives
//!   let a malformed FIRST element decide that no reading licensed a
//!   quoted-string standing later in the value that §11.2 admits perfectly well
//!   — so inputs whose probe is plainly a parameter's data graded
//!   `yields-underivable`, and the axis could not see the reader manufacturing a
//!   challenge out of them. A reader in recovery is past the point where any
//!   derivation of the whole value exists; what it must not do is cut a value
//!   the grammar admits at that position, and that is what this now asks.
//! - **Reached.** Some derivation has an element start exactly at the probe's
//!   offset, reads it as an `auth-scheme`, and derives the rest of the value
//!   from there. This is the whole value deriving, where **Derives** is the
//!   probe's own bytes deriving.

use std::collections::HashSet;

/// What the oracle says about one field value and the offset a probe challenge
/// stands at in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
  /// Some reading puts the offset inside a §5.6.4 quoted-string, whether or
  /// not that string closes.
  ///
  /// [`covered`] is the whole of it, and the module doc says why it is a
  /// question about a POSITION rather than about a derivation that reaches one.
  pub excused: bool,
  /// Some derivation reads the offset as the `auth-scheme` of a challenge and
  /// derives the rest of the value from there.
  pub reached: bool,
  /// A whole challenge derives from the offset to the end of the value —
  /// asked of those bytes ALONE, with no claim that anything reaches them.
  ///
  /// This is what says a challenge stands there to be hidden, and it is asked
  /// of the real bytes for a reason. Grading a hider by a control instead — the
  /// same value with every DQUOTE replaced — lets the control REPAIR: swapping
  /// the DQUOTE out of `Digest realm=zc"` leaves `Digest realm=zcq`, which
  /// parses where the original never could, so the control reports a challenge
  /// hidden that no reading of the real bytes has.
  pub derives: bool,
}

/// The parameter list still open at an element boundary, or its absence.
///
/// `None` is a boundary at which no challenge can take another parameter: the
/// value has not started, or the challenge before this comma took no `1*SP`,
/// or its body was RFC 9110 §11.2's `token68` alternative, which is not a list.
type Context = Option<Vec<Vec<u8>>>;

/// One position in the walk: where the next element starts, and what may
/// follow it. A position at the value's length is the value having derived.
type State = (usize, Context);

/// Where an element that ended at some offset leaves the walk.
pub(crate) enum Edge {
  /// Only the list's own `OWS` stood behind it, so the value ends there.
  Ends,
  /// A comma stood behind it, and the next element starts here.
  Next(usize),
}

/// Reads `value` as RFC 9110 §11.6.1's `#challenge` every way the grammar
/// admits, and reports the three facts the offset `probe` is graded by.
pub fn read(value: &[u8], probe: usize) -> Verdict {
  let mut verdict = Verdict {
    excused: covered(value, probe),
    reached: false,
    derives: derives_as_a_challenge(value, probe),
  };
  let mut seen: HashSet<State> = HashSet::new();
  let mut queue: Vec<State> = Vec::new();
  let start: State = (0, None);
  seen.insert(start.clone());
  queue.push(start);

  while let Some((at, context)) = queue.pop() {
    if at == probe && verdict.derives {
      verdict.reached = true;
    }
    for next in step(value, at, context.as_ref()) {
      if seen.insert(next.clone()) {
        queue.push(next);
      }
    }
  }
  verdict
}

/// Every element boundary reachable from the one at `at`, and the context each
/// leaves behind.
///
/// RFC 9110 §5.6.1.2 expands a list as
/// `#element => [ element ] *( OWS "," OWS [ element ] )`, which hangs every
/// `OWS` it has on a comma and none in front of the first element — so nothing
/// here skips whitespace before an element no comma was crossed to reach.
fn step(value: &[u8], at: usize, context: Option<&Vec<Vec<u8>>>) -> Vec<State> {
  let mut out = Vec::new();

  // The empty element RFC 9110 §5.6.1.2 admits, which ends no challenge: its
  // opening sentence is "Empty elements do not contribute to the count of
  // elements present."
  push(&mut out, value, boundary(value, at), context.cloned());

  for (end, opened) in challenge_readings(value, at) {
    push(&mut out, value, boundary(value, end), opened);
  }

  // The element read as one more parameter of the challenge already open.
  if let Some(names) = context
    && let Some(param) = auth_param(value, at)
  {
    let name = folded(value, param.name);
    // RFC 9110 §11.2: "each parameter name MUST only occur once per
    // challenge". A reading that repeats one is not a reading — so the name is
    // answered BEFORE anything about this parameter's value is believed.
    if !names.contains(&name)
      && let Some(end) = param.end
    {
      let mut names = names.clone();
      names.push(name);
      names.sort();
      push(&mut out, value, boundary(value, end), Some(names));
    }
  }

  out
}

/// Every way the element at `at` reads as a whole `challenge`: where it ends,
/// and the parameter list it leaves open behind it.
///
/// ```text
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// [`covers`] guards its `#auth-param` recursion against a body RFC 9110
/// §11.2's `token68` already derives, and nothing here repeats that guard,
/// because nothing here needs it: every reading below is kept only where
/// [`boundary`] admits its end, and the two `#auth-param` readings of a body
/// whose first element is wholly a `token68` are both refused there — the empty
/// first element because a `token68` byte is neither `OWS` nor a comma, and the
/// parameter because [`auth_param`] answers `None` for the element the same
/// disjointness argument covers. A guard here would be a second spelling of a
/// filter that already holds, and would answer for its own correctness rather
/// than being tested by anything.
fn challenge_readings(value: &[u8], at: usize) -> Vec<(usize, Context)> {
  let mut out = Vec::new();
  let Some(scheme_end) = token_end(value, at) else {
    return out;
  };
  // `1*SP` is the only entrance the body has, so a scheme with no SP behind it
  // is a whole challenge that took no parameters.
  if value.get(scheme_end) != Some(&b' ') {
    out.push((scheme_end, None));
    return out;
  }
  let body = skip_sp(value, scheme_end);

  // RFC 9110 §11.2's `token68` alternative, which is not a list and holds no
  // name to repeat.
  if let Some(end) = token68_end(value, body) {
    out.push((end, None));
  }
  // The `#auth-param` alternative with its first element empty, which is how
  // `Basic , realm="x"` is one challenge carrying one parameter.
  out.push((body, Some(Vec::new())));
  // And with a parameter in that first element. No name stands in front of it,
  // so §11.2's MUST has nothing to refuse here.
  if let Some(param) = auth_param(value, body)
    && let Some(end) = param.end
  {
    out.push((end, Some(vec![folded(value, param.name)])));
  }
  out
}

/// Whether RFC 9110 §5.6.1.2 lets an element of the OUTER `#challenge` list
/// begin at `at`.
///
/// ```text
/// #element  => [ element ] *( OWS "," OWS [ element ] )
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// The expansion puts an element of the outer list at exactly two kinds of
/// offset: the value's first byte, and the far side of a comma with the `OWS`
/// that comma carries behind it. Nowhere else — and in particular NOT at the
/// body position §11.3's `1*SP` opens, which stands inside an outer element
/// and which the production puts no second `challenge` at.
///
/// # Why the comma may be read raw
///
/// Readings differ about whether a given comma SEPARATES or is some value's
/// data; they do not differ about where the commas are. So where a raw comma
/// stands in front of `at` with only §5.6.3 whitespace between, the reading
/// that leaves that comma outside every string puts an element start here —
/// and where none does, no reading can, because every element start behind the
/// first is behind a comma. Whether that reading also holds the probe inside a
/// string is [`covered`]'s question and is asked separately.
///
/// [`covers`] carries the same distinction as [`Start`], reached by walking the
/// value; this is the same sentence read off §5.6.1.2 at one offset. The two
/// are separate compositions of `skip_ows` on purpose.
fn starts_an_element(value: &[u8], at: usize) -> bool {
  let Some(comma) = value
    .get(..at)
    .and_then(|front| front.iter().rposition(|&byte| byte == b','))
  else {
    // No comma in front, so the only element that can begin here is the list's
    // first — and §5.6.1.2 puts no `OWS` in front of that one.
    return at == 0;
  };
  skip_ows(value, comma.saturating_add(1)) == at
}

/// Whether a whole `challenge` stands at `at`: an element of the outer
/// `#challenge` list begins there, and one derives from it to where RFC 9110
/// §5.6.1.2 lets a list element end.
///
/// The probe's OWN bytes, asked in isolation. What stands behind the element it
/// ends at is a different question — one about the rest of the list and not
/// about whether a challenge is written here — which is why [`Verdict::reached`]
/// is the separate fact that a derivation gets here at all.
///
/// # The bytes in front DO answer one thing, and leaving it out invented a
/// challenge to hide
///
/// Where a challenge may STAND. `challenge = auth-scheme [ 1*SP ( token68 /
/// #auth-param ) ]` puts no second challenge at a body's first element, so
/// `Broken;junk,Newauth Digest realm=z` has the probe at an offset no reading
/// of the outer `#challenge` list has an element start at — and hiding it is
/// what a reader MUST do, since showing it would be manufacturing a challenge
/// out of one challenge's body. Asked without [`starts_an_element`], this
/// answered `true` there and the axis graded 18 records of corpus O
/// `hider-unexcused`: a zero-target reporting the reader for doing the one
/// thing the module exists to make it do. [`covers`] has carried the same
/// distinction as [`Start`] since `Basic a a=", Digest realm=z`, and this is
/// the axis's third input catching up with it.
fn derives_as_a_challenge(value: &[u8], at: usize) -> bool {
  starts_an_element(value, at)
    && challenge_readings(value, at)
      .into_iter()
      .any(|(end, _)| boundary(value, end).is_some())
}

/// Records the state an [`Edge`] leads to, if it leads to one.
fn push(out: &mut Vec<State>, value: &[u8], edge: Option<Edge>, context: Context) {
  match edge {
    Some(Edge::Ends) => out.push((value.len(), None)),
    Some(Edge::Next(at)) => out.push((at, context)),
    None => {}
  }
}

/// One `auth-param` the walk read: where its name is, and where it ends when
/// this reading has it end at all.
struct Param {
  name: (usize, usize),
  /// One past the parameter's last byte, or `None` where the value is a string
  /// nothing closes and there is no parameter to hand back.
  end: Option<usize>,
}

/// Where RFC 9110 §11.2's `auth-param` admits the VALUE of an element beginning
/// at `at`, or `None` for an element that is no `auth-param`.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Three terminals stand in front of that value and all three are read here:
/// the name `token`, the `=`, and the `BWS` §5.6.3 defines as `OWS`'s own bytes
/// on either side of it. This is the one position a §5.6.4 quoted-string may
/// open at behind an `auth-scheme` — §5.6.2's `tchar` and §11.2's `token68`
/// alphabet both exclude DQUOTE — which is the fact [`covered`] is decided on.
pub(crate) fn value_position(value: &[u8], at: usize) -> Option<usize> {
  let name_end = token_end(value, at)?;
  let eq = skip_ows(value, name_end);
  if value.get(eq) != Some(&b'=') {
    return None;
  }
  Some(skip_ows(value, eq.saturating_add(1)))
}

/// Reads RFC 9110 §11.2's `auth-param` at `at`.
fn auth_param(value: &[u8], at: usize) -> Option<Param> {
  let start = value_position(value, at)?;
  let name = (at, token_end(value, at)?);

  if value.get(start) == Some(&b'"') {
    return match scan_quoted(value, start.saturating_add(1)) {
      Quoted::Closed(end) => Some(Param {
        name,
        end: Some(end),
      }),
      // Nothing closes it, so this reading has no parameter to hand back.
      Quoted::Open => Some(Param { name, end: None }),
      Quoted::Invalid => None,
    };
  }
  let end = token_end(value, start)?;
  Some(Param {
    name,
    end: Some(end),
  })
}

/// Whether some reading of `value` puts `probe` inside an RFC 9110 §5.6.4
/// quoted-string.
///
/// # What a reading is
///
/// ```text
/// #element   => [ element ] *( OWS "," OWS [ element ] )
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// A left-to-right walk over element starts, and [`covers`] enumerates every
/// one of them. Two regimes, and which regime an element is in is the whole of
/// what this gets right that asking after the WHOLE value's derivation got
/// wrong:
///
/// - **In front of the first fault the grammar decides.** A `parameter-value`
///   beginning with a DQUOTE derives only the `quoted-string` alternative —
///   §5.6.2's `tchar` excludes DQUOTE — so that string is not a choice, and
///   where it closes is where the element ends.
/// - **Behind the first fault nothing derives, so every DQUOTE §11.2 admits a
///   value at is a choice**: a reading may open the string there, and a reading
///   may leave it shut and take the element to the next comma read raw. The
///   readings BETWEEN the two extremes are the ones a comparison of the raw
///   reading with the greedy one never asks, and they are where a manufactured
///   challenge comes from.
///
/// A fault is an element start no reading of the grammar leaves. That is the
/// correction al8n/wren#77 forced: the old question was whether a derivation of
/// the whole value REACHED the position, so one malformed element decided that
/// no reading licensed a quoted-string standing perfectly well behind it, and
/// the axis could not see the reader cutting that value in half.
///
/// # A reading is a derivation, and an alternative that fails is not one
///
/// The second correction, and the one the `token68` guard in [`covers`] is.
/// `( token68 / #auth-param )` is unordered, so a recipient may TRY either
/// alternative — but where one of them derives the body and the other derives
/// no part of it, only the first is a reading of these bytes. Locating the
/// value's first fault at an element start that exists only inside the failed
/// alternative puts every DQUOTE behind it into the free regime on the strength
/// of a reading nobody has, and that is how the excuse for
/// `Bearer abc, Broken<HTAB>junk, x="open, Digest realm=z` was manufactured.
pub(crate) fn covered(value: &[u8], probe: usize) -> bool {
  covers(
    value,
    Position::HEAD,
    Regime::Every,
    probe,
    &mut HashSet::new(),
  )
}

/// Whether RFC 9110 §11.2 derives the WHOLE of `element` as one `auth-param`.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// `( token / quoted-string )` is one alternative taken whole, so bytes behind
/// the value are bytes no `auth-param` derives, and a string that never closes
/// leaves the element deriving nothing. [`boundary`] is what asks the second
/// question, over an element §5.6.1.2's `OWS` is already off the front of.
///
/// This exists so that a table naming which of a family's spans §11.2 derives
/// can be CHECKED against §11.2 rather than transcribed beside it. Two
/// transcriptions of one production, each tested from the reading that produced
/// it, is the shape al8n/wren#76 was filed over.
pub(crate) fn derives_a_parameter(element: &[u8]) -> bool {
  match auth_param(element, 0) {
    Some(Param { end: Some(end), .. }) => matches!(boundary(element, end), Some(Edge::Ends)),
    _ => false,
  }
}

/// Whether the GRAMMAR puts `probe` inside an RFC 9110 §5.6.4 quoted-string —
/// which is [`covered`] over the readings a recipient has no choice about.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Two things are dropped, and they are the two ways a covering reading can be
/// a CHOICE rather than a derivation.
///
/// - **The free regime behind a fault**, which [`covers`] enters only where
///   nothing derives. There a DQUOTE at a §11.2 value position is one a reading
///   may open and a reading may leave shut, so the two readings disagree about
///   the bytes behind it by construction.
/// - **A string whose own element does not derive.** `( token / quoted-string )`
///   is one alternative taken WHOLE, so a `quoted-string` that never closes, or
///   one with bytes behind its close that no production admits, leaves the
///   element deriving nothing — and a recipient reading those bytes as that
///   parameter's data is choosing one reading of a run rather than following the
///   grammar. `Basic a=","a, Digest realm=z` is the shape: the comma is inside
///   `a`'s value under the reading that opens the string, and outside it under
///   the reading that leaves it shut, and neither is forced.
///
/// So `covered && !forced` is exactly **the readings disagree**, and
/// [`settled`] is what that is for.
fn forced(value: &[u8], probe: usize) -> bool {
  covers(
    value,
    Position::HEAD,
    Regime::Forced,
    probe,
    &mut HashSet::new(),
  )
}

/// Whether every reading of `value` agrees about the offset `at`: that it is
/// inside an RFC 9110 §5.6.4 quoted-string, or that it is outside one.
///
/// Three cases and only the third is a disagreement.
///
/// - No reading puts it inside a string — settled, as a separator or as a byte
///   of a run every reading reads the same way.
/// - Every reading puts it inside one, because the grammar leaves no choice —
///   settled, as that parameter's data. `Basic a1="x,y", Digest realm=z` holds
///   such a comma, and a walk that crosses it inside the string loses nothing.
/// - Some readings put it inside and some do not — **unsettled**, and this is
///   the only case a walk is entitled to decline a boundary over.
pub fn settled(value: &[u8], at: usize) -> bool {
  !covered(value, at) || forced(value, at)
}

/// Whether every RFC 9110 §5.6.1.2 comma standing in front of `probe` is one
/// [`settled`] answers `true` for.
///
/// A `#challenge` walk reaches the probe by crossing commas, one at a time, and
/// it may decline any comma the readings disagree about — that is the whole of
/// what [`crate::AuthError::ChallengeBoundaryUnknown`] is for. Where NO comma in
/// front of the probe is one they disagree about, there was nothing to decline:
/// every element boundary between the value's head and the probe is one every
/// reading places in the same byte, and a walk that stopped anyway stopped at a
/// boundary the grammar had already made for it.
///
/// The commas are read RAW rather than by any reading's element walk, which is
/// what makes this an over-approximation in the safe direction: a byte that is
/// a comma inside some string and no separator anywhere is still asked about,
/// and answering `false` for it only ever moves a record OUT of the class this
/// is a zero-target for.
pub fn every_comma_in_front_is_settled(value: &[u8], probe: usize) -> bool {
  value
    .iter()
    .enumerate()
    .take(probe)
    .filter(|&(_, &byte)| byte == b',')
    .all(|(at, _)| settled(value, at))
}

/// Which readings a [`covers`] walk is over.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Regime {
  /// Every reading RFC 9110 admits a recipient, the free ones behind a fault
  /// included, and every DQUOTE §11.2 admits a value at whether or not the
  /// element it stands in goes on to derive. This is what `Verdict::excused`
  /// is asked over, and its doc says why the question is about a POSITION.
  Every,
  /// Only the readings the grammar leaves a recipient no choice about.
  /// [`forced`]'s doc names the two this drops and why each of them is a
  /// choice.
  Forced,
}

/// Which list an element start belongs to.
///
/// A `challenge` stands at an element of the OUTER `#challenge` list and
/// nowhere else. The first element of a challenge's own `#auth-param` list
/// begins at the body position `1*SP` admits — inside the outer element — and
/// `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` puts no second
/// challenge there. Reading one anyway is how `Basic a a=", Digest realm=z`
/// acquired a reading in which `a` is a scheme and the DQUOTE behind it opens a
/// value: the `#auth-param` list has one element, `a a=`, and no production
/// admits a string in it at all.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
enum Start {
  /// An element of the outer `#challenge` list, where a challenge may open.
  Element,
  /// The first element of a challenge's `#auth-param` list, where none may.
  Body,
}

/// One position of a [`covers`] walk, and the whole of what memoises it.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct Position {
  /// An element start, and an offset every reading in hand stands OUTSIDE a
  /// quoted-string at.
  at: usize,
  /// Which list that element start belongs to.
  start: Start,
  /// Whether a challenge's `#auth-param` list is open here. At the head of the
  /// value none is, which is why `Basic ="x, Digest realm=z` has no reading in
  /// which `Basic` names a parameter whose value swallows the comma.
  list: bool,
  /// Whether an element start in front of this one is one no reading of the
  /// grammar leaves.
  faulted: bool,
}

impl Position {
  /// The head of the value: its first element, with no list open and no fault
  /// in front of it.
  const HEAD: Self = Self {
    at: 0,
    start: Start::Element,
    list: false,
    faulted: false,
  };

  /// The same position at the element start `at`, in the outer `#challenge`
  /// list and with `list` as given — which is every step this walk makes.
  const fn next(self, at: usize, list: bool) -> Self {
    Self {
      at,
      start: Start::Element,
      list,
      faulted: self.faulted,
    }
  }
}

fn covers(
  value: &[u8],
  here: Position,
  regime: Regime,
  probe: usize,
  seen: &mut HashSet<Position>,
) -> bool {
  let Position {
    at,
    start,
    list,
    faulted,
  } = here;
  if at > probe || !seen.insert(here) {
    return false;
  }
  // Whether ANY reading of the grammar leaves this element start. Where none
  // does, this start is the fault, and every reading behind it is free.
  let mut derived = false;
  let mut hit = false;

  // The empty element §5.6.1.2 admits: "A recipient MUST parse and ignore a
  // reasonable number of empty list elements".
  match boundary(value, at) {
    None => {}
    Some(Edge::Ends) => derived = true,
    Some(Edge::Next(next)) => {
      derived = true;
      hit |= covers(value, here.next(next, list), regime, probe, seen);
    }
  }

  // The element read as a whole `challenge`, which only an element of the outer
  // list may be.
  if start == Start::Element
    && let Some(scheme_end) = token_end(value, at)
  {
    if value.get(scheme_end) == Some(&b' ') {
      // The scheme and its `1*SP` derive whatever the body does, so a fault
      // inside the body is the BODY's element start and not this one.
      //
      // The bare-scheme reading is NOT dropped here, though this arm does not
      // spell it. `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`
      // leaves `Basic<SP>, Digest realm=z` deriving as two challenges, and the
      // body's empty first element below reaches that same successor: §5.6.3's
      // `OWS` is `*( SP / HTAB )` and §11.3's opener is `1*SP`, so `skip_sp`
      // lands inside the run `skip_ows` crosses and `boundary(value, at)` at
      // the body IS `boundary(value, scheme_end)`. What differs is the `list`
      // the successor carries, and `readings`'s module doc carries the argument
      // and the search that say the difference costs no opener. `readings`
      // states the reading and this does not; that file's wording is the one
      // this should be read as.
      derived = true;
      let body = skip_sp(value, scheme_end);
      // RFC 9110 §11.2's `token68` alternative, which is not a list. It is the
      // body when its run reaches the end of the body's first element — RFC
      // 9110 §5.6.1.2's `OWS` and then the comma, or the end of the value.
      let run = token68_end(value, body).filter(|&end| boundary(value, end).is_some());
      if let Some(Edge::Next(next)) = run.and_then(|end| boundary(value, end)) {
        hit |= covers(value, here.next(next, false), regime, probe, seen);
      }
      // And the `#auth-param` alternative, whose first element starts at the
      // body position — an element start inside this outer element. Taken only
      // where `token68` did NOT derive the body, because the two alternatives
      // never derive one element between them:
      //
      // ```text
      // token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
      // auth-param = token BWS "=" BWS ( token / quoted-string )
      // ```
      //
      // RFC 9110 §11.2's base alphabet holds no `=`, so every `=` in a
      // `token68` lies in its trailing pad; and where the run reaches the
      // element's end, nothing but more `=` and §5.6.3's `OWS` stands behind
      // that pad. `auth-param` needs `BWS` and then a `token` or a
      // `quoted-string` — a §5.6.2 `tchar` or a DQUOTE — and `=`, SP and HTAB
      // are none of those. So `#auth-param` does not derive the body's first
      // element, this walk is not at an element start there under any reading,
      // and a position no reading is at cannot be the value's first fault.
      // Reading it as one is what put `Bearer abc, Broken<HTAB>junk, x="open,
      // Digest realm=z` behind a fault that is not there, and excused a
      // `Digest` that no reading of the value holds inside a value.
      //
      // ABNF's `/` is unordered and nothing here orders it. What this says is
      // that ONE alternative derives these bytes and the other derives none of
      // them, which is not a choice §11.6.1 leaves a recipient.
      if run.is_none() {
        hit |= covers(
          value,
          Position {
            at: body,
            start: Start::Body,
            list: true,
            faulted,
          },
          regime,
          probe,
          seen,
        );
      }
    } else {
      // No `1*SP`, so the scheme is a whole challenge that took no parameters.
      match boundary(value, scheme_end) {
        None => {}
        Some(Edge::Ends) => derived = true,
        Some(Edge::Next(next)) => {
          derived = true;
          hit |= covers(value, here.next(next, false), regime, probe, seen);
        }
      }
    }
  }

  // The element read as one more `auth-param` of a list already open.
  //
  // RFC 9110 §11.2's one-name-once MUST is deliberately NOT applied here, and
  // the reason is not that it makes no difference — it does. Applying it would
  // make a repeated name an element nothing derives, which opens the free
  // regime with the list still open, and
  // `Basic a=1, a=2, Bearer abc, x="open, Digest realm=z` would then be excused
  // for a reading in which every element since `a=2` is garbage that list still
  // holds. Not applying it lets `a=2` derive, so the `token68` of `Bearer abc`
  // closes the list and the DQUOTE behind it stands at no value position.
  //
  // The second is right, and this is what it rests on. §5.6.1.2 delimits the
  // list before §11.2 says anything about names: the MUST is prose over a list
  // whose elements are already where the commas put them, and honouring it
  // moves no comma and un-derives no element. This function asks where a
  // quoted-string may open, which is a question about element boundaries — so
  // a rule that moves none of them cannot move its answer. What the MUST does
  // decide is whether the value CONFORMS, which is `reached`'s question and not
  // this one; `step` applies it for exactly that reason, and the two functions
  // differ here because they are asked different things.
  //
  // `http_semantics::auth::AuthError::is_a_receiver_bound` classifies
  // `DuplicateParameter` on the same argument, from the other side of the
  // differential. That agreement is a result rather than a construction: this
  // module reads nothing from that one.
  if list && let Some(start) = value_position(value, at) {
    if value.get(start) == Some(&b'"') {
      let shut = scan_quoted(value, start.saturating_add(1));
      // Whether the element this string stands in DERIVES, which is what
      // `Regime::Forced` asks beyond the position. `( token / quoted-string )`
      // is one alternative taken WHOLE, so a string that never closes, or one
      // with bytes behind its close that §5.6.1.2 does not admit there, leaves
      // the element deriving nothing — and a recipient reading those bytes as
      // this parameter's data is then taking one reading of a run rather than
      // following the grammar.
      let derives = matches!(shut, Quoted::Closed(end) if boundary(value, end).is_some());
      if open_at(value, start, probe) && (matches!(regime, Regime::Every) || derives) {
        return true;
      }
      if let Quoted::Closed(end) = shut {
        match boundary(value, end) {
          None => {}
          Some(Edge::Ends) => derived = true,
          Some(Edge::Next(next)) => {
            derived = true;
            hit |= covers(value, here.next(next, list), regime, probe, seen);
          }
        }
      }
    } else if let Some(end) = token_end(value, start) {
      match boundary(value, end) {
        None => {}
        Some(Edge::Ends) => derived = true,
        Some(Edge::Next(next)) => {
          derived = true;
          hit |= covers(value, here.next(next, list), regime, probe, seen);
        }
      }
    }
  }

  // `Regime::Forced` stops here whatever the element did: every reading below
  // this line is one a recipient CHOOSES, which is the half [`forced`] drops.
  if matches!(regime, Regime::Forced) || !(faulted || !derived) {
    return hit;
  }

  // Behind a fault. The DQUOTE §11.2 admits a value at is a choice: one reading
  // opens the string there, and one leaves it shut and reads the element to the
  // next comma raw.
  if list
    && let Some(start) = value_position(value, at)
    && value.get(start) == Some(&b'"')
  {
    if open_at(value, start, probe) {
      return true;
    }
    // The reading that opened it, past the close: what is left of the element
    // holds no value position of its own, so it runs to the next raw comma.
    if let Quoted::Closed(end) = scan_quoted(value, start.saturating_add(1)) {
      hit |= resume(value, raw_comma_end(value, end), list, regime, probe, seen);
    }
  }
  // And the reading that opens nothing at all.
  hit |= resume(value, raw_comma_end(value, at), list, regime, probe, seen);
  hit
}

/// The element start behind the comma at `end`, walked from there.
///
/// The end of `value` is no comma and opens no element, so a run that reaches
/// it ends the reading.
///
/// Reached only from the free regime, so [`Regime::Forced`] never gets here and
/// the regime is passed on rather than taken: [`covers`] is one walk, and a
/// second entrance that hard-coded a regime would be a second rule.
///
/// # The channel a fault reaches through, which is the `list` and nothing else
///
/// ```text
/// #element   => [ element ] *( OWS "," OWS [ element ] )
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// `faulted` is what puts the elements behind here into the free regime, and
/// the free regime buys exactly one thing: at an element §11.2 admits a value
/// position in, the DQUOTE standing there is one a reading may open and a
/// reading may leave shut. §11.2 admits a value position only inside a
/// `#auth-param` list — `auth-param` is what the production names, and a list is
/// the only place one occurs — so **an element reached with no list open has no
/// value position, no DQUOTE a reading may choose, and nothing the free regime
/// can do that the grammar does not already do.**
///
/// So the fault propagates `list` rather than `true`. A fault met where a list
/// is open reaches forward through that list's own possible open string, and
/// that is `Basic a=1, Broken;junk, Bearer, x="open, Digest realm=z` — the list
/// `Basic` opened may still be running at `x`, so the comma inside `x`'s value
/// is one the readings disagree about. A fault met where none is open reaches
/// nothing: `Broken;junk, Safe, Basic a=1, a=2, Bearer abc, x="open, Digest
/// realm=z` has no list at `Broken;junk` for a string to belong to, so the
/// elements behind it are read exactly as they are without it — and the `Basic`
/// list that opens later is a list this fault never stood in.
///
/// Setting `true` here regardless is how a fault at the head of a value reached
/// forward into a list opened three elements behind it and excused a `Digest`
/// no reading of these bytes holds inside a value. An oracle that carries the
/// module's own defect cannot grade the module for it, and this one did: the
/// hiding zero-target could not see this witness because THIS line excused
/// it.
fn resume(
  value: &[u8],
  end: usize,
  list: bool,
  regime: Regime,
  probe: usize,
  seen: &mut HashSet<Position>,
) -> bool {
  match value.get(end) {
    Some(&b',') => covers(
      value,
      Position {
        at: skip_ows(value, end.saturating_add(1)),
        start: Start::Element,
        list,
        faulted: list,
      },
      regime,
      probe,
      seen,
    ),
    _ => false,
  }
}

/// Whether the RFC 9110 §5.6.4 quoted-string opening at `quote` still HOLDS
/// `probe` — whether the reading that opened it has the probe among the bytes
/// the sender wrote as that value's data.
///
/// The scan is taken over `value` cut at `probe`, so what it reports is the
/// state the string is in THERE, and two of [`Quoted`]'s three states hold it.
///
/// - [`Quoted::Open`], escape pending or not. The string reaches the probe.
/// - [`Quoted::Closed`], and it does not: that reading stands outside the
///   string at the probe exactly as the reading that never opened one does.
/// - [`Quoted::Invalid`], and it DOES. A byte §5.6.4 forbids means no
///   `quoted-string` derives over those bytes, so the string reaches no close
///   at all — and a reading that opened it therefore holds every byte behind
///   the DQUOTE, the probe included. It is not a `quoted-string`; it is a run
///   the sender wrote between an opening DQUOTE and nothing, and a recipient
///   that cuts a challenge out of it is reading that challenge out of a value's
///   interior.
///
/// **The third state is the one this collapsed**, and collapsing it is what
/// left `Basic x="<%x01>, Digest realm=z` graded `yields-underivable` while the
/// reader handed a caller a `Digest` built from bytes behind an admitted
/// opening DQUOTE. `http_semantics::grammar`'s own `Readings::absorb` had
/// already ruled the other way for RFC 9110 §5.6.6's `parameters`, and this
/// function is where the two derivations of [`excused`](Verdict::excused) BOTH
/// took the reader's answer — which is why the differential over them was zero
/// across the whole corpus while the defect stood.
///
/// One byte standing BEHIND the probe still decides nothing here: what the
/// sender wrote between the DQUOTE and the probe is `qdtext` either way, and a
/// reader that cut it in half read a challenge out of a value's interior.
pub(crate) fn open_at(value: &[u8], quote: usize, probe: usize) -> bool {
  quote < probe
    && !matches!(
      scan_quoted(
        value.get(..probe).unwrap_or_default(),
        quote.saturating_add(1)
      ),
      Quoted::Closed(_)
    )
}

/// Where the run at `at` ends when no quoted-string is opened in it: the first
/// comma, read raw, or the end of `value`.
pub(crate) fn raw_comma_end(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while !matches!(value.get(at), None | Some(&b',')) {
    at = at.saturating_add(1);
  }
  at
}

/// Where the element that ends at `end` leaves the list, or `None` when bytes
/// the element cannot hold stand behind it.
///
/// RFC 9110 §5.6.1.2 puts `OWS` on both sides of the comma, so the whitespace
/// in front of it is the LIST's rather than the element's and is skipped here
/// and not by whatever read the element.
pub(crate) fn boundary(value: &[u8], end: usize) -> Option<Edge> {
  let at = skip_ows(value, end);
  match value.get(at) {
    None => Some(Edge::Ends),
    Some(&b',') => Some(Edge::Next(skip_ows(value, at.saturating_add(1)))),
    Some(_) => None,
  }
}

/// The name, lowercased. RFC 9110 §11.2's name token "is matched
/// case-insensitively", and the MUST above is checked under that fold.
fn folded(value: &[u8], (start, end): (usize, usize)) -> Vec<u8> {
  value
    .get(start..end)
    .unwrap_or_default()
    .to_ascii_lowercase()
}

/// RFC 9110 §5.6.2's `tchar`.
///
/// ```text
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///  "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
/// ```
fn is_tchar(byte: u8) -> bool {
  byte.is_ascii_alphanumeric()
    || matches!(
      byte,
      b'!'
        | b'#'
        | b'$'
        | b'%'
        | b'&'
        | b'\''
        | b'*'
        | b'+'
        | b'-'
        | b'.'
        | b'^'
        | b'_'
        | b'`'
        | b'|'
        | b'~'
    )
}

/// The end of the `token` starting at `at`, or `None` when there is not one.
pub(crate) fn token_end(value: &[u8], at: usize) -> Option<usize> {
  let mut end = at;
  while value.get(end).is_some_and(|&byte| is_tchar(byte)) {
    end = end.saturating_add(1);
  }
  (end > at).then_some(end)
}

/// The end of RFC 9110 §11.2's `token68` starting at `at`, or `None`.
///
/// ```text
/// token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
/// ```
pub(crate) fn token68_end(value: &[u8], at: usize) -> Option<usize> {
  let mut end = at;
  while value.get(end).is_some_and(|&byte| {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
  }) {
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

/// Past RFC 9110 §5.6.3's `OWS` — `*( SP / HTAB )` — from `at`.
pub(crate) fn skip_ows(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while matches!(value.get(at), Some(&b' ') | Some(&b'\t')) {
    at = at.saturating_add(1);
  }
  at
}

/// Past the `1*SP` that admits a challenge's body.
pub(crate) fn skip_sp(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while value.get(at) == Some(&b' ') {
    at = at.saturating_add(1);
  }
  at
}

/// How a §5.6.4 quoted-string scan ended.
pub(crate) enum Quoted {
  /// The closing DQUOTE was found; the value ends at this offset.
  Closed(usize),
  /// The input ran out first.
  Open,
  /// A byte the grammar forbids stood inside it.
  Invalid,
}

/// Scans the interior of a RFC 9110 §5.6.4 quoted-string from `at`.
///
/// ```text
/// quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
/// qdtext        = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
/// quoted-pair   = "\" ( HTAB / SP / VCHAR / obs-text )
/// ```
pub(crate) fn scan_quoted(value: &[u8], at: usize) -> Quoted {
  let mut at = at;
  let mut escape = false;
  loop {
    let Some(&byte) = value.get(at) else {
      return Quoted::Open;
    };
    at = at.saturating_add(1);
    let vchar_or_obs_text = matches!(byte, 0x21..=0x7E | 0x80..=0xFF);
    if escape {
      if !(byte == b'\t' || byte == b' ' || vchar_or_obs_text) {
        return Quoted::Invalid;
      }
      escape = false;
      continue;
    }
    match byte {
      b'"' => return Quoted::Closed(at),
      b'\\' => escape = true,
      _ if byte == b'\t' || byte == b' ' || vchar_or_obs_text => {}
      _ => return Quoted::Invalid,
    }
  }
}
