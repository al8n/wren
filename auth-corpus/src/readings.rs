//! A second derivation of the one fact `oracle::Verdict::excused` turns on:
//! **does some reading of the value hold the probe inside an RFC 9110 §5.6.4
//! quoted-string?**
//!
//! ```text
//! #element      => [ element ] *( OWS "," OWS [ element ] )
//! challenge     = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
//! auth-param    = token BWS "=" BWS ( token / quoted-string )
//! quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
//! ```
//!
//! # Why a second one
//!
//! `excused` decides `hider-excused` against `over-yield`, so a defect it
//! shares with the reader is invisible in the answer column, in the axis column
//! and in every zero-target at once. That is not hypothetical: a witness
//! turned up that the hiding zero-target could not see, and the reason was
//! that `oracle::resume` carried the reader's own defect. It was caught by a
//! measurement taken BEFORE a fix, not by a gate.
//!
//! Every other verdict in this crate has something to disagree with it.
//! `excused` had nothing. This is that something.
//!
//! # What the two derivations share, and what they do not
//!
//! **Shared, deliberately: one transcription per production.** `token_end`,
//! `token68_end`, `skip_ows`, `skip_sp`, `scan_quoted`, `value_position`,
//! `boundary` and `raw_comma_end` are read from `oracle`(crate::oracle) rather
//! than written again. Two transcriptions of one rule, each tested from the
//! reading that produced it, is the shape al8n/wren#76 was filed over and the
//! shape `coding-corpus` exists to prevent: it doubles the places one typo can
//! live and halves the chance either copy is read again.
//!
//! **Not shared: the composition.** Which readings a recipient HAS, and how
//! they compose, is written here from §11.6.1 by a different route — and every
//! defect this branch found in the oracle lived in the composition rather than
//! in a production:
//!
//! | oracle's composition | here |
//! |---|---|
//! | a recursive descent that stops at `at > probe` | a forward closure that never sees the probe |
//! | short-circuits `true` inside the walk | computes the SET of offsets a string may open at, then asks |
//! | a `faulted` flag propagated by `resume` | no fault regime at all — see below |
//! | a `Start` tag telling a body's first element from the outer list's | the body's first element handled where it occurs |
//! | a `Regime` selecting which readings count | one enumeration; `forced` is not this function's question |
//! | memo key `(at, start, list, faulted)` | memo key `(at, list)` |
//! | the bare scheme read only where NO `1*SP` stands behind it | read either way |
//!
//! # The last row of that table is a divergence, and it is equivalent
//!
//! `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`. The optional
//! group needs a body, so a run of SP with nothing derivable behind it is
//! §5.6.1.2's own `OWS` in front of the comma and the challenge is the bare
//! scheme — `Basic<SP>, Digest realm=z` is two challenges, and the module under
//! test yields exactly those two. **This file's wording is the right one**, and
//! `element` reads the bare scheme whether or not a SP stands there;
//! `oracle::covers` reads it only in its no-SP arm.
//!
//! The two answer alike anyway, and the reason is one fact about the two
//! whitespace productions rather than an accident:
//!
//! 1. §5.6.3's `OWS` is `*( SP / HTAB )` and §11.3's opener is `1*SP`, so
//!    `skip_sp(v, scheme_end)` lands INSIDE the run `skip_ows(v, scheme_end)`
//!    crosses, and both end at the same offset. Hence
//!    `boundary(v, scheme_end) == boundary(v, body)` — the bare scheme's edge
//!    and the body's first element's edge are the SAME edge.
//! 2. So the extra reading fires exactly when `step(boundary(value, body), …,
//!    true, …)` fires, and pushes the same offset with `list` false where that
//!    one pushed it true. It can never set `derived` where the body branch has
//!    not already set it, so it suppresses no crossing either.
//! 3. And a state that differs only by `list` being false contributes no
//!    opener the `list`-true state does not. The one way it could is that a
//!    `list`-false state crosses where a `list`-true state derives — but the
//!    crossing then runs to a raw comma INSIDE a `quoted-string` that closes,
//!    and no opener can be recorded there: `scan_quoted` reaching that close
//!    means every DQUOTE between is a `quoted-pair`, preceded by a backslash,
//!    while a value position is preceded by `=` or `BWS`. Every exit from
//!    inside the string lands on the element boundary the derived reading
//!    already reached.
//!
//! **Searched as well as argued**: `openable` compared against a build with the
//! reading confined to the no-SP arm, over every string of length 1..=9 over
//! this crate's own eight-byte alphabet — 153 391 688 values — and over six
//! prefixes that force the divergence at the first element crossed with every
//! suffix of length 1..=7, 14 380 464 values, comparing `oracle::covered` and
//! `readings::covered` at every offset of each. Zero differences.
//! `a_bare_scheme_a_1_sp_stands_behind_is_a_reading_both_walks_reach` keeps a
//! handful of those values as a gate. What falls outside the search is any
//! shape needing a byte the alphabet omits — a `token68`-only character such as
//! `/` or `+`, or an `obs-text` byte — or more than nine bytes of structure
//! outside the six prefixes; the argument above is what covers those.
//!
//! # The fault regime is one rule, and the differential is what proved it
//!
//! `oracle::covers` carries a `faulted` flag. This walk carries the same one,
//! under the name `free`, and it is the one thing the two derivations could not
//! be made independent about. Two drafts tried and the differential refused
//! both **before either could ship**, which is the most useful thing it has
//! done:
//!
//! - **Draft one had no flag at all**, on the argument that the freedom is
//!   local: an element no reading derives ends at the first raw comma and
//!   leaves the list as it stood, so `Epoch::reaches_past_itself` would fall
//!   out rather than be written. The differential answered with **1 632 offsets**, and
//!   `Basic a="x`, then `j`, then a line opening at the element `trap=` whose
//!   string never closes and carrying the probe behind it, is the shape.
//!   `a="x` derives nothing, so the list §11.3's `1*SP` opened is still open
//!   behind it; `j` on the next line DERIVES, as a bare `auth-scheme`, so a
//!   local rule had it CLOSE that list — leaving `trap=`'s DQUOTE at no value
//!   position and the probe excused by nothing. Behind an element that derives nothing there
//!   is a reading in which every element since is garbage the open list still
//!   holds, and that reading has the list open behind a bare `auth-scheme` and
//!   behind a `token68` too. An element that derives in isolation is garbage
//!   all the same once the value has stopped deriving in front of it.
//! - **Draft two made the regime a second closure** seeded from the element
//!   starts the first got stuck at, so that the flag became a seed set. The
//!   differential answered with **1 020 offsets** in the other direction, and
//!   the shape was the same witness:
//!   `Broken;junk, Basic p1=1, …, p17=17, Bearer, x="open, Digest realm=z`.
//!   A seed set says WHERE freedom starts and cannot say where it stops, so a
//!   list-free fault at the head of the value reached forward into a list
//!   opened three elements behind it — the same defect this very oracle
//!   carried, independently rebuilt from scratch by someone who had read the
//!   fix.
//!
//! So freedom is a fact about a POSITION and it both starts and stops: it
//! starts where no reading derives, and it reaches forward only through the
//! `#auth-param` list that position stood in. That is one rule and there is one
//! way to state it. **This file states it once, and so does `oracle::resume`,
//! and the two agreeing about it is not evidence.** Everything else the two
//! compose out of is independent, and that is where all four oracle defects on
//! this branch lived.

use std::collections::BTreeSet;

use crate::oracle::{
  Edge, Quoted, boundary, open_at, raw_comma_end, scan_quoted, skip_ows, skip_sp, token_end,
  token68_end, value_position,
};

/// Whether some reading of `value` holds `probe` inside a §5.6.4
/// quoted-string.
///
/// Two steps, and separating them is the point: [`openable`] says WHERE a
/// reading may open a string, with no idea that a probe exists, and this asks
/// whether one of those strings is still open at the probe. `oracle::covers`
/// fuses the two — it cuts its own search off at the probe and returns the
/// moment it finds a covering string — so its structure and its answer are one
/// line and neither can be inspected without the other.
pub fn covered(value: &[u8], probe: usize) -> bool {
  openable(value)
    .iter()
    .any(|&quote| open_at(value, quote, probe))
}

/// Every offset at which some reading of `value` OPENS a §5.6.4 quoted-string.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// §11.2 names one value position per `auth-param`, and §5.6.2's `tchar` and
/// §11.2's `token68` alphabet both exclude DQUOTE, so a string may open at that
/// position and nowhere else. The set is therefore the value positions the
/// readings of this value reach, filtered to the ones holding a DQUOTE.
///
/// Probe-free by construction, and a SET rather than a boolean: a caller asks
/// about an offset afterwards, so this cannot cut its own search short on one,
/// and what it found can be printed.
pub fn openable(value: &[u8]) -> BTreeSet<usize> {
  walk(value).0
}

/// Every offset at which some reading of `value` begins an element of the OUTER
/// RFC 9110 §5.6.1.2 `#challenge` list.
///
/// ```text
/// #element  => [ element ] *( OWS "," OWS [ element ] )
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// The second derivation of the fact `oracle::starts_an_element` answers, and
/// it is reached the other way round: that one reads §5.6.1.2 at ONE offset —
/// the value's first byte, or the far side of a comma with the `OWS` that comma
/// carries behind it — and this one is the set of offsets the walk of every
/// reading actually stands at. A position no reading reaches is one no
/// challenge can stand at, and a local rule cannot see that.
///
/// The body position §11.3's `1*SP` opens is NOT in the set, and that is the
/// distinction both derivations exist for: [`element`] passes it to
/// [`parameter`], [`token68_end`] and [`cross`] as an offset, and pushes only
/// what stands BEHIND it as a state. `oracle::covers` carries the same fact as
/// its `Start` and reaches it a third way.
pub fn element_starts(value: &[u8]) -> BTreeSet<usize> {
  walk(value).1
}

/// The one walk both answers are taken from: where a string may open, and where
/// an element of the outer list may begin.
///
/// The two are one walk because they are one derivation asked two questions.
/// What they are held against are `oracle::covers` and
/// `oracle::starts_an_element`, which are two compositions of the OTHER
/// derivation.
fn walk(value: &[u8]) -> (BTreeSet<usize>, BTreeSet<usize>) {
  let mut opens = BTreeSet::new();
  let mut seen: BTreeSet<State> = BTreeSet::new();
  let mut starts: BTreeSet<usize> = BTreeSet::new();
  // The head of the value: its first element, with no `#auth-param` list open
  // and nothing faulted in front of it.
  let mut work = vec![State {
    at: 0,
    list: false,
    free: false,
  }];
  while let Some(state) = work.pop() {
    if !seen.insert(state) {
      continue;
    }
    starts.insert(state.at);
    element(value, state, &mut opens, &mut work);
  }
  (opens, starts)
}

/// One element start a reading of the value stands at.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct State {
  /// The offset, which every reading in hand stands OUTSIDE a string at.
  at: usize,
  /// Whether a challenge's `#auth-param` list is open here — the whole of what
  /// RFC 9110 §11.6.1's ambiguity needs remembered, since which readings an
  /// element has is otherwise decided by its own bytes.
  list: bool,
  /// Whether an element start in front of this one is one no reading derives,
  /// so that the elements here may be garbage the open list still holds.
  ///
  /// The module doc carries why this cannot be dropped and what the two
  /// attempts to drop it cost.
  free: bool,
}

/// Every reading of the one §5.6.1.2 element beginning at `at`, and where each
/// leaves the walk.
fn element(value: &[u8], here: State, opens: &mut BTreeSet<usize>, work: &mut Vec<State>) {
  let State { at, list, free } = here;
  // Whether ANY reading of the grammar derives this element. An element that
  // derives is not garbage inside somebody's list — until something in front of
  // it has already stopped deriving, which is what `free` says.
  let mut derived = false;

  // §5.6.1.2's empty element: "A recipient MUST parse and ignore a reasonable
  // number of empty list elements".
  derived |= step(boundary(value, at), here, list, work);

  // The element read as a whole `challenge`.
  if let Some(scheme_end) = token_end(value, at) {
    if value.get(scheme_end) == Some(&b' ') {
      let body = skip_sp(value, scheme_end);
      // Whether any reading derives the body's FIRST element, which is the whole
      // of what the challenge reading of this outer element turns on: the two
      // share one boundary, so the outer element derives exactly where that
      // first element does.
      let mut entered = false;
      // §11.2's `token68`, which is no list.
      if let Some(end) = token68_end(value, body) {
        entered |= step(boundary(value, end), here, false, work);
      }
      // And `#auth-param`, whose FIRST element is the body itself — an element
      // start inside this outer one, where §11.6.1 puts no second challenge.
      // Its own successors are the outer list's, with that list now open.
      entered |= parameter(value, body, here, opens, work);
      // Including when that first element is EMPTY. `#auth-param` carries
      // neither bound of §5.6.1's `<n>#<m>element`, so the empty list derives —
      // and a challenge whose `1*SP` was taken has ENTERED a body, so the list
      // it opened is open behind it even though it holds nothing.
      // `Basic<SP>, a=", Digest realm=z` is the value that says so: `a`'s
      // DQUOTE stands at a value position of the list `Basic<SP>` opened, and a
      // reading that had `Basic<SP>` close its list instead puts the probe
      // outside every string.
      entered |= step(boundary(value, body), here, true, work);
      // And where NOTHING derives the body's first element, the recipient that
      // took the `1*SP` is standing inside the list §11.3's `1*SP` opened, with
      // its first element the thing that failed. The elements behind it may be
      // more parameters of THAT list, whatever stood in front of the challenge
      // — `Basic<SP><HTAB>a, a=", Digest realm=z` is the value that tells this
      // apart from a fault standing in front of a list that never opened.
      if !entered {
        cross(value, body, true, work);
      }
      derived |= entered;
    }
    // The bare scheme, whose body was never entered, so no list is open behind
    // it. Read whether or not a SP stands there: `challenge = auth-scheme
    // [ 1*SP ( token68 / #auth-param ) ]` needs a body for the optional group,
    // so a run of SP with nothing derivable behind it is §5.6.1.2's own `OWS` in
    // front of the comma and the challenge is the bare scheme.
    derived |= step(boundary(value, scheme_end), here, false, work);
  }

  // The element read as one more `auth-param` of the list already open.
  if list {
    derived |= parameter(value, at, here, opens, work);
  }

  // And the element read as garbage: a run the grammar derives no part of,
  // crossed to the first comma no opened string holds. Available where nothing
  // derives THIS element, and behind a fault where nothing derived an element
  // in front of it either.
  if free || !derived {
    cross(value, at, list, work);
  }
}

/// The element at `at` read as RFC 9110 §11.2's `auth-param`, with the list its
/// successors inherit open.
///
/// Returns whether that reading DERIVES the element — which is
/// `( token / quoted-string )` taken WHOLE, so a value with bytes behind it
/// derives nothing and a string that never closes derives nothing either.
///
/// The DQUOTE standing at the value position is recorded whether or not the
/// element goes on to derive, and that is what `excused` is asked over: the
/// question is about the POSITION §11.2 admits a string at, not about a
/// derivation that reaches past it. `oracle::Verdict::excused`'s doc carries
/// the correction al8n/wren#77 forced, and this is the same rule reached from
/// the other side.
fn parameter(
  value: &[u8],
  at: usize,
  here: State,
  opens: &mut BTreeSet<usize>,
  work: &mut Vec<State>,
) -> bool {
  let Some(start) = value_position(value, at) else {
    return false;
  };
  if value.get(start) != Some(&b'"') {
    return match token_end(value, start) {
      Some(end) => step(boundary(value, end), here, true, work),
      None => false,
    };
  }
  opens.insert(start);
  let Quoted::Closed(end) = scan_quoted(value, start.saturating_add(1)) else {
    // Nothing closes it, so the reading that opened it holds every byte behind
    // it and reaches no further element start at all.
    return false;
  };
  if step(boundary(value, end), here, true, work) {
    return true;
  }
  // The string closed and the element ran on past that close, so no
  // `auth-param` derives it — but the reading that opened the string is still a
  // reading, and what is left of the element holds no value position of its
  // own. It runs to the next raw comma like any other underived run.
  cross(value, end, true, work);
  false
}

/// Where a reading that ended an element at some offset leaves the walk, and
/// whether it ended one at all.
///
/// `free` is inherited rather than recomputed: a reading that derives this
/// element does not un-fault what stands in front of it.
fn step(edge: Option<Edge>, here: State, list: bool, work: &mut Vec<State>) -> bool {
  match edge {
    // Bytes §5.6.1.2 does not admit behind the element, so this reading did not
    // end an element here and derives nothing.
    None => false,
    // The value ends, so the reading is whole and there is nothing behind it.
    Some(Edge::Ends) => true,
    Some(Edge::Next(next)) => {
      work.push(State {
        at: next,
        list,
        free: here.free,
      });
      true
    }
  }
}

/// Where a run the grammar derives no part of leaves the walk: the first comma
/// no opened string holds, which is the raw one.
///
/// **`free` behind the crossing is `list` and never `true`**, and that is
/// `Epoch::reaches_past_itself`'s channel rule: the free regime buys exactly
/// one thing, a DQUOTE at a §11.2
/// value position that a reading may open and a reading may leave shut, and
/// §11.2 admits a value position only inside a `#auth-param` list. So a run
/// crossed with no list open reaches nothing the grammar does not already
/// reach. Spelling it `true` is how a fault at the head of a value reached
/// forward into a list opened three elements behind it, the same defect found
/// in `oracle::resume` — and which a draft of this file rebuilt from scratch,
/// so the module doc says plainly that the two agreeing here is not
/// evidence.
fn cross(value: &[u8], at: usize, list: bool, work: &mut Vec<State>) {
  let end = raw_comma_end(value, at);
  if value.get(end) == Some(&b',') {
    work.push(State {
      at: skip_ows(value, end.saturating_add(1)),
      list,
      free: list,
    });
  }
}
