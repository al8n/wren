//! An independent reading of the two `parameter` productions and the three
//! list elements built out of them, written from RFC 9110's grammar rather
//! than from any of the three walks this corpus grades.
//!
//! # What it is for
//!
//! The differential's first question is whether two readers of one production
//! answer alike. Its second is whether they are allowed to be wrong TOGETHER,
//! and only a derivation written from the RFC can answer that. This module is
//! that derivation. It shares no code with `http_semantics::grammar` or with
//! `http1-proto`'s `Transfer-Encoding` accumulator; if it agreed with either by
//! construction it would grade nothing.
//!
//! # The productions
//!
//! The list construct, RFC 9110 §5.6.1.2, is the same for all three:
//!
//! ```text
//! #element => [ element ] *( OWS "," OWS [ element ] )
//! ```
//!
//! RFC 9110 §5.6.3's whitespace, cited on every `OWS` and `BWS` below:
//!
//! ```text
//! OWS            = *( SP / HTAB )
//! RWS            = 1*( SP / HTAB )
//! BWS            = OWS
//! ```
//!
//! RFC 9110 §5.6.2's `token` and §5.6.4's `quoted-string`, which every element
//! here is ultimately built out of:
//!
//! ```text
//! token          = 1*tchar
//! quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
//! qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
//! quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
//! ```
//!
//! Then one element rule per [`Production`], each carried WHOLE — its container
//! and its inner rule both, because half of what separates them lives in the
//! container and issue #75 records what an omitted container cost. RFC 9110
//! §10.1.4, the element of RFC 9112 §7's `Transfer-Encoding = #transfer-coding`:
//!
//! ```text
//! transfer-coding    = token *( OWS ";" OWS transfer-parameter )
//! transfer-parameter = token BWS "=" BWS ( token / quoted-string )
//! ```
//!
//! And RFC 9110 §10.1.4's OTHER container over that same element, which is the
//! whole of the field it is written in:
//!
//! ```text
//! TE                 = #t-codings
//! t-codings          = "trailers" / ( transfer-coding [ weight ] )
//! transfer-coding    = token *( OWS ";" OWS transfer-parameter )
//! transfer-parameter = token BWS "=" BWS ( token / quoted-string )
//! ```
//!
//! with RFC 9110 §12.4.2's weight, whose `qvalue` this module has to spell
//! because the ambiguity below turns on it:
//!
//! ```text
//! weight = OWS ";" OWS "q=" qvalue
//! qvalue = ( "0" [ "." 0*3DIGIT ] )
//!        / ( "1" [ "." 0*3("0") ] )
//! ```
//!
//! RFC 9110 §5.6.6, whose `parameters` has no head of its own and takes one
//! from whatever rule concatenates it — §5.6.2's `token`, for the walk this
//! grades:
//!
//! ```text
//! parameters      = *( OWS ";" OWS [ parameter ] )
//! parameter       = parameter-name "=" parameter-value
//! parameter-name  = token
//! parameter-value = ( token / quoted-string )
//! ```
//!
//! And RFC 9110 §10.1.1, which extends that same `parameters` with a head of
//! its own — note WHERE the bracket closes:
//!
//! ```text
//! Expect =      #expectation
//! expectation = token [ "=" ( token / quoted-string ) parameters ]
//! ```
//!
//! And RFC 9110 §12.5.1, which concatenates that same `parameters` behind a
//! head that is not a token and behind NO bracket at all:
//!
//! ```text
//! Accept = #( media-range [ weight ] )
//!
//! media-range    = ( "*/*"
//!                    / ( type "/" "*" )
//!                    / ( type "/" subtype )
//!                  ) parameters
//! type           = token
//! subtype        = token
//! weight         = OWS ";" OWS "q=" qvalue
//! ```
//!
//! Two facts about that rule, both of which this module depends on.
//!
//! Its three alternatives collapse to `token "/" token` EXACTLY, and the
//! collapse is a fact about RFC 9110 §5.6.2 rather than a simplification: `*`
//! is a `tchar`, so the two wildcard spellings are already derived by the third
//! alternative. That is why the reader this grades spells its name grammar as a
//! token on each side of one solidus, and why this module can too.
//!
//! And `[ weight ]` adds no string to what `media-range` already derives, since
//! `parameters` repeats without bound and §12.4.2's `qvalue` is a `token`. It
//! is a rule about MEANING — "Recipients SHOULD process any parameter named "q"
//! as weight, regardless of parameter ordering" — so a `q` whose value is no
//! `qvalue` is refused by the reader and derived here, which is a difference
//! between two FIELDS and not between two readings of `parameters`. `main`
//! licenses it as its own axis, counted, for the reason it counts the three
//! differences between §10.1.4 and §5.6.6.
//!
//! # The three questions, and what each is asked ABOUT
//!
//! Issue #77 records an oracle that answered "no reading licenses this" about a
//! quoted-string that was, locally, perfectly admitted, because it asked
//! whether the WHOLE value derives and reported that answer about one offset
//! inside it. So each question below names its subject:
//!
//! - [`Reading::derives`] — some derivation of the **whole** value as
//!   `#element` exists. Asked of the whole value, reported about the whole
//!   value, and about nothing inside it.
//! - [`Reading::element_starts`] — the offsets at which some derivation of a
//!   **prefix** of the value begins a non-empty element. A prefix, not the
//!   whole value: an offset is licensed as a member's start by the bytes in
//!   FRONT of it, and what stands behind it is a different question.
//! - [`Reading::string_data`] — the offsets that lie strictly inside a §5.6.4
//!   `quoted-string` whose DQUOTE stands at a `parameter-value` position some
//!   prefix derivation admits. Also a question about the bytes in front, and
//!   the one that tells a member invented out of a value's own data apart from
//!   a member shown at an offset no reading reaches.
//! - [`Reading::member_params`] — the parameter names read by each derivation
//!   of an element at that offset which ENDS WHERE THE LIST ADMITS AN END.
//!   The one question here about the bytes BEHIND an offset, and the only one
//!   that can be: an extent is where a member stops, and nothing in front of a
//!   member says where it stops.
//!
//! # Why the fourth question can be answered EXACTLY, and not as a bound
//!
//! `element_ends` reports a SET of ends because how many repetitions of the
//! parameter rule an element took is genuinely ambiguous. Filtered to the ends
//! the LIST admits, that set has at most one member, and the argument is one
//! line of §5.6.1.2: every step this walk takes past an end requires a
//! particular byte to stand at it — `;` for a repetition of the parameter rule,
//! `=` for §10.1.1's argument — and [`boundary`] admits an end only where the
//! next non-`OWS` byte is `,` or the value's end. An end the element continues
//! past is therefore an end the list does not admit, and the other way round,
//! so no two ends of one element are both boundaries.
//!
//! That is what makes an EXACT grading possible where a bound would be useless.
//! A bound that admitted any parameter sequence the grammar reaches is
//! satisfied by a walk that stopped one parameter early, which is the whole of
//! issue #79's defect class; it cannot tell a member that ended where the list
//! ends from one that ended in front of a `;` and threw the rest away.
//!
//! One production answers the fourth question with TWO sequences rather than
//! one, and that is the ambiguity issue #80 was filed over rather than a
//! failure of the argument above: the two readings share the element's single
//! boundary-ending END and disagree about what the bytes in front of it WERE.
//! See [`Production::TCodings`].
//!
//! # Where the OWS at the value's two ends is admitted, and why
//!
//! §5.6.1.2's expansion hangs every `OWS` it has on a comma, so it admits none
//! in front of the first element and none behind the last. RFC 9110 §5.5 is
//! what admits them, one level up: "A field value does not include leading or
//! trailing whitespace." What reaches a field's walk has therefore already had
//! both ends removed, and grading a value that still carries them against
//! §5.6.1.2 alone would report a divergence about bytes no field value holds.
//! So the walk below starts past the leading `OWS` and ends past the trailing
//! one — the two ends §5.5 names, and nowhere else.
//!
//! # What it does NOT model
//!
//! No reader's own bounds, because none of the three has one over these
//! productions today. If one gains a parameter or member limit, it belongs in
//! the reader's grading and not here: a bound is the reader's refusal, not the
//! grammar's, and an oracle carrying one would be grading a module against
//! itself.

use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Which element production a value is read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Production {
  /// RFC 9110 §10.1.4's `transfer-coding` — the element of RFC 9112 §7's
  /// `Transfer-Encoding = #transfer-coding`, and what `TE` names too.
  TransferCoding,
  /// RFC 9110 §5.6.6's `parameters` behind a §5.6.2 `token` head, which is the
  /// member `http_semantics::grammar::parameterised_list` reads under
  /// `ParamSyntax::Parameter`.
  TokenParameters,
  /// RFC 9110 §10.1.1's `expectation`.
  Expectation,
  /// RFC 9110 §10.1.4's `t-codings` — the element of the `TE` field, which is
  /// `transfer-coding` with §12.4.2's `[ weight ]` behind it and the literal
  /// `"trailers"` beside it.
  ///
  /// **It derives exactly the strings [`TransferCoding`](Self::TransferCoding)
  /// does**, and both halves of that are facts about RFC 9110 §5.6.2's `token`
  /// rather than simplifications. `"trailers"` is spelled by `token`, so the
  /// first alternative adds no string the second does not already derive. And
  /// every `weight` is spelled by `OWS ";" OWS transfer-parameter`: `"q="` is a
  /// `token` and an `=`, and every §12.4.2 `qvalue` is DIGIT and `.`, both of
  /// which §5.6.2 admits as `tchar`. So `derives`, `element_starts` and
  /// `string_data` are `TransferCoding`'s, byte for byte.
  ///
  /// **What is different is the fourth question, and only there.** Because the
  /// two alternatives derive one string, a member ending in a `q` that a
  /// `weight` derives has TWO parameter readings and one end: the `q` is the
  /// last `transfer-parameter`, or it is the `weight` and the member has one
  /// parameter fewer. [`Reading::member_params`] carries both, and this module
  /// picks neither — see its own doc for why nothing in RFC 9110 picks one.
  TCodings,
  /// RFC 9110 §12.5.1's `media-range` — the SAME §5.6.6 `parameters`, behind a
  /// `type "/" subtype` head and behind no bracket at all.
  ///
  /// The third head this corpus writes, and the one that makes the §5.6.6
  /// comparison askable about a list of more than one element: §10.1.1 puts its
  /// `parameters` inside a bracket and §12.5.1 does not, so a `media-range` has
  /// the shape [`TokenParameters`](Self::TokenParameters) has — `NAME
  /// parameters` — with the name grammar as the whole of the difference.
  MediaRange,
}

/// What the oracle says about one field value under one production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
  /// Some derivation of the WHOLE value as `#element` exists.
  pub derives: bool,
  /// Offsets at which some derivation of a PREFIX of the value begins a
  /// non-empty element.
  pub element_starts: BTreeSet<usize>,
  /// Offsets strictly inside a §5.6.4 `quoted-string` that opened at a
  /// `parameter-value` position some prefix derivation admits.
  pub string_data: BTreeSet<usize>,
  /// For each offset an element both begins at and ends the list at: every
  /// parameter-name sequence a derivation reaching that end reads, in order.
  ///
  /// The extent question, and the only one here asked about the bytes BEHIND an
  /// offset. An offset with no row is one no derivation of an element there
  /// carries all the way to a `,` or to the value's end.
  ///
  /// Normally one sequence, because at most one end of an element is a list
  /// boundary — the module doc carries that argument. Two under
  /// [`Production::TCodings`], where RFC 9110 §10.1.4's `[ weight ]` and its
  /// `*( OWS ";" OWS transfer-parameter )` reach the same end over the same
  /// bytes and disagree about what the last of them was.
  ///
  /// # What no clause of RFC 9110 settles
  ///
  /// A reader of `TE` has to decide whether the `q` in a member ending
  /// `;q=0.5` is that member's last `transfer-parameter` or its `weight`, and
  /// the ABNF derives it both ways. RFC 9110 settles it for `Accept` and for
  /// nothing else: §12.5.1 tells a recipient to "process any parameter named
  /// "q" as weight, regardless of parameter ordering", which is a rule about a
  /// PARAMETER's name and not about where the parameter section stops, and
  /// which §12.5.1's own note grounds in the media type registry — a registry
  /// that governs media types and not transfer codings. §12.4.2 calls the
  /// weight a "common parameter, named "q" (case-insensitive)" and says only
  /// what it means, not which rule derived it. §10.1.4 says nothing about it at
  /// all.
  ///
  /// So this module reports both readings and grades a reader against either.
  /// `main` records which one each reader took, so a `TE` reader added later is
  /// held to a reading somebody chose rather than inventing a third.
  pub member_params: BTreeMap<usize, Vec<Vec<ParamName>>>,
  /// For each of those same offsets: where the element's HEAD ends, and whether
  /// the derivation reaching the list boundary ends there too.
  ///
  /// The extent question asked of a reader that hands out no offsets. RFC 9110
  /// §10.1.1's `Expectations` is a fold over eight bits with no lifetime
  /// parameter — it borrows no field line and can hand over no subslice — so
  /// nothing it says can be `place`d. What it does say is whether some member
  /// parsed WHOLE as the bare `100-continue`, which is a statement about where
  /// that member ENDED, and this is what that is graded against.
  ///
  /// **When [`derives`](Self::derives) holds, these keys are exactly the
  /// members of the value's one derivation.** Each start has at most one end
  /// the list admits, so it has at most one successor, so the chain from the
  /// first start is unique and the reachable set is that chain. A start that
  /// reaches no boundary has no row here at all, which is the same fact from
  /// the other side.
  pub member_heads: BTreeMap<usize, MemberHead>,
}

/// Where one element's head ends, and whether the element does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberHead {
  /// One past the head's last byte — the `token` for RFC 9110 §10.1.4, §5.6.6
  /// and §10.1.1, and `type "/" subtype` for §12.5.1.
  pub end: usize,
  /// The derivation that reaches the list boundary ends AT the head, so the
  /// member is its head and nothing else.
  ///
  /// For RFC 9110 §10.1.1 this is the whole of what distinguishes the
  /// expectation the field defines from one it does not:
  ///
  /// ```text
  /// Expect      = #expectation
  /// expectation = token [ "=" ( token / quoted-string ) parameters ]
  /// ```
  ///
  /// The bracket is optional and holds everything behind the `token`, so a
  /// member that is its head and nothing else is the bare token, and a member
  /// that is not took the bracket.
  pub bare: bool,
}

/// One parameter name a derivation reads, as its offsets in the value RFC 9110
/// §5.2 joins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamName {
  /// Where the name's first byte is.
  pub at: usize,
  /// One past its last.
  pub end: usize,
  /// Whether the repetition this name heads is ALSO derived by RFC 9110
  /// §12.4.2's `weight`, taken as a fact about those bytes alone.
  ///
  /// ```text
  /// weight = OWS ";" OWS "q=" qvalue
  /// ```
  ///
  /// So: the name is `q`, case-insensitively, since RFC 5234 §2.3 makes a
  /// quoted ABNF literal case-insensitive and §12.4.2 says so again in prose;
  /// no `BWS` stands on either side of the `=`, because `weight` writes `"q="`
  /// as one literal and admits none; the value is a `token` rather than a
  /// §5.6.4 `quoted-string`, which `weight` has no alternative for; and its
  /// bytes are a `qvalue`.
  ///
  /// It says nothing about POSITION. Only a repetition standing last in its
  /// element can be the `[ weight ]` RFC 9110 §10.1.4 brackets behind
  /// `transfer-coding`, and [`read`] is what applies that.
  pub weight: bool,
}

impl Reading {
  /// Whether a member a reader began at `at` is one some derivation begins an
  /// element at.
  ///
  /// The question a manufactured member fails: `gzip;;x="a, chunked, b", br`
  /// read under [`Production::TokenParameters`] licenses the `br` behind the
  /// string, and read under [`Production::TransferCoding`] licenses nothing
  /// past `gzip`, because RFC 9110 §10.1.4 brackets no empty slot and so admits
  /// no `parameter-value` for that DQUOTE to stand at.
  pub fn licenses_member_at(&self, at: usize) -> bool {
    self.element_starts.contains(&at)
  }

  /// Whether `at` is one of the offsets some prefix derivation reads as a
  /// quoted-string's data.
  pub fn is_string_data(&self, at: usize) -> bool {
    self.string_data.contains(&at)
  }

  /// Every parameter-name sequence a derivation of the element at `at` that
  /// reaches a list boundary reads.
  ///
  /// Empty where no derivation of an element beginning there ends where the
  /// list admits an end — which is a different answer from "no element begins
  /// there", and the one a member whose extent is wrong earns.
  pub fn member_params(&self, at: usize) -> &[Vec<ParamName>] {
    match self.member_params.get(&at) {
      Some(readings) => readings,
      None => &[],
    }
  }

  /// Where the element at `at` ends its head, and whether it ends there.
  ///
  /// `None` where no derivation of an element beginning there reaches a list
  /// boundary — the same absence [`member_params`](Self::member_params) reports
  /// as an empty slice.
  pub fn member_head(&self, at: usize) -> Option<MemberHead> {
    self.member_heads.get(&at).copied()
  }
}

/// Reads `value` under `production` and answers the four questions.
pub fn read(value: &[u8], production: Production) -> Reading {
  let mut element_starts = BTreeSet::new();
  let mut string_data = BTreeSet::new();
  let mut member_params: BTreeMap<usize, Vec<Vec<ParamName>>> = BTreeMap::new();
  let mut member_heads: BTreeMap<usize, MemberHead> = BTreeMap::new();
  let mut derives = false;

  // §5.5 removes the field value's leading whitespace, so the list begins past
  // it; §5.6.1.2's own expansion admits none there.
  let first = skip_ows(value, 0);
  let mut seen: HashSet<usize> = HashSet::new();
  let mut queue = vec![first];
  seen.insert(first);

  while let Some(at) = queue.pop() {
    let mut ends = Vec::new();
    let mut chain = Vec::new();
    let head = element_ends(
      value,
      at,
      production,
      &mut ends,
      &mut chain,
      &mut string_data,
    );
    if !ends.is_empty() {
      element_starts.insert(at);
    }
    // The fourth question. An end the list admits is one this element does not
    // continue past, so at most one of them is here — the module doc carries
    // that argument, and it is what makes the answer exact.
    for &(end, taken) in &ends {
      if boundary(value, end).is_none() {
        continue;
      }
      if let Some(head_end) = head {
        member_heads.insert(
          at,
          MemberHead {
            end: head_end,
            bare: end == head_end,
          },
        );
      }
      let read = chain.get(..taken).unwrap_or_default().to_vec();
      let readings = member_params.entry(at).or_default();
      // RFC 9110 §10.1.4's `t-codings = "trailers" / ( transfer-coding
      // [ weight ] )`: the bracket sits behind the whole repetition, so only
      // the LAST parameter can be the `weight`, and when it is, the same end is
      // reached by an element carrying one parameter fewer.
      if production == Production::TCodings && read.last().is_some_and(|last| last.weight) {
        let shorter = read.get(..read.len().saturating_sub(1)).unwrap_or_default();
        readings.push(shorter.to_vec());
      }
      readings.push(read);
    }
    // The empty element §5.6.1.2 admits: `[ element ]` with nothing in it.
    // It contributes no element and ends nothing, so the boundary is asked at
    // the very offset the element would have started at.
    for end in std::iter::once(at).chain(ends.iter().map(|&(end, _)| end)) {
      match boundary(value, end) {
        Some(Edge::Ends) => derives = true,
        Some(Edge::Next(next)) if seen.insert(next) => queue.push(next),
        Some(Edge::Next(_)) => {}
        None => {}
      }
    }
  }

  Reading {
    derives,
    element_starts,
    string_data,
    member_params,
    member_heads,
  }
}

/// Where the element that ended at `end` leaves the list.
enum Edge {
  /// Nothing but the value's trailing whitespace stood behind it, so the value
  /// ends there.
  Ends,
  /// A comma stood behind it, and the next element starts here.
  Next(usize),
}

/// Where an element ending at `end` leaves the list, or `None` when bytes no
/// list construct admits stand behind it.
///
/// RFC 9110 §5.6.1.2 puts `OWS` on both sides of its comma, so the whitespace
/// in front of one belongs to the LIST rather than to whatever read the
/// element; the whitespace in front of the value's END belongs to neither and
/// is RFC 9110 §5.5's, as this module's own doc says.
fn boundary(value: &[u8], end: usize) -> Option<Edge> {
  let at = skip_ows(value, end);
  match value.get(at) {
    None => Some(Edge::Ends),
    Some(&b',') => Some(Edge::Next(skip_ows(value, at.saturating_add(1)))),
    Some(_) => None,
  }
}

/// Every offset an element starting at `at` may end at, appended to `ends`
/// beside the number of parameter names the derivation reaching it read, with
/// those names appended to `chain` and every quoted-string interior recorded in
/// `data`.
///
/// The alternatives inside an element are all decided by the next byte, so this
/// is a walk rather than a search: a `quoted-string` ends at the first
/// unescaped DQUOTE because §5.6.4's `qdtext` excludes DQUOTE, and a `token`
/// takes every `tchar` it can because a `tchar` left behind can begin none of
/// `OWS`, `";"`, `","` or the end of the value. What is genuinely ambiguous is
/// how MANY repetitions of the parameter rule the element took, which is why
/// this reports a set of ends rather than one.
///
/// **`chain` is one sequence and not one per end, and that is a property of the
/// walk rather than a compression.** Each step appends at most one parameter
/// name and never revisits one, so the names an end was reached through are
/// exactly `chain`'s first `taken` — which is what the `usize` beside each end
/// carries.
fn element_ends(
  value: &[u8],
  at: usize,
  production: Production,
  ends: &mut Vec<(usize, usize)>,
  chain: &mut Vec<ParamName>,
  data: &mut BTreeSet<usize>,
) -> Option<usize> {
  let head_end = head_end(value, at, production)?;
  let mut cursor = head_end;

  if production == Production::Expectation {
    // RFC 9110 §10.1.1's
    // `expectation = token [ "=" ( token / quoted-string ) parameters ]`: the
    // bracket closes AFTER `parameters`, so a member with parameters and no
    // argument is not an expectation, and the bare token is the only other
    // reading.
    ends.push((head_end, chain.len()));
    if value.get(head_end) != Some(&b'=') {
      return Some(head_end);
    }
    let Some(after) = argument_end(value, head_end.saturating_add(1), data) else {
      return Some(head_end);
    };
    ends.push((after, chain.len()));
    cursor = after;
  } else {
    // §10.1.4 and §5.6.6 both put the repetition outside any bracket the head
    // is in, so the head alone is an element under either.
    ends.push((head_end, chain.len()));
  }

  // The repetition: `*( OWS ";" OWS transfer-parameter )` for RFC 9110
  // §10.1.4, `*( OWS ";" OWS [ parameter ] )` for §5.6.6, for §10.1.1's tail
  // and for §12.5.1's `media-range`.
  loop {
    let semicolon = skip_ows(value, cursor);
    if value.get(semicolon) != Some(&b';') {
      return Some(head_end);
    }
    let slot = skip_ows(value, semicolon.saturating_add(1));
    let Some(name_end) = token_end(value, slot) else {
      // Only §5.6.6 brackets the slot. §10.1.4 does not, so a `;` that
      // introduces no `transfer-parameter` derives nothing.
      if is_transfer(production) {
        return Some(head_end);
      }
      cursor = semicolon.saturating_add(1);
      ends.push((cursor, chain.len()));
      continue;
    };
    // The `=`, with the BWS §10.1.4 admits on both sides of it and §5.6.6
    // admits on neither.
    let bws = is_transfer(production);
    let eq = if bws {
      skip_ows(value, name_end)
    } else {
      name_end
    };
    if value.get(eq) != Some(&b'=') {
      return Some(head_end);
    }
    let start = eq.saturating_add(1);
    let start = if bws { skip_ows(value, start) } else { start };
    let Some(after) = argument_end(value, start, data) else {
      return Some(head_end);
    };
    // Whether these bytes are ALSO RFC 9110 §12.4.2's
    // `weight = OWS ";" OWS "q=" qvalue`. See [`ParamName::weight`]; whether
    // the repetition stands where `[ weight ]` may be is [`read`]'s to say.
    let named_q = value
      .get(slot..name_end)
      .is_some_and(|name| name.eq_ignore_ascii_case(b"q"));
    let unspaced = eq == name_end && start == eq.saturating_add(1);
    let weight = named_q && unspaced && value.get(start..after).is_some_and(is_qvalue);
    chain.push(ParamName {
      at: slot,
      end: name_end,
      weight,
    });
    cursor = after;
    ends.push((cursor, chain.len()));
  }
}

/// Whether `production` reads its repetitions as RFC 9110 §10.1.4's
/// `transfer-parameter` — with the `BWS` around the `=` that rule admits, and
/// without the empty slot §5.6.6's brackets are the whole of.
///
/// Both containers §10.1.4 is written with, and no others: `#transfer-coding`
/// for RFC 9112 §7's `Transfer-Encoding`, and `#t-codings` for `TE`.
const fn is_transfer(production: Production) -> bool {
  matches!(
    production,
    Production::TransferCoding | Production::TCodings
  )
}

/// Whether `token` is RFC 9110 §12.4.2's `qvalue`.
///
/// ```text
/// qvalue = ( "0" [ "." 0*3DIGIT ] )
///        / ( "1" [ "." 0*3("0") ] )
/// ```
///
/// The fraction's length is bounded and its digits differ between the two
/// alternatives, so `1.5` is no `qvalue` and neither is `0.5000` — which is
/// what makes a `q` that cannot be a `weight` a shape this corpus can write.
fn is_qvalue(token: &[u8]) -> bool {
  let Some(&lead) = token.first() else {
    return false;
  };
  let rest = token.get(1..).unwrap_or_default();
  let zero = match lead {
    b'0' => true,
    b'1' => false,
    _ => return false,
  };
  if rest.is_empty() {
    return true;
  }
  let Some(fraction) = rest.strip_prefix(b".") else {
    return false;
  };
  fraction.len() <= 3
    && fraction.iter().all(|&byte| {
      if zero {
        byte.is_ascii_digit()
      } else {
        byte == b'0'
      }
    })
}

/// The end of the element's HEAD at `at` — the piece in front of the `;` every
/// one of these productions repeats.
///
/// RFC 9110 §10.1.4, §5.6.6-behind-a-token and §10.1.1 each head their element
/// with one §5.6.2 `token`; §12.5.1's `media-range` heads it with `type "/"
/// subtype`, which is a token on each side of ONE solidus. A second solidus
/// ends no token — `/` is not a `tchar` — so `a/b/c` heads nothing, which is
/// what the reader this grades says too.
///
/// §10.1.4's `t-codings` takes the same `token` head and needs no alternative
/// for the `"trailers"` it names beside `transfer-coding`: `token = 1*tchar`
/// spells those eight letters, so the literal derives nothing the head does not
/// already reach. What tells a `trailers` member apart is the FIELD's meaning
/// and not this grammar, which is why `main` counts it rather than deriving it.
fn head_end(value: &[u8], at: usize, production: Production) -> Option<usize> {
  let end = token_end(value, at)?;
  if production != Production::MediaRange {
    return Some(end);
  }
  if value.get(end) != Some(&b'/') {
    return None;
  }
  token_end(value, end.saturating_add(1))
}

/// The end of one `( token / quoted-string )` at `at`, recording the interior
/// of a quoted-string in `data`.
///
/// `None` where neither alternative derives — an unclosed string, a byte
/// §5.6.4 forbids inside one, or no `tchar` at all.
fn argument_end(value: &[u8], at: usize, data: &mut BTreeSet<usize>) -> Option<usize> {
  if value.get(at) != Some(&b'"') {
    return token_end(value, at);
  }
  match scan_quoted(value, at.saturating_add(1)) {
    Quoted::Closed(end) => {
      // Strictly inside: the two DQUOTEs are the string's own delimiters and
      // not its data.
      for offset in at.saturating_add(1)..end.saturating_sub(1) {
        data.insert(offset);
      }
      Some(end)
    }
    Quoted::Open => {
      // Nothing closes it, so this reading derives no element — and every byte
      // from here to the end of the value is inside the string it opened.
      for offset in at.saturating_add(1)..value.len() {
        data.insert(offset);
      }
      None
    }
    Quoted::Invalid => None,
  }
}

/// How a §5.6.4 quoted-string scan ended.
enum Quoted {
  /// The closing DQUOTE was found; the string ends at this offset.
  Closed(usize),
  /// The value ran out first.
  Open,
  /// A byte §5.6.4's `qdtext` / `quoted-pair` forbids stood inside it.
  Invalid,
}

/// Scans the interior of a RFC 9110 §5.6.4 `quoted-string` from `at`.
fn scan_quoted(value: &[u8], at: usize) -> Quoted {
  let mut at = at;
  let mut escaped = false;
  loop {
    let Some(&byte) = value.get(at) else {
      return Quoted::Open;
    };
    at = at.saturating_add(1);
    // VCHAR is %x21-7E; obs-text is %x80-FF. Together they are every byte a
    // `quoted-pair` may carry behind its backslash, and every `qdtext` byte
    // apart from DQUOTE and the backslash themselves.
    let vchar_or_obs_text = matches!(byte, 0x21..=0x7E | 0x80..=0xFF);
    if escaped {
      if !(byte == b'\t' || byte == b' ' || vchar_or_obs_text) {
        return Quoted::Invalid;
      }
      escaped = false;
      continue;
    }
    match byte {
      b'"' => return Quoted::Closed(at),
      b'\\' => escaped = true,
      _ if byte == b'\t' || byte == b' ' || vchar_or_obs_text => {}
      _ => return Quoted::Invalid,
    }
  }
}

/// RFC 9110 §5.6.2's `tchar`.
///
/// ```text
/// tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
///                / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
///                / DIGIT / ALPHA
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

/// The end of the `token` starting at `at`, or `None` where there is not one —
/// RFC 9110 §5.6.2's `token = 1*tchar` names at least one character.
fn token_end(value: &[u8], at: usize) -> Option<usize> {
  let mut end = at;
  while value.get(end).is_some_and(|&byte| is_tchar(byte)) {
    end = end.saturating_add(1);
  }
  (end > at).then_some(end)
}

/// Past RFC 9110 §5.6.3's `OWS` from `at`.
fn skip_ows(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while matches!(value.get(at), Some(&b' ') | Some(&b'\t')) {
    at = at.saturating_add(1);
  }
  at
}
