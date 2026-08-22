//! `cargo run -p xtask -- quote-check [<spec-dir>]` — the check behind the
//! rule that a quotation mark in this workspace's comments promises the RFC's
//! own characters.
//!
//! # The rule
//!
//! A reader who sees quoted spec text must be able to search the spec for those
//! bytes and find them. So a quotation that is INTRODUCED follows a colon and
//! keeps the RFC's capital, and one that is genuinely spliced mid-sentence is
//! narrowed to start after the sentence's first word. Neither re-cases, re-orders
//! nor paraphrases what sits inside the marks.
//!
//! The defect this exists to stop is not hypothetical: a review of this
//! workspace found a sentence-initial capital lowered to fit the surrounding
//! prose in 56 places, a clause ended with a full stop where the RFC has a
//! semicolon, and one sentence inside quotation marks that appears in no RFC at
//! all. A case-INSENSITIVE sweep passed every one of them, which is why this one
//! is case-sensitive.
//!
//! # Which quoted spans are checked (the attribution rule)
//!
//! Not every quoted span is a citation — `"websocket"` is a field value,
//! `"nothing this time, ask me again"` is the author's own words, and reporting
//! either as a failure is how a check gets switched off. A span is checked when
//! it is ANCHORED and PROSE-SIZED:
//!
//! - **Anchored**: its first [`ANCHOR_CHARS`] characters appear in one of the
//!   supplied specs, ignoring case. A quotation of a spec BEGINS where the spec
//!   begins; a span the specs do not begin is not a quotation of them, and
//!   nothing is said about it.
//! - **Prose-sized**: at least [`MIN_WORDS`] words and [`MIN_CHARS`] characters.
//!   Quoted TOKENS are field values and identifiers, not citations; a short
//!   token also collides with ordinary spec words by accident, which is exactly
//!   the false positive to avoid.
//!
//! This is the rule for a span whose own block names no RFC, or names more
//! than one ([`cited_rfc`]) — the rule below, "attribution by citation",
//! takes over whenever it names exactly one. For an unattributed span: an
//! anchored, prose-sized span must then appear in full and case-sensitively
//! in one of the specs it anchored in — several may hold the same opening, and
//! a verbatim match in any of them clears it, because with no citation naming
//! one, the tool is not told which. Failing that, the anchor tells the tool
//! which grade it is: a whole-span match ignoring case is a re-cased quotation,
//! and no whole-span match at all is one whose WORDS have drifted — the span
//! demonstrably starts as spec text and then stops being it.
//!
//! What this deliberately cannot see is a rewording INSIDE the anchor, because
//! the span then no longer begins as any spec does. Anchoring on the span's tail
//! as well was tried and reverted: RFCs restate each other, and the tail of this
//! workspace's RFC 2616 `#rule` quotation is also the tail of a sentence in RFC
//! 9110 §5.6.1.2, so the tail anchor reported a correct quotation of a spec that
//! was not even supplied. A check that invents failures gets switched off, so
//! this one is a floor under the convention rather than a proof of it.
//!
//! A quotation may elide with `…` or `...`; each segment is then checked on its
//! own, because an ellipsis promises that what remains is verbatim.
//!
//! ## Attribution by citation
//!
//! A block naming exactly one RFC is a stronger signal than anchoring: the
//! quotations inside it are graded against ONLY the spec that RFC names, not
//! against whichever loaded spec happens to share their opening text.
//! Anchoring is not required in this case — the citation IS the attribution —
//! and this closes a hole the anchor-only rule always had: a sentence
//! attributed to RFC 9110 used to pass because RFC 9112 happened to contain
//! it too, and the citation itself was never read. When the named spec was
//! never loaded, that is not silence: it is reported as [`Grade::Unloaded`],
//! because a claim this run could not check is a different fact from a
//! quotation with no supplied spec to check it against.
//!
//! An ABNF production goes the OTHER way and is checked against every loaded
//! spec regardless of citation — see [`grade_production`]'s doc comment for
//! why. The two are intentionally asymmetric: a quoted SENTENCE inside a
//! citing block is almost always that RFC's own prose, but a grammar RULE
//! beside a citation is routinely shown for comparison with a different
//! spec's.
//!
//! # What is normalised away on BOTH sides, and why
//!
//! Only differences a Rust comment cannot avoid, or the RFC's own typesetting:
//!
//! - **Quote characters** (`"`, `'`, `` ` ``, `|`). A quotation nested inside a
//!   quotation cannot be spelled the same way in Rust source, so the RFCs' inner
//!   `"100-continue"` is respelled with backticks here — and RFC 6455's
//!   `|Sec-WebSocket-Version|` field notation likewise.
//! - **The backslash and the typographic apostrophe** (`\`, `’`), which the
//!   comment side may carry and none of the fetched spec texts contains.
//! - **Markdown emphasis** (`**`), which is rustdoc's typography, not the spec's.
//! - **The specs' own inline cross-references** — `(Section 10.1.1)` and
//!   `(Appendix A.2)` — which are navigation rather than normative words, and
//!   which this workspace quotes both with and without.
//! - **The RFCs' page furniture**: `[Page n]` footers, the running header after
//!   each form feed, the `|` change bars beside an inset paragraph, and the
//!   hyphenation of a word broken across a line.
//! - **Line wrapping**, on both sides. Consecutive comment lines are joined
//!   before matching, so a quotation wrapped across three `///` lines is seen
//!   whole — the second reason the earlier sweep missed what it missed.
//!
//! Fenced code blocks inside a doc comment are skipped, and an inline code span
//! containing a `"` is masked: both are code, and their quote characters would
//! otherwise pair with a real quotation's and produce nonsense spans.
//!
//! What is read is every `//` comment, a comment that FOLLOWS code on the same
//! line included. Finding one of those means walking the code before it,
//! because only the walk tells `// a comment` from the `"//!"` inside
//! `strip_prefix("//!")`: a slash pair inside a string literal opens no
//! comment. The code half is then DISCARDED rather than scanned, which is the
//! masking argument once more — a string literal cannot be read as a quotation
//! if it is never read at all. A line carrying no comment ENDS the block, so
//! two unrelated quotations never pair across the code between them. `/* */`
//! blocks are not read; this workspace writes none.
//!
//! A `.md` file has no comment syntax, so the whole file is read as one
//! comment block: a blank line ends one block the way a bare code line ends a
//! `.rs` one, and a fenced block is skipped for the same reason a doc
//! comment's is — a fence holds code, and a quote mark inside it opens no
//! quotation.
//!
//! # Which files are walked
//!
//! Every `.rs` and `.md` file under the workspace root, skipping build output
//! (`target/`), dot directories, and — unless `--include-ignored` — anything
//! git ignores. `docs/` is the notable case: it holds design documents that
//! quote the RFCs heavily, and it is gitignored, so it exists on a
//! developer's disk and not in CI. Walking it by default would make one
//! command check two different sets of files depending on where it runs,
//! which is exactly the kind of green run that means nothing.
//! `--include-ignored` scans it anyway.
//!
//! # Where the specs come from
//!
//! Raw spec text is about three quarters of a megabyte, which does not belong in
//! the repository, and no gate should depend on reaching the network. So the
//! directory is an argument, `--fetch` is opt-in, and the default cache
//! ([`DEFAULT_DIR`]) is gitignored. Each file is the `.txt` rendering from
//! <https://www.rfc-editor.org/rfc/rfcNNNN.txt>, named `rfcNNNN.txt`; every
//! `.txt` in the directory is loaded, so adding a spec is adding a file.

use std::{
  collections::HashSet,
  fs,
  path::{Path, PathBuf},
  process::Command,
};

type Error = Box<dyn std::error::Error>;

/// A candidate ABNF production found in one file, paired with the source
/// line its opening backtick is on.
type Spans = Vec<(usize, String)>;

/// A quotation found in one file, paired with the source line its opening
/// mark is on and the single RFC its block cited, if any ([`cited_rfc`]).
///
/// The citation travels WITH the span rather than being looked up again at
/// grading time: it is a property of the block the span was cut from, and the
/// block is gone by the time `run` gets to grading.
type QuotedSpans = Vec<(usize, String, Option<u32>)>;

/// The default, gitignored cache directory, relative to the workspace root.
pub const DEFAULT_DIR: &str = ".rfc-cache";

/// The specs `--fetch` downloads: the ones this workspace's comments cite.
///
/// RFC 2616 is deliberately absent. It is obsolete — superseded first by the
/// 723x series and then by the 91xx series — so a comment citing it is either
/// quoting a dead spec a live one now governs, or a deliberate historical
/// note; either way, adding an obsolete RFC to make a production pass is the
/// same shape of bending this gate as loosening the extractor would be.
const FETCHED: &[u32] = &[3986, 6455, 7692, 8441, 9110, 9111, 9112, 9113, 9114, 9220];

/// How much of a span must be found in a spec for the span to be treated as a
/// quotation OF that spec.
const ANCHOR_CHARS: usize = 48;

/// The shortest quotation this check governs, in words.
const MIN_WORDS: usize = 5;

/// The shortest quotation this check governs, in characters.
const MIN_CHARS: usize = 24;

/// One spec, joined and normalised, beside an ASCII-lowercased copy of itself.
///
/// The copy is ASCII-lowercased rather than lowercased so that an offset found
/// in one is an offset into the other: only then can a case-insensitive hit be
/// shown back to the reader in the spec's OWN characters, which is the whole
/// point of reporting it.
struct Spec {
  name: String,
  text: String,
  lower: String,
}

/// What went wrong with one quoted span — including that it could not be
/// checked at all.
enum Grade<'a> {
  /// The spec has these words, in other cases.
  Recased(&'a Spec, String),
  /// The spec begins this way and then says something else.
  Reworded(&'a Spec, String),
  /// The block cited this RFC, but no spec by that name was loaded — a
  /// checkable claim this run could not check, not a pass.
  Unloaded(u32),
}

/// Checks every RFC quotation in the workspace's comments against the specs in
/// `dir` (or [`DEFAULT_DIR`]), downloading them first when `fetch`.
pub fn run(dir: Option<&str>, fetch: bool, include_ignored: bool) -> Result<(), Error> {
  let root = crate::workspace_root()?;
  let dir = dir.map_or_else(|| root.join(DEFAULT_DIR), PathBuf::from);

  if fetch {
    fetch_specs(&dir)?;
  }

  let specs = load_specs(&dir)?;
  // Hoisted once, beside `load_specs`: normalising every spec for every
  // production would be O(productions × specs) of repeated work, and
  // `grade_production` needs only the normalised text, not the `Spec` it
  // came from — `specs` stays alongside for that, indexed the same.
  let normalised_specs: Vec<String> = specs.iter().map(|spec| normalise(&spec.text)).collect();
  let mut sources = Vec::new();
  let mut skipped = 0usize;
  collect_sources(&root, &mut sources, include_ignored, &mut skipped)?;
  sources.sort();

  let mut checked = 0usize;
  let mut failures = 0usize;
  let mut abnf_checked = 0usize;
  let mut abnf_failures = 0usize;
  let mut abnf_skipped = 0usize;
  let mut abnf_exempt = 0usize;
  for source in &sources {
    let text = fs::read_to_string(source)?;
    let shown = source.strip_prefix(&root).unwrap_or(source).display();
    let (spans, productions, skipped_here) = spans_for(source, &text);
    abnf_skipped += skipped_here;
    for (line, span, cited) in spans {
      for segment in span.split(['…']).flat_map(|part| part.split("...")) {
        let quoted = normalise(segment);
        let Some(grade) = grade(&quoted, cited, &specs, &mut checked) else {
          continue;
        };
        failures += 1;
        match grade {
          Grade::Recased(spec, actual) => {
            println!("{shown}:{line}: quotation is re-cased, not {}'s", spec.name);
            println!("  comment: \"{quoted}\"");
            println!("  {}: \"{actual}\"", spec.name);
          }
          Grade::Reworded(spec, actual) => {
            println!("{shown}:{line}: quoted words are not {}'s", spec.name);
            println!("  comment: \"{quoted}\"");
            println!("  {}: \"{actual}…\"", spec.name);
          }
          Grade::Unloaded(number) => {
            println!("{shown}:{line}: cites RFC {number}, which was not loaded");
            println!("  comment: \"{quoted}\"");
            println!(
              "  add {number} to FETCHED and run \
               `cargo run -p xtask -- quote-check --fetch`"
            );
          }
        }
      }
    }
    // Per-file: a marker in one file cannot exempt a span in another.
    let exempt = exempted_spans(&text);
    for (line, production) in productions {
      if exempt.contains(&production) {
        abnf_exempt += 1;
        continue;
      }
      // A deliberately elided production promises only that what remains is
      // verbatim — the same reading `run` already gives a quotation span.
      for segment in production.split(['…']).flat_map(|part| part.split("...")) {
        let Some(spec) = grade_production(segment, &specs, &normalised_specs, &mut abnf_checked)
        else {
          continue;
        };
        abnf_failures += 1;
        println!("{shown}:{line}: ABNF production is not {}'s", spec.name);
        println!("  comment: `{segment}`");
      }
    }
  }

  // Printed regardless of what the loop above found: a failing run has MORE
  // reason to know what went unscanned, not less.
  if !include_ignored && skipped > 0 {
    println!(
      "quote-check: {skipped} git-ignored director{} not scanned — quotations \
       there are UNCHECKED (pass --include-ignored to scan them)",
      if skipped == 1 { "y" } else { "ies" }
    );
  }
  // Also printed regardless: a span this uncited or exempted is not a
  // failure, but it is not silence either — a fenced-off count is how
  // `negotiation.rs:592`'s `quoted-pair` (a real, correctly-quoted RFC 2616
  // production whose citation sits outside its own block) stays VISIBLE as
  // unchecked instead of vanishing the way it did before this line existed.
  println!(
    "quote-check: {abnf_skipped} production-shaped spans skipped (no RFC cited), {abnf_exempt} \
     marked gate-exempt"
  );

  if failures == 0 && abnf_failures == 0 {
    println!(
      "quote-check: {checked} quotations verbatim, {abnf_checked} ABNF productions verbatim"
    );
    return Ok(());
  }
  let mut reasons = Vec::new();
  if failures > 0 {
    reasons.push(format!(
      "{failures} of {checked} quotations are not the spec's own characters"
    ));
  }
  if abnf_failures > 0 {
    reasons.push(format!(
      "{abnf_failures} of {abnf_checked} ABNF productions are not the spec's own characters"
    ));
  }
  Err(reasons.join("; ").into())
}

/// Every quotation and candidate ABNF production `path`'s contents holds,
/// dispatched by extension, as `(quoted, productions, skipped)` — each
/// `quoted` span carrying the single RFC its own block cited, if any.
///
/// `.md` is read as one long comment block ([`markdown_quotations`]);
/// anything else — in practice always `.rs`, since [`collect_sources`] hands
/// this only `.rs` or `.md` paths — is read as `.rs`-style comments
/// ([`quotations`]).
fn spans_for(path: &Path, text: &str) -> (QuotedSpans, Spans, usize) {
  if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
    markdown_quotations(text)
  } else {
    quotations(text)
  }
}

/// Grades one normalised span, counting it when it is one this check governs.
///
/// `cited` is the single RFC the span's own block named, if any
/// ([`cited_rfc`]). A block that cites one RFC is claiming THAT spec's
/// words, so a cited span is graded only against the spec it names — not
/// against whichever loaded spec happens to contain it. That closes a hole
/// this check always had: a sentence attributed to RFC 9110 used to pass
/// because RFC 9112 happened to contain it too, and the attribution itself
/// was never read. A spec the block names but this run never loaded is not
/// silence either — it is [`Grade::Unloaded`], because a claim this run could
/// not check is a different fact from a claim with nothing to check against.
///
/// This is deliberately the OPPOSITE of [`grade_production`], which grades
/// against every loaded spec regardless of citation. That is not an
/// inconsistency: a quoted SENTENCE inside a citing block is almost always
/// that RFC's own prose, but a grammar RULE beside a citation is routinely
/// shown for comparison with a different spec's — see `grade_production`'s
/// doc comment for the worked example.
fn grade<'a>(
  quoted: &str,
  cited: Option<u32>,
  specs: &'a [Spec],
  checked: &mut usize,
) -> Option<Grade<'a>> {
  if quoted.split_whitespace().count() < MIN_WORDS || quoted.chars().count() < MIN_CHARS {
    return None; // not prose-sized: not a quotation
  }

  if let Some(number) = cited {
    let name = format!("rfc{number}");
    let Some(spec) = specs.iter().find(|spec| spec.name == name) else {
      *checked += 1;
      return Some(Grade::Unloaded(number));
    };
    *checked += 1;
    if spec.text.contains(quoted) {
      return None;
    }
    let lowered = quoted.to_ascii_lowercase();
    if let Some(at) = spec.lower.find(&lowered) {
      return Some(Grade::Recased(spec, excerpt(&spec.text, at, quoted.len())));
    }
    let head = anchor(quoted);
    let at = spec.lower.find(&head).unwrap_or(0);
    return Some(Grade::Reworded(
      spec,
      excerpt(&spec.text, at, quoted.len().saturating_mul(2)),
    ));
  }

  // No citation: the pre-existing any-spec behaviour, unchanged. Without a
  // citation naming which spec is claimed, anchoring — the span's own opening
  // characters — is the only signal that it is a quotation of a supplied spec
  // at all.
  let head = anchor(quoted);
  let anchored: Vec<&Spec> = specs
    .iter()
    .filter(|spec| spec.lower.contains(&head))
    .collect();
  if anchored.is_empty() {
    // Not a quotation of any supplied spec: an internal quotation, a quoted
    // identifier, or an UNCITED quotation from a spec this run was not given.
    // With no citation naming it, there is no spec to report as unloaded —
    // unlike the cited branch above, this stays silent. Not this check's
    // business.
    return None;
  }

  *checked += 1;
  if anchored.iter().any(|spec| spec.text.contains(quoted)) {
    return None;
  }

  let lowered = quoted.to_ascii_lowercase();
  if let Some(spec) = anchored
    .iter()
    .find(|spec| spec.lower.contains(&lowered))
    .copied()
  {
    let at = spec.lower.find(&lowered).unwrap_or(0);
    return Some(Grade::Recased(spec, excerpt(&spec.text, at, quoted.len())));
  }

  // The anchor is where the reader should start reading the spec.
  let spec = anchored[0];
  let at = spec.lower.find(&head).unwrap_or(0);
  let actual = excerpt(&spec.text, at, quoted.len().saturating_mul(2));
  Some(Grade::Reworded(spec, actual))
}

/// The first [`ANCHOR_CHARS`] characters of `quoted`, ASCII-lowercased.
fn anchor(quoted: &str) -> String {
  quoted
    .chars()
    .take(ANCHOR_CHARS)
    .collect::<String>()
    .to_ascii_lowercase()
}

/// `text[from..from + len]`, with both ends moved to a character boundary.
fn excerpt(text: &str, from: usize, len: usize) -> String {
  let mut start = from.min(text.len());
  while start < text.len() && !text.is_char_boundary(start) {
    start += 1;
  }
  let mut end = start.saturating_add(len).min(text.len());
  while end > start && !text.is_char_boundary(end) {
    end -= 1;
  }
  text.get(start..end).unwrap_or_default().to_string()
}

/// Grades one production segment. `None` when it is too short to be a
/// checkable claim, or when SOME loaded spec contains it verbatim.
///
/// Every loaded spec is searched, not only the one [`cited_rfc`] named for
/// the block: 6455 borrows grammar from 2616 and the 723x series, and a
/// block's citation is often a COMPARISON point rather than an attribution —
/// three real, correctly-transcribed RFC 6455 productions sit in blocks whose
/// only citation is RFC 9110, discussing where the two grammars disagree.
/// That is right for a production the way it would be wrong for a quotation:
/// a quoted SENTENCE inside a citing block is almost certainly that RFC's
/// own, but a grammar RULE beside a citation is often shown for contrast.
/// [`cited_rfc`] still decides whether a span is a candidate at all — a block
/// naming no RFC makes no checkable claim — it just no longer decides which
/// spec the candidate is graded against.
///
/// On failure the first spec is named, same as [`grade`] falls back to when a
/// quotation's anchor does not narrow it — arbitrarily, since nothing here
/// says which loaded spec a production was meant to be quoting.
///
/// `normalised_specs` is [`normalise`] applied to each spec's (already
/// normalised) text, indexed the same as `specs` — hoisted by the caller so
/// grading `n` productions costs O(n + specs) of normalising rather than
/// O(n × specs).
fn grade_production<'a>(
  segment: &str,
  specs: &'a [Spec],
  normalised_specs: &[String],
  checked: &mut usize,
) -> Option<&'a Spec> {
  let wanted = normalise(segment);
  if wanted.split_whitespace().count() < 3 {
    return None;
  }
  *checked += 1;
  if normalised_specs.iter().any(|spec| spec.contains(&wanted)) {
    return None;
  }
  specs.first()
}

/// The production-shaped spans `source` marks exempt, matched by the span's
/// own extracted text.
///
/// A `// gate-exempt: <span> — <reason>` comment, anywhere in the file, marks
/// `<span>` (everything up to the em dash, or the rest of the line when there
/// is none) as a deliberate non-production rather than a silent one: `` `q =
/// 1` `` is production-SHAPED — [`is_production`] cannot tell a grammar rule
/// from a Rust value shown in a block that legitimately cites a spec for
/// something else — and narrowing the shape-matcher itself was tried and
/// rejected, because any rule keyed on the right-hand side makes a BROKEN
/// production stop looking like one too: a check whose defect makes the item
/// disappear is worse than no check. A marker cannot do that — it names the
/// exact text it exempts, so it goes stale (and stops matching) the moment
/// that text changes, rather than silently widening to cover something new.
///
/// One mechanism, one spelling: a later check reuses this same marker, so
/// recognising it lives here rather than folded into the ABNF pipeline.
fn exempted_spans(source: &str) -> HashSet<String> {
  let mut out = HashSet::new();
  for line in source.lines() {
    let Some((body, _)) = comment_body(line) else {
      continue;
    };
    let Some(rest) = body.strip_prefix("gate-exempt:") else {
      continue;
    };
    let text = rest.split(" — ").next().unwrap_or(rest).trim();
    if !text.is_empty() {
      out.insert(text.to_string());
    }
  }
  out
}

/// Every quoted span in `source`'s comments, with the line its opening quote
/// is on and the single RFC its own block cited (if any) — beside every
/// backticked ABNF production candidate whose block names a single RFC, as
/// `(quoted, productions, skipped)`. `skipped` counts the production-shaped
/// spans found in a block that named no RFC, or named more than one — a
/// candidate this check has no citation to grade, not a failure.
///
/// Consecutive comment lines are one block and are joined before the quotes are
/// paired, so a quotation wrapped across lines is one span rather than several.
/// A production is found per raw line, before [`mask_code_spans`] runs on it —
/// but which block it belongs to, and so whether [`cited_rfc`] admits it as a
/// candidate at all, is decided at the block's flush, once the whole block
/// exists to be asked. Every quoted span pulled from the same block carries
/// the same citation, for the same reason: the block, not the line, is what
/// was cited.
fn quotations(source: &str) -> (QuotedSpans, Spans, usize) {
  let mut out: QuotedSpans = Vec::new();
  let mut productions = Vec::new();
  let mut skipped = 0usize;
  let mut block = String::new();
  // (byte offset into `block`, source line) for the start of each joined line.
  let mut marks: Vec<(usize, usize)> = Vec::new();
  // ABNF production candidates seen in the block under construction, admitted
  // or skipped only once the block's own citation is known.
  let mut pending: Vec<(usize, String)> = Vec::new();
  let mut fenced = false;

  let mut flush =
    |block: &mut String, marks: &mut Vec<(usize, usize)>, pending: &mut Vec<(usize, String)>| {
      // Computed once and reused for every span AND for the production gate
      // below: both readings are "what did this block cite", so there is only
      // one place that question is asked.
      let cited = cited_rfc(block);
      for (at, span) in quoted_spans(block) {
        let line = marks
          .iter()
          .take_while(|(offset, _)| *offset <= at)
          .last()
          .map_or(0, |(_, line)| *line);
        out.push((line, span.to_string(), cited));
      }
      if cited.is_some() {
        productions.append(pending);
      } else {
        skipped += pending.len();
        pending.clear();
      }
      block.clear();
      marks.clear();
    };

  for (index, raw) in source.lines().enumerate() {
    let Some((body, own_line)) = comment_body(raw) else {
      fenced = false;
      flush(&mut block, &mut marks, &mut pending);
      continue;
    };
    if own_line {
      if body.starts_with("```") {
        fenced = !fenced;
        continue;
      }
      if fenced {
        continue;
      }
    } else {
      // A comment that FOLLOWS code cannot be inside a doc fence: the fence
      // would have had to close before the code line that carries it.
      fenced = false;
    }
    if !block.is_empty() {
      block.push(' ');
    }
    marks.push((block.len(), index + 1));
    for span in abnf_spans(body) {
      pending.push((index + 1, span));
    }
    block.push_str(&mask_code_spans(body));
  }
  flush(&mut block, &mut marks, &mut pending);
  (out, productions, skipped)
}

/// Every quotation in a Markdown file, with the line its opening quote is on
/// and the single RFC its own block cited (if any), beside every backticked
/// ABNF production candidate whose block names a single RFC, as `(quoted,
/// productions, skipped)` — see [`quotations`] for what `skipped` counts and
/// why, and for the citation this mirrors.
///
/// A `.md` file is comment text throughout, so there is no comment prefix to
/// find and no code half to discard — but fenced blocks are still skipped, for
/// the same reason they are in a doc comment: a fence holds code, and a
/// quotation mark inside code is not opening a quotation.
///
/// Unlike [`quotations`], this function flushes the block on EVERY fence
/// toggle, open and close alike. `quotations` does not: it toggles `fenced`
/// and moves on, so the prose before a `.rs` doc-comment fence and the prose
/// after it stay in the same block, and a quote mark on one side can pair with
/// a quote mark on the other into one spurious span crossing the fence.
/// Flushing here trades that for the opposite failure — a quotation that
/// itself opens before a fence and closes after it is silently uncounted
/// rather than joined — which is the safer of the two: a fence is far likelier
/// to separate two unrelated paragraphs than a real quotation is to straddle
/// one.
fn markdown_quotations(source: &str) -> (QuotedSpans, Spans, usize) {
  let mut out: QuotedSpans = Vec::new();
  let mut productions = Vec::new();
  let mut skipped = 0usize;
  let mut block = String::new();
  let mut marks: Vec<(usize, usize)> = Vec::new();
  // ABNF production candidates seen in the block under construction, admitted
  // or skipped only once the block's own citation is known — see
  // `quotations`'s `pending` for why this can't be decided per-line.
  let mut pending: Vec<(usize, String)> = Vec::new();
  let mut fenced = false;

  let mut flush =
    |block: &mut String, marks: &mut Vec<(usize, usize)>, pending: &mut Vec<(usize, String)>| {
      // See `quotations`'s `flush` for why this is computed once and reused
      // for both the spans below and the production gate.
      let cited = cited_rfc(block);
      for (at, span) in quoted_spans(block) {
        let line = marks
          .iter()
          .take_while(|(offset, _)| *offset <= at)
          .last()
          .map_or(0, |(_, line)| *line);
        out.push((line, span.to_string(), cited));
      }
      if cited.is_some() {
        productions.append(pending);
      } else {
        skipped += pending.len();
        pending.clear();
      }
      block.clear();
      marks.clear();
    };

  for (index, raw) in source.lines().enumerate() {
    if raw.trim_start().starts_with("```") {
      fenced = !fenced;
      flush(&mut block, &mut marks, &mut pending);
      continue;
    }
    if fenced {
      continue;
    }
    if raw.trim().is_empty() {
      flush(&mut block, &mut marks, &mut pending);
      continue;
    }
    if !block.is_empty() {
      block.push(' ');
    }
    marks.push((block.len(), index + 1));
    for span in abnf_spans(raw) {
      pending.push((index + 1, span));
    }
    block.push_str(&mask_code_spans(raw));
  }
  flush(&mut block, &mut marks, &mut pending);
  (out, productions, skipped)
}

/// The comment on one source line, and whether the line is nothing but that
/// comment.
///
/// A comment that FOLLOWS code counts. Finding one means walking the code half,
/// because the only thing that distinguishes `// a comment` from the `"//!"`
/// inside `strip_prefix("//!")` is whether the slashes sit inside a string
/// literal. The code half is then DISCARDED rather than scanned, which is the
/// same argument [`mask_code_spans`] makes for an inline code span, applied to
/// a whole line: a string literal cannot be read as a quotation if it is never
/// read at all.
///
/// The `own_line` half of the answer is for the fence rule, which is a property
/// of doc comments and not of a comment beside code.
fn comment_body(line: &str) -> Option<(&str, bool)> {
  let trimmed = line.trim_start();
  let own_line = trimmed.starts_with("//");
  let text = if own_line {
    trimmed
  } else {
    line.get(trailing_comment_at(line)?..)?
  };
  let body = text
    .strip_prefix("///")
    .or_else(|| text.strip_prefix("//!"))
    .or_else(|| text.strip_prefix("//"))?;
  Some((body.trim(), own_line))
}

/// Where a comment begins on a line that starts with code, or `None` when the
/// line carries none.
///
/// Walks the code so a slash pair inside a string literal opens no comment —
/// `strip_prefix("//!")` and `"http://example.org"` both NAME one without
/// starting one. Char literals are stepped over for their quotes alone, since
/// no two-character `//` fits inside one; a lone `'` is a lifetime and is
/// passed by. A string literal left open at end of line ends the walk, because
/// what follows it on the next line is not this line's to read.
fn trailing_comment_at(line: &str) -> Option<usize> {
  let bytes = line.as_bytes();
  let mut at = 0usize;
  while at < bytes.len() {
    if let Some((quote, hashes, raw)) = string_opens_at(bytes, at) {
      at = string_ends(bytes, quote, hashes, raw)?;
      continue;
    }
    match bytes.get(at) {
      Some(b'/') if bytes.get(at.saturating_add(1)) == Some(&b'/') => return Some(at),
      Some(b'\'') => at = char_literal_ends(bytes, at),
      _ => at = at.saturating_add(1),
    }
  }
  None
}

/// The four spellings of a string literal one line of Rust can carry — `"…"`,
/// `b"…"`, `r#"…"#` and `br#"…"#` — reported as the offset of the opening
/// quote, the hash count a raw one closes on, and whether it is raw.
///
/// All four are here because every one of them can hold a `//`. The
/// identifier guard is what keeps `foo_b"x"` from being read as a byte string:
/// a prefix letter preceded by an identifier character is part of that
/// identifier.
fn string_opens_at(bytes: &[u8], at: usize) -> Option<(usize, usize, bool)> {
  let mut cursor = at;
  if bytes.get(cursor) == Some(&b'b') {
    cursor = cursor.saturating_add(1);
  }
  let raw = bytes.get(cursor) == Some(&b'r');
  if raw {
    cursor = cursor.saturating_add(1);
  }
  let hashes_at = cursor;
  while bytes.get(cursor) == Some(&b'#') {
    cursor = cursor.saturating_add(1);
  }
  let hashes = cursor.saturating_sub(hashes_at);
  if bytes.get(cursor) != Some(&b'"') || (!raw && hashes > 0) {
    return None;
  }
  if cursor > at
    && at > 0
    && bytes
      .get(at.saturating_sub(1))
      .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
  {
    return None;
  }
  Some((cursor, hashes, raw))
}

/// One past the string literal whose opening quote is at `quote`, or `None`
/// when it does not close on this line.
fn string_ends(bytes: &[u8], quote: usize, hashes: usize, raw: bool) -> Option<usize> {
  let mut at = quote.saturating_add(1);
  while at < bytes.len() {
    match bytes.get(at) {
      // A raw string has no escapes, which is the whole of what `r` means.
      Some(b'\\') if !raw => at = at.saturating_add(2),
      Some(b'"') => {
        let close = at.saturating_add(1);
        let closes = bytes
          .get(close..close.saturating_add(hashes))
          .is_some_and(|tail| tail.iter().all(|byte| *byte == b'#'));
        if closes {
          return Some(close.saturating_add(hashes));
        }
        at = close;
      }
      _ => at = at.saturating_add(1),
    }
  }
  None
}

/// One past the char literal at `at`, or one past the tick when what is there
/// is a lifetime rather than a literal.
///
/// `\'"\'` is the case that matters: its quote opens no string.
fn char_literal_ends(bytes: &[u8], at: usize) -> usize {
  match (
    bytes.get(at.saturating_add(1)),
    bytes.get(at.saturating_add(2)),
    bytes.get(at.saturating_add(3)),
  ) {
    (Some(b'\\'), Some(_), Some(b'\'')) => at.saturating_add(4),
    (Some(_), Some(b'\''), _) => at.saturating_add(3),
    _ => at.saturating_add(1),
  }
}

/// The `"…"` spans in one joined comment block, paired left to right.
fn quoted_spans(block: &str) -> Vec<(usize, &str)> {
  let mut out = Vec::new();
  let bytes = block.as_bytes();
  let mut at = 0;
  while at < bytes.len() {
    if bytes[at] != b'"' {
      at += 1;
      continue;
    }
    let Some(len) = block[at + 1..].find('"') else {
      break;
    };
    if len > 0 {
      out.push((at, &block[at + 1..at + 1 + len]));
    }
    at += len + 2;
  }
  out
}

/// The backticked ABNF productions on one raw comment line.
///
/// Runs BEFORE [`mask_code_spans`], which erases a backticked span holding a
/// `"` — and a production's terminals are quoted, so by the time a block is
/// built its productions are gone. [`quoted_spans`] would not have found them
/// either: a production without a terminal carries no `"` at all.
///
/// A span counts when it opens with `name =`, which is what separates an RFC
/// 5234 rule from a backticked identifier. `=/` (incremental alternatives)
/// counts too.
fn abnf_spans(line: &str) -> Vec<String> {
  let mut out = Vec::new();
  let mut rest = line;
  while let Some(open) = rest.find('`') {
    let after = &rest[open + 1..];
    let Some(close) = after.find('`') else {
      return out;
    };
    let span = &after[..close];
    if is_production(span) {
      out.push(span.to_string());
    }
    rest = &after[close + 1..];
  }
  out
}

/// Whether `span` opens with an RFC 5234 rule name and a single `=`.
///
/// `name ==` is a Rust comparison, not RFC 5234 assignment — requiring the
/// character AFTER the `=` not to be a second `=` is what tells `` `need ==
/// out.len()` `` from `` `rule = value` ``. `=/` (incremental alternatives)
/// still counts: its second character is `/`, not `=`.
fn is_production(span: &str) -> bool {
  let trimmed = span.trim_start();
  let name: String = trimmed
    .chars()
    .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
    .collect();
  if name.is_empty() || !name.starts_with(|ch: char| ch.is_ascii_alphabetic()) {
    return false;
  }
  let mut after_name = trimmed[name.len()..].trim_start().chars();
  after_name.next() == Some('=') && after_name.next() != Some('=')
}

/// The single RFC number `block` names, or `None` when it names zero or names
/// more than one.
///
/// A bare `name =` cannot say which spec it is a claim about — a production
/// is too short to anchor on the way [`grade`] anchors a quotation on its own
/// opening characters. The surrounding prose says it instead: a block naming
/// exactly one RFC commits every production inside it to that one spec: a
/// block naming none, or naming several, leaves it unclear which — so neither
/// is this check's business, the same "not this check's business" `grade`
/// reaches for an unanchored quotation.
fn cited_rfc(block: &str) -> Option<u32> {
  let mut found: Option<u32> = None;
  let mut rest = block;
  while let Some(at) = rest.find("RFC ") {
    let after = &rest[at + 4..];
    let digits: String = after.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    rest = &after[digits.len()..];
    if digits.is_empty() {
      continue;
    }
    let cited: u32 = digits.parse().ok()?;
    match found {
      None => found = Some(cited),
      Some(existing) if existing == cited => {}
      Some(_) => return None,
    }
  }
  found
}

/// Masks an inline code span that contains a `"`.
///
/// `` `"` `` is a quote character being NAMED, not one opening a quotation, and
/// leaving it in place pairs it with a real quotation's and swallows a paragraph.
fn mask_code_spans(line: &str) -> String {
  let mut out = String::with_capacity(line.len());
  let mut rest = line;
  while let Some(open) = rest.find('`') {
    out.push_str(&rest[..open]);
    let after = &rest[open + 1..];
    let Some(close) = after.find('`') else {
      out.push_str(&rest[open..]);
      return out;
    };
    let span = &after[..close];
    if span.contains('"') {
      out.push_str("<code>");
    } else {
      out.push('`');
      out.push_str(span);
      out.push('`');
    }
    rest = &after[close + 1..];
  }
  out.push_str(rest);
  out
}

/// Reduces a span to the characters a comparison may turn on.
///
/// The module docs list what goes and why; nothing here is allowed to change a
/// word.
fn normalise(text: &str) -> String {
  let text = strip_cross_references(text);
  let mut out = String::with_capacity(text.len());
  let mut chars = text.chars().peekable();
  let mut space = false;
  while let Some(ch) = chars.next() {
    match ch {
      '*' if chars.peek() == Some(&'*') => {
        chars.next();
      }
      '`' | '"' | '\'' | '|' | '\\' | '\u{2019}' => {}
      ch if ch.is_whitespace() => space = !out.is_empty(),
      ch => {
        if space {
          out.push(' ');
          space = false;
        }
        out.push(ch);
      }
    }
  }
  out
}

/// Removes `(Section n)` and `(Appendix n)`, and the space before them.
fn strip_cross_references(text: &str) -> String {
  let mut out = String::with_capacity(text.len());
  let mut rest = text;
  while let Some(open) = rest.find('(') {
    let after = &rest[open + 1..];
    let reference = (after.starts_with("Section ") || after.starts_with("Appendix "))
      .then(|| after.find(')'))
      .flatten();
    out.push_str(&rest[..open]);
    match reference {
      Some(close) => {
        while out.ends_with(' ') || out.ends_with('\t') {
          out.pop();
        }
        rest = &after[close + 1..];
      }
      None => {
        out.push('(');
        rest = after;
      }
    }
  }
  out.push_str(rest);
  out
}

/// Loads every `.txt` in `dir` as a spec.
fn load_specs(dir: &Path) -> Result<Vec<Spec>, Error> {
  let mut specs = Vec::new();
  let entries = fs::read_dir(dir).map_err(|err| missing_specs(dir, &err.to_string()))?;
  for entry in entries {
    let path = entry?.path();
    if path.extension().and_then(|ext| ext.to_str()) != Some("txt") {
      continue;
    }
    let name = path
      .file_stem()
      .and_then(|stem| stem.to_str())
      .unwrap_or("spec")
      .to_string();
    let text = spec_text(&fs::read_to_string(&path)?);
    let lower = text.to_ascii_lowercase();
    specs.push(Spec { name, text, lower });
  }
  if specs.is_empty() {
    return Err(missing_specs(dir, "it holds no .txt files"));
  }
  specs.sort_by(|a, b| a.name.cmp(&b.name));
  Ok(specs)
}

fn missing_specs(dir: &Path, why: &str) -> Error {
  format!(
    "no spec text in {}: {why}\n\
     Put the `.txt` rendering of each RFC there as `rfcNNNN.txt` — they are at\n\
     https://www.rfc-editor.org/rfc/rfcNNNN.txt — or run\n\
     `cargo run -p xtask -- quote-check --fetch` to download the ones this\n\
     workspace cites into {DEFAULT_DIR}/.",
    dir.display()
  )
  .into()
}

/// Downloads the cited specs into `dir` with `curl`.
///
/// `curl` rather than an HTTP dependency: this runs by hand, once, and an xtask
/// that pulls a TLS stack in to fetch six text files has bought nothing.
fn fetch_specs(dir: &Path) -> Result<(), Error> {
  fs::create_dir_all(dir)?;
  for rfc in FETCHED {
    let url = format!("https://www.rfc-editor.org/rfc/rfc{rfc}.txt");
    let into = dir.join(format!("rfc{rfc}.txt"));
    let status = Command::new("curl")
      .args(["--fail", "--silent", "--show-error", "--location", "-o"])
      .arg(&into)
      .arg(&url)
      .status()
      .map_err(|err| format!("could not run curl: {err}"))?;
    if !status.success() {
      return Err(format!("curl could not fetch {url}").into());
    }
    println!("fetched {}", into.display());
  }
  Ok(())
}

/// Joins one spec's lines, discarding the page furniture around them.
fn spec_text(raw: &str) -> String {
  let mut joined = String::with_capacity(raw.len());
  let mut header = false;
  for line in raw.lines() {
    if header {
      header = false;
      continue;
    }
    if line.contains('\u{c}') {
      // A form feed, and the running header on the line after it.
      header = true;
      continue;
    }
    if line.trim_end().ends_with(']') && line.contains("[Page ") {
      continue;
    }
    let body = strip_change_bar(line).trim();
    // A word the RFC broke across a line keeps its hyphen and loses the break:
    // `Transfer-` + `Encoding` is one field name, not two words.
    let hyphenated =
      joined.ends_with('-') && body.starts_with(|ch: char| ch.is_ascii_alphanumeric());
    if !hyphenated && !joined.is_empty() {
      joined.push(' ');
    }
    joined.push_str(body);
  }
  normalise(&joined)
}

/// Removes the `|` an RFC insets a paragraph with — never RFC 6455's `|Field|`,
/// whose bar is followed by the name rather than by space.
fn strip_change_bar(line: &str) -> &str {
  let trimmed = line.trim_start();
  match trimmed.strip_prefix('|') {
    Some(rest) if rest.is_empty() || rest.starts_with(char::is_whitespace) => rest,
    _ => trimmed,
  }
}

/// Every `.rs` and `.md` file in the workspace, skipping build output, dot
/// directories, and — unless `include_ignored` — anything git ignores.
///
/// The git-ignore rule is what keeps a green run meaning ONE thing: `docs/` is
/// ignored, so it exists on a developer's disk and not in CI, and walking it by
/// default would make the same command check different sets in the two places.
fn collect_sources(
  dir: &Path,
  out: &mut Vec<PathBuf>,
  include_ignored: bool,
  skipped: &mut usize,
) -> Result<(), Error> {
  for entry in fs::read_dir(dir)? {
    let path = entry?.path();
    let name = path
      .file_name()
      .and_then(|name| name.to_str())
      .unwrap_or("");
    if path.is_dir() {
      if name == "target" || name.starts_with('.') {
        continue;
      }
      if !include_ignored && is_ignored(&path)? {
        *skipped += 1;
        continue;
      }
      collect_sources(&path, out, include_ignored, skipped)?;
    } else {
      match path.extension().and_then(|ext| ext.to_str()) {
        Some("rs") | Some("md") => out.push(path),
        _ => {}
      }
    }
  }
  Ok(())
}

/// Whether git ignores `path`.
///
/// `git check-ignore` exits 0 when the path IS ignored and 1 when it is not,
/// so the exit code is the answer and no output needs parsing — but only 0 and
/// 1 are that answer. Anything else (128 on a fatal error such as "not a
/// repository", or no code at all if the process was killed by a signal) is a
/// failure to check, and reporting it as `false` would be this exact defect in
/// miniature: an unchecked path silently counted as "checked, and fine".
fn is_ignored(path: &Path) -> Result<bool, Error> {
  let status = Command::new("git")
    .args(["check-ignore", "--quiet"])
    .arg(path)
    .status()
    .map_err(|err| format!("could not run git check-ignore: {err}"))?;
  match status.code() {
    Some(0) => Ok(true),
    Some(1) => Ok(false),
    Some(code) => Err(
      format!(
        "git check-ignore on {}: exited with status {code}",
        path.display()
      )
      .into(),
    ),
    None => Err(format!("git check-ignore on {}: killed by signal", path.display()).into()),
  }
}

#[cfg(test)]
mod tests {
  use super::{markdown_quotations, quotations, spans_for};
  use std::path::Path;

  fn spans(source: &str) -> Vec<String> {
    quotations(source)
      .0
      .into_iter()
      .map(|(_, s, _)| s)
      .collect()
  }

  // `markdown_quotations` mirrors `spans` above: same shape, different source
  // function, because a `.md` file has no comment prefix to key off of.
  fn markdown_spans(source: &str) -> Vec<String> {
    markdown_quotations(source)
      .0
      .into_iter()
      .map(|(_, s, _)| s)
      .collect()
  }

  // A quotation in a comment that FOLLOWS code is governed like any other. A
  // comment this scanner does not read is one the convention does not reach,
  // which is the whole of what makes this line worth pinning.
  #[test]
  fn a_comment_after_code_is_read() {
    let source = "  let x = 1; // RFC 9112 §9.6: \"the server MUST NOT process\"\n";
    assert_eq!(spans(source), ["the server MUST NOT process"]);
  }

  // Why finding that comment takes a walk rather than a search for the first
  // slash pair: every line below NAMES one without starting a comment. The code
  // half is discarded, so a string literal is never read as a quotation.
  #[test]
  fn a_slash_pair_inside_a_string_literal_opens_no_comment() {
    for source in [
      "  let a = \"// \\\"not a quotation\\\"\";\n",
      "  let b = r#\"// \"not a quotation\"\"#;\n",
      "  let c = b\"// \\\"not a quotation\\\"\";\n",
      "  let d = \"https://example.org/x\";\n",
      "  let e = trimmed.strip_prefix(\"//!\");\n",
    ] {
      assert!(spans(source).is_empty(), "{source}");
    }
  }

  // A char literal holding a quote opens no string, so the comment beside it is
  // still found. A lifetime is a lone tick and must not swallow the line.
  #[test]
  fn a_char_literal_does_not_open_a_string() {
    let quote = "  let c = '\"'; // \"the server MUST NOT process\"\n";
    assert_eq!(spans(quote), ["the server MUST NOT process"]);
    let lifetime = "  fn f<'a>(x: &'a str) {} // \"the server MUST NOT process\"\n";
    assert_eq!(spans(lifetime), ["the server MUST NOT process"]);
  }

  // A string left open at end of line ends the walk: what closes it belongs to
  // the next line, and this one has no comment to report.
  #[test]
  fn an_unterminated_string_reports_no_comment() {
    assert!(spans("  let a = \"open // not a comment\n").is_empty());
  }

  // Wrapping still works, and it works ACROSS the two kinds: consecutive
  // comment lines are one block, so a quotation split over them is one span.
  #[test]
  fn consecutive_comment_lines_join() {
    let source = "  /// \"the server MUST NOT\n  /// process\"\n";
    assert_eq!(spans(source), ["the server MUST NOT process"]);
    let mixed = "  // \"the server MUST NOT\n  let x = 1; // process\"\n";
    assert_eq!(spans(mixed), ["the server MUST NOT process"]);
  }

  // A line that is neither code-with-a-comment nor a comment ends the block, so
  // two unrelated quotations never pair across it.
  #[test]
  fn a_bare_code_line_ends_the_block() {
    let source = "  // \"first\n  let x = 1;\n  // second\"\n";
    assert!(spans(source).is_empty());
  }

  // The fence rule is a property of doc comments. A fenced block is skipped,
  // and the fence cannot reach past the code line that follows it.
  #[test]
  fn a_fenced_block_is_skipped_and_does_not_reach_past_code() {
    let fenced = "  /// ```\n  /// let a = \"the server MUST NOT process\";\n  /// ```\n";
    assert!(spans(fenced).is_empty());
    let unclosed = "  /// ```\n  let x = 1; // \"the server MUST NOT process\"\n";
    assert_eq!(spans(unclosed), ["the server MUST NOT process"]);
  }

  // An inline code span naming a quote character is masked, on a trailing
  // comment exactly as on a doc comment: leaving it in place pairs it with a
  // real quotation's and swallows a paragraph.
  #[test]
  fn a_quote_naming_code_span_is_masked_after_code_too() {
    let source = "  let x = 1; // the `\"` character, and \"the server MUST NOT process\"\n";
    assert_eq!(spans(source), ["the server MUST NOT process"]);
  }

  // A `.md` file is scanned like a `.rs` one: the convention is about the
  // quotation, not about which file it was copied into.
  #[test]
  fn a_markdown_quotation_is_read() {
    let source = "See RFC 9112 §9.6: \"the server MUST NOT process\" further requests.\n";
    assert_eq!(markdown_spans(source), ["the server MUST NOT process"]);
  }

  // Unlike `quotations`, a fence flushes the block on both toggles (see
  // `markdown_quotations`'s doc comment for why): a quotation that opens
  // before a fence and closes after it is silently uncounted rather than
  // spuriously spanning the fence. Without the flush this same input pairs
  // "beta" with "gamma" into one bogus span joining the two paragraphs.
  #[test]
  fn a_quotation_straddling_a_fence_is_not_joined() {
    let source = "Alpha \"beta\n```\ncode\n```\ngamma\" delta\n";
    assert!(markdown_spans(source).is_empty());
  }

  // `run` picks `markdown_quotations` or `quotations` by extension; this is
  // the one place that choice is exercised, so it is asserted directly rather
  // than resting on a human reading a printed count.
  #[test]
  fn spans_for_dispatches_by_extension() {
    let source = "See RFC 9112 §9.6: \"the server MUST NOT process\" further requests.\n";
    let (quoted, productions, skipped) = spans_for(Path::new("notes.md"), source);
    // The span carries the block's own citation as its third element.
    assert_eq!(
      quoted,
      vec![(1, "the server MUST NOT process".to_string(), Some(9112))]
    );
    assert!(productions.is_empty());
    assert_eq!(skipped, 0);
    let (quoted, productions, skipped) = spans_for(Path::new("notes.rs"), source);
    assert!(quoted.is_empty());
    assert!(productions.is_empty());
    assert_eq!(skipped, 0);
  }

  // An ABNF production reaches neither existing path: `mask_code_spans` erases
  // a backticked span holding a `"`, and `quoted_spans` only takes `"…"`. It
  // needs its own extractor, and this is the shape that finds one.
  #[test]
  fn a_backticked_production_is_extracted() {
    let line = "  /// RFC 9110 §8.3.1: `media-type = type \"/\" subtype parameters`";
    assert_eq!(
      super::abnf_spans(line),
      ["media-type = type \"/\" subtype parameters"]
    );
  }

  // Prose in backticks is not a production. The `=` is what distinguishes a
  // rule from a name, and requiring it is what keeps this extractor quiet.
  #[test]
  fn a_backticked_name_is_not_a_production() {
    assert!(super::abnf_spans("  /// see `open_request` and `Connection`").is_empty());
  }

  // `is_production` once saw only the FIRST character after `name`, so a Rust
  // equality check opened a production too. Requiring the SECOND character
  // not to be `=` closes that without rejecting `=/`, RFC 5234's
  // incremental-alternative operator.
  #[test]
  fn a_double_equals_is_not_a_production() {
    let line = "  // the EXACT fit, `need == out.len()`: the boundary between the two arms";
    assert!(super::abnf_spans(line).is_empty());
    let incremental = "  // `rule =/ extra-alternative` still opens one";
    assert_eq!(
      super::abnf_spans(incremental),
      ["rule =/ extra-alternative"]
    );
  }

  // A block naming exactly one RFC commits every production inside it to that
  // spec — the citation IS the anchor a bare `name =` cannot carry alone.
  #[test]
  fn a_block_naming_one_rfc_is_cited() {
    let block = "RFC 6455 §9.1's extension-param = token [ \"=\" (token | quoted-string) ]";
    assert_eq!(super::cited_rfc(block), Some(6455));
  }

  // The same RFC named twice is still one spec, not an ambiguity.
  #[test]
  fn a_block_naming_the_same_rfc_twice_is_still_one() {
    let block = "RFC 6455 §9.1's grammar, restated at RFC 6455 §1.3 for the reader";
    assert_eq!(super::cited_rfc(block), Some(6455));
  }

  // Two DIFFERENT RFCs in one block leave it unclear which spec a bare
  // `name =` inside it is a claim about — not this check's business, the same
  // way `grade` treats a quotation that anchors to no supplied spec.
  #[test]
  fn a_block_naming_two_rfcs_is_not_cited() {
    let block = "RFC 2616 §2.1's #rule, which RFC 9110 §5.6.1.2 restates";
    assert!(super::cited_rfc(block).is_none());
  }

  // Prose that names no RFC at all makes no checkable claim either.
  #[test]
  fn a_block_naming_no_rfc_is_not_cited() {
    assert!(super::cited_rfc("just an ordinary sentence about `last = false`").is_none());
  }

  // The gate is applied to the WHOLE block, not the line: a production
  // reached through `quotations` is a CANDIDATE only when its block names
  // exactly one RFC. Ambiguous and uncited blocks both withhold theirs — not
  // silently: each is counted as skipped rather than dropped without a trace.
  #[test]
  fn a_production_survives_only_in_a_single_rfc_block() {
    let cited = "  /// RFC 6455 §9.1's `extension-param = token`\n";
    let (_, productions, skipped) = quotations(cited);
    assert_eq!(
      productions,
      vec![(1, "extension-param = token".to_string())]
    );
    assert_eq!(skipped, 0);

    let ambiguous = "  /// RFC 2616 and RFC 9110 both define `token = 1*tchar`\n";
    let (_, productions, skipped) = quotations(ambiguous);
    assert!(productions.is_empty());
    assert_eq!(skipped, 1);

    let uncited = "  /// see `last = false` above\n";
    let (_, productions, skipped) = quotations(uncited);
    assert!(productions.is_empty());
    assert_eq!(skipped, 1);
  }

  // A production the citation gate would otherwise admit is withheld anyway
  // when a `gate-exempt:` marker names its exact text — the mechanism a
  // narrower `is_production` cannot be, because a marker names what it
  // exempts rather than a shape a broken production could also stop matching.
  #[test]
  fn a_gate_exempt_marker_is_recognised_by_its_exact_span() {
    let source = "// gate-exempt: q = 1 — a weight value in prose, not RFC 9110 grammar\n";
    let exempt = super::exempted_spans(source);
    assert!(exempt.contains("q = 1"));
    assert!(!exempt.contains("q = 2"));
  }

  // Prose before the em dash is the exemption; the rationale after it is not
  // part of what must match.
  #[test]
  fn a_gate_exempt_marker_stops_at_the_em_dash() {
    let exempt =
      super::exempted_spans("// gate-exempt: answerable = false — a Rust flag, not grammar\n");
    assert!(exempt.contains("answerable = false"));
    assert!(!exempt.iter().any(|span| span.contains('—')));
  }

  /// A minimal, hand-built spec for testing `grade_production` directly,
  /// independent of anything the workspace's own comments happen to cite.
  fn test_spec(name: &str, text: &str) -> super::Spec {
    super::Spec {
      name: name.to_string(),
      text: text.to_string(),
      lower: text.to_ascii_lowercase(),
    }
  }

  // `grade_production` is the function Ruling 7 narrowed to one spec and
  // Ruling 8 widened back to all of them. Pinned directly, with hand-built
  // specs, because the property must hold independently of whether the
  // workspace happens to contain a production whose citing block names a
  // different RFC than its real source — today it does (three
  // `handshake/*.rs` sites), but nothing should notice if that ever stops
  // being true.
  #[test]
  fn a_production_found_in_a_later_spec_still_passes() {
    let specs = [
      test_spec("rfc1", "an unrelated spec with no matching grammar at all"),
      test_spec("rfc2", "widget-param = token widget-value here"),
    ];
    let normalised: Vec<String> = specs
      .iter()
      .map(|spec| super::normalise(&spec.text))
      .collect();
    let mut checked = 0;
    assert!(
      super::grade_production(
        "widget-param = token widget-value",
        &specs,
        &normalised,
        &mut checked
      )
      .is_none()
    );
    assert_eq!(checked, 1);
  }

  // The property Ruling 8 must not have cost: a production in NO loaded spec
  // still fails, and still names one — the first, the same arbitrary
  // fallback `grade` uses for an unanchored quotation.
  #[test]
  fn a_production_in_no_spec_fails_and_names_one() {
    let specs = [
      test_spec("rfc1", "an unrelated spec with no matching grammar at all"),
      test_spec("rfc2", "widget-param = token widget-value here"),
    ];
    let normalised: Vec<String> = specs
      .iter()
      .map(|spec| super::normalise(&spec.text))
      .collect();
    let mut checked = 0;
    let graded = super::grade_production(
      "gadget-param = token gadget-value",
      &specs,
      &normalised,
      &mut checked,
    );
    assert_eq!(graded.map(|spec| spec.name.as_str()), Some("rfc1"));
    assert_eq!(checked, 1);
  }

  // Below the three-word floor: not a checkable claim, so `checked` does not
  // move — this is what keeps a stray two-token span from inflating the
  // denominator.
  #[test]
  fn a_span_below_the_word_floor_is_not_counted() {
    let specs = [test_spec("rfc1", "x=y is mentioned in here somewhere")];
    let normalised: Vec<String> = specs
      .iter()
      .map(|spec| super::normalise(&spec.text))
      .collect();
    let mut checked = 0;
    assert!(super::grade_production("x=y", &specs, &normalised, &mut checked).is_none());
    assert_eq!(checked, 0);
  }

  // The three answers `grade` used to collapse into one `None`. A green run
  // must not look the same as a run that could not check anything: a block
  // citing RFC 9782 (never loaded — it is not in `FETCHED`) is a checkable
  // claim this run could not honour, and that must surface rather than vanish.
  #[test]
  fn an_unloaded_citation_grades_as_unloaded() {
    let specs: Vec<super::Spec> = Vec::new();
    let mut checked = 0;
    let graded = super::grade(
      "the identifier is a valid URI reference and is compared",
      Some(9782),
      &specs,
      &mut checked,
    );
    assert!(matches!(graded, Some(super::Grade::Unloaded(9782))));
    assert_eq!(
      checked, 1,
      "an unloaded citation still counts as one this check governs"
    );
  }

  // The hole grading-by-citation closes: `rfc1` holds these exact words, but
  // the block cites `rfc2`, which does not — so this must FAIL, not silently
  // pass the way the pre-citation any-spec match did (a sentence attributed to
  // RFC 9110 passing because RFC 9112 happened to contain it too). The
  // attribution is read, not just present.
  #[test]
  fn a_quotation_attributed_to_the_wrong_loaded_spec_fails() {
    let specs = [
      test_spec(
        "rfc1",
        "the widget registry must reject a duplicate identifier",
      ),
      test_spec(
        "rfc2",
        "an unrelated spec discussing something else entirely",
      ),
    ];
    let mut checked = 0;
    let graded = super::grade(
      "the widget registry must reject a duplicate identifier",
      Some(2),
      &specs,
      &mut checked,
    );
    assert!(matches!(graded, Some(super::Grade::Reworded(spec, _)) if spec.name == "rfc2"));
    assert_eq!(checked, 1);
  }
}
