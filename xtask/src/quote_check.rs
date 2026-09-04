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
//! This is the rule for a span whose own block names no RFC this run loaded
//! ([`cited_rfcs`]) — the rule below, "attribution by citation", takes over
//! whenever it names one or more. For an unattributed span: an anchored,
//! prose-sized span must then appear in full and case-sensitively in one of
//! the specs it anchored in — several may hold the same opening, and a
//! verbatim match in any of them clears it, because with no citation naming
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
//! Anchoring and citation answer two DIFFERENT questions, asked in that
//! order, never one standing in for the other:
//!
//! 1. **Is this span demonstrably a quotation of some loaded spec at all?**
//!    Anchoring answers this, and only this — the span's own opening
//!    characters either appear in a loaded spec's text or they do not,
//!    regardless of what the surrounding block claims.
//! 2. **If so, which spec is it from?** An anchored span is graded against
//!    the specs its own block NAMES ([`cited_rfcs`]) — all of them, and
//!    only them — not against whichever loaded spec happens to share its
//!    opening text. This closes a hole the anchor-only rule always had: a
//!    sentence attributed to RFC 9110 used to pass because RFC 9112 happened
//!    to contain it too, and the citation itself was never read. A verbatim
//!    match in any ONE of the named specs clears the span, because a block
//!    naming several has accounted for all of them; picking one of the
//!    several instead was measured and rejected, and `grade`'s Ruling 12
//!    carries the numbers. An anchored span whose block names no RFC this
//!    run loaded keeps the any-spec anchored behaviour above, unchanged.
//!
//!    A span in none of its block's named specs, and anchoring in none of
//!    them either, is the case this cannot resolve on its own: it is either
//!    a quotation mis-transcribed from a named spec or a correct quotation
//!    of a spec the block never names. It is reported with both facts and
//!    no verdict ([`Grade::Foreign`]) — re-attributing it to whichever
//!    loaded spec contains the text is the repair that is always wrong.
//!
//! Letting the citation answer BOTH questions was tried and reverted: a
//! prose-sized span sitting anywhere in a block that cites an RFC for one
//! unrelated point is not thereby a quotation of it, and grading it as one is
//! exactly how a block's own rhetorical asides — a title, a question, an
//! author's paraphrase — got checked against spec text they were never
//! claiming to be.
//!
//! An UNANCHORED span's fate then depends on whether the block gave anyone a
//! REASON to expect a quotation (Ruling 10a):
//!
//! - The block cites a spec this run never loaded: "unanchored" proves
//!   nothing (this run was never given the text to match against), so
//!   [`Grade::Unloaded`] is the honest answer.
//! - The block cites a spec this run DID load: someone had reason to expect
//!   a quotation here and did not get one. Not a failure — it is counted
//!   separately (`unattributable`, printed by [`run`]) rather than either
//!   silently dropped or wrongly graded.
//! - The block cites nothing at all: nobody had any reason to think this
//!   was a quotation in the first place. This is the ORIGINAL silent
//!   `None`, uncounted anywhere — conflating "not my business" with "my
//!   business and I could not do it" is the same category error as
//!   reporting the author's own words as a failure, just moved from the
//!   pass/fail line to the backlog count instead.
//!
//! `unattributable` is therefore a BACKLOG of untriaged spans, not a defect
//! list: even narrowed to blocks that cite a loaded spec, it still holds two
//! different things a human has not yet told apart — a possible quotation
//! that genuinely does not match (worth reading), and the author's own
//! rhetorical prose that happens to sit near a citation for something else
//! (not worth reading twice). A reader who takes the count for a defect tally
//! will either panic at its size or learn to ignore it; both are worse than
//! knowing what it actually holds.
//!
//! **The backlog is still a check, and it is the only one a FABRICATION can
//! trip.** An invented sentence matches no spec, so it anchors in nothing, so
//! it can never be graded — naming an RFC in its block moves it from invisible
//! to counted and no further. [`UNTRIAGED`] is what makes counted checkable:
//! the backlog is held to a number PER FILE, so a file that grows one fails,
//! whatever the total does. **Tripping a fabrication is not the same as
//! being proof against one**, and the gap is named at that constant rather
//! than left for a reader to find: what it detects is GROWTH and PLACEMENT,
//! and what it tracks is triage. What it does not do is read the backlog for
//! anyone; see that constant for why the numbers are pinned in both directions
//! and what the count would cost to drive to zero.
//!
//! **What this still cannot see**, stated rather than merely being the case:
//!
//! - A quotation so reworded, or so short an excerpt, that its own first
//!   [`ANCHOR_CHARS`] characters match nothing in any loaded spec is beyond
//!   this tool's reach — anchoring is the floor the whole check stands on, and
//!   nothing narrows a spec it cannot even find a foothold in.
//! - A fabricated span put in the place of a genuine untriaged one INSIDE a
//!   single file. The file's count does not move, so [`UNTRIAGED`] has nothing
//!   to disagree with, and the swap is invisible to a run. Pinning the number
//!   exactly does not close this — a growth-only budget misses the same case,
//!   and the two are indistinguishable here. What the exact per-file number
//!   DOES close is a different pair of cases, both named at that constant.
//!
//! An ABNF production goes the OTHER way once admitted as a candidate: it is
//! checked against every loaded spec regardless of citation — see
//! [`grade_production`]'s doc comment for why. The two are intentionally
//! asymmetric: a quoted SENTENCE that anchors inside a citing block is almost
//! always that RFC's own prose, but a grammar RULE beside a citation is
//! routinely shown for comparison with a different spec's.
//!
//! ## Where a fence is reached into, and the forms still outside
//!
//! Both extractors are shape-bound, and each shape leaves a form outside the
//! check. Neither is a defect found and left; both are boundaries, and a
//! boundary that no run states is the disease this command exists to remove.
//!
//! - **Grammar inside a FENCED block.** [`abnf_spans`] reads backticked
//!   spans, and a fenced line is skipped before it ever runs — while a fence
//!   is how this workspace transcribes most of its grammar, several
//!   productions at a time, one rule per line. Reaching those lines needed a
//!   rule for which fences hold grammar and which hold Rust (this crate's doc
//!   comments are full of both), and the fence's own INFO STRING is that rule
//!   ([`fence_holds_grammar`]): a `text` fence is text its author told rustdoc
//!   not to compile, and [`is_production`] then decides its lines one at a
//!   time, exactly as it does a backticked span's. A fence tagged anything
//!   else keeps the old boundary, and the production-shaped lines inside one
//!   are still COUNTED — so what was read and what remains are both numbers
//!   in the run's own output. What makes the info string a rule rather than a
//!   heuristic invented to move a number: the author declares it, it excludes
//!   every doctest in the workspace without any judgement about content, and
//!   it is not the production's right-hand side — which nothing here may be
//!   keyed on, for the reason [`exempted_spans`] records.
//! - **A QUOTATION inside a fenced block.** Untouched by the above, and
//!   deliberately: a quote character inside code is not opening a quotation,
//!   which is why fences are skipped at all. Only the ABNF path reaches in.
//! - **A quotation set as a BLOCKQUOTE.** [`quoted_spans`] pairs `"` marks,
//!   so spec text quoted by indentation and a leading `>` instead carries
//!   nothing for it to pair. That form is NOT counted, and the difference
//!   from the one above is worth stating: a production has a shape to
//!   recognise, while an indented paragraph of prose is indistinguishable
//!   from any other indented paragraph. Counting it would mean counting
//!   every blockquote in the workspace, which measures nothing.
//!
//! ## What a production must BE before it is compared
//!
//! The comparison is a substring test, so a production with its tail cut off
//! still matches: `transfer-coding = token *( OWS ";" OWS transfer-parameter`
//! is a substring of RFC 9110 §10.1.4's own text, and the run that graded it
//! printed `verbatim` and meant it. That is not a hypothetical. A transcription
//! that carried §10.1.4's inner `transfer-parameter` rule and left out the
//! CONTAINER it sits in passed this gate — and the container is the second
//! place the two grammars differ, §5.6.6 bracketing the slot where §10.1.4
//! does not. It was verbatim. It was also half a grammar, and nothing that
//! runs found it — only reading the ABNF by hand did.
//!
//! So a candidate is now asked to BE a rule before it is asked whether it is
//! the spec's: a name, a definition operator, and a right-hand side that
//! balances ([`rule_fault`]). `(` and `[` must close, in that nesting order;
//! `"` and `<` open a `char-val` and a `prose-val`, which nothing is read
//! inside of; `;` outside both begins an ABNF comment and ends the rule; and
//! something must be left. It is deliberately NOT part of [`is_production`],
//! because keying admission on the right-hand side would make a broken
//! production stop looking like a production — the gate's own defect would
//! then delete the item it should be reporting. Admitted by the name and the
//! operator, FAILED on the right-hand side.
//!
//! Two boundaries come with it, and both are the rule's, not the tree's:
//!
//! - **ABNF wraps, and a wrapped line is not a truncation.** The RFCs set
//!   `media-range` over four lines, and this workspace transcribes them that
//!   way, so a fenced rule's first line ends inside a group it does not close.
//!   [`read_fenced_line`] joins the continuation lines onto what the shape
//!   test reads while leaving what the COMPARISON reads a single line. A rule
//!   wrapped inside a BACKTICKED span wraps for the other reason — the comment
//!   ran out of line — and used to escape the check entirely rather than be
//!   misjudged by it: pairing backticks within a line found no closer and
//!   extracted no span at all, so the rule was never graded and never counted.
//!   [`abnf_spans`] now reads a PARAGRAPH, which is the unit a Markdown code
//!   span is allowed to wrap across, and pairs backtick RUNS the way rustdoc
//!   does.
//! - **A truncation on a boundary this cannot see still passes.** A rule with
//!   no brackets — `media-type = type "/" subtype parameters` — can lose its
//!   last name and still balance, still be a substring, and still be called
//!   verbatim. So can one cut at a `/` between two complete alternatives. What
//!   this rejects is a production truncated INSIDE a group, which is the shape
//!   the measured defect had and the shape most truncations of an HTTP
//!   production have, because HTTP's productions are mostly groups. It does
//!   not decide that a transcription is the WHOLE of its rule, and nothing
//!   that reads only the comment can: the rule's own name is the only thing
//!   that says how much of it there should be.
//!
//! [`MIN_PRODUCTION_WORDS`] is the floor under BOTH verdicts, and it is the
//! same floor as before: a span below it is neither malformed nor verbatim but
//! none of this check's business, so `q=` and `realm=` stay unreported exactly
//! as they were. That constant carries what widening past it was measured to
//! cost.
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
//! One rule is NOT shared, and the asymmetry is deliberate:
//!
//! - **Editorial brackets** (`[…]`), including the RFCs' own inline
//!   `[RFC2616]` references, go from a QUOTATION only
//!   ([`strip_bracket_insertions`]). A PRODUCTION keeps them
//!   ([`normalise_production`]): in ABNF a bracket is optional-element
//!   syntax, so it is the rule rather than a mark around it, and taking it
//!   from both sides at once left a comparison that agreed with itself about
//!   a stub and called it verbatim. [`strip_bracket_insertions`] carries the
//!   worked example, and is the one place it is spelled out.
//!
//! Fenced code blocks inside a doc comment are skipped, and an inline code span
//! containing a `"` is masked: both are code, and their quote characters would
//! otherwise pair with a real quotation's and produce nonsense spans. The ABNF
//! path is the one exception, and only for a fence [`fence_holds_grammar`]
//! admits: it takes the production-shaped lines and nothing else, so no quote
//! character inside a fence is ever paired.
//!
//! The masking unit is a PARAGRAPH ([`mask_paragraph`]), and it was a line.
//! A code span that wraps across two comment lines met no closing backtick on
//! the first of them, so the masker gave up and emitted the rest of that line
//! as prose — leaking every quote character inside the span into the block.
//! An ODD number of leaked quotes displaces every real quotation after it,
//! since [`quoted_spans`] pairs left to right, and where the prose between the
//! leak and the quotation falls under the two floors above, [`grade`] returns
//! before it counts anything: the quotation is then never graded, never
//! counted and never reported. That is the escape the ABNF bullet above
//! describes, reached through the quotation path, and
//! `a_code_span_wrapped_across_lines_does_not_leak_its_quotes` is the block it
//! used to swallow. The unit is the paragraph rather than the whole block
//! because a code span may not cross a blank line: pairing over a block pairs
//! two paragraphs' unrelated strays and masks the quotation between them.
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
  collections::{BTreeMap, HashSet},
  fs,
  path::{Path, PathBuf},
  process::Command,
};

type Error = Box<dyn std::error::Error>;

/// The candidate ABNF productions found in one file.
type Spans = Vec<Candidate>;

/// How one paragraph's lines reach the comment block: one masked body per
/// line, in the paragraph's own order.
///
/// [`mask_paragraph`] is the only implementation this command runs. It is a
/// parameter, and not a call, so that the tests can drive the REAL extraction
/// over the per-line masking that shipped before this — see
/// [`take_paragraph`].
type Masker = fn(&[(usize, &str)]) -> Vec<String>;

/// One ABNF production candidate: the span as extracted, and the whole rule
/// that span is part of.
///
/// The two hold the same text for a BACKTICKED candidate. Such a span may
/// wrap across the lines of its paragraph and [`abnf_spans`] joins it back
/// together while extracting it, so what comes out is already the whole of
/// what its author wrote — there is nothing left for `rule` to add. They
/// differ for a FENCED one, where a rule too long for a line is continued on
/// the next, indented, exactly as the RFCs themselves set it: `span` is then
/// the one line, and `rule` is that line with its continuations joined on.
///
/// Both are kept because they answer different questions and neither answers
/// the other's. [`grade_production`] compares `span`, because the spec's own
/// text is what a transcribed line must match and the joining is this
/// extractor's doing rather than the author's. [`rule_fault`] reads `rule`,
/// because "is this a complete rule" is a question about the RULE — a first
/// line ending mid-group is not a truncation, it is a line.
struct Candidate {
  /// The source line the span's opening backtick, or its fenced line, is on.
  line: usize,
  /// The span as extracted: one backticked span, or one line of a fence.
  span: String,
  /// The whole rule `span` belongs to — `span` itself, or `span` with the
  /// fenced continuation lines behind it joined on.
  rule: String,
}

/// A quotation found in one file, paired with the source line its opening
/// mark is on and every RFC its block named ([`cited_rfcs`]).
///
/// The citations travel WITH the span rather than being looked up again at
/// grading time: they are a property of the block the span was cut from, and
/// the block is gone by the time `run` gets to grading.
type QuotedSpans = Vec<(usize, String, Vec<u32>)>;

/// Everything one file's comments held for this check — what it can grade,
/// and what it reached but cannot.
///
/// A struct rather than a tuple because most of the fields are bare counts,
/// and a caller reading `(spans, productions, 100, 7, 14, 33, 0)` has no way
/// to tell which boundary is which.
struct Extracted {
  /// Quoted spans, for [`grade`].
  quoted: QuotedSpans,
  /// ABNF production candidates for [`grade_production`]: a backticked span
  /// whose block named at least one RFC, and a production-shaped line inside
  /// a fence [`fence_holds_grammar`] admitted.
  productions: Spans,
  /// Production-shaped backticked spans whose block named no RFC at all:
  /// prose that made no claim about any spec, so there is nothing here for
  /// this check to grade. A block naming SEVERAL is no longer among them —
  /// see [`cited_rfcs`] for what counting it as one cost, measured.
  uncited: usize,
  /// Fenced blocks whose info string [`fence_holds_grammar`] admitted.
  fences_read: usize,
  /// How many of `productions` were read from inside those fences — the
  /// numerator this widening added, printed beside its own denominator.
  fenced_read: usize,
  /// Fenced blocks whose info string [`fence_holds_grammar`] declined.
  fences_skipped: usize,
  /// Production-shaped lines inside a DECLINED fence, which this extractor
  /// still does not reach — see the module doc's boundary section, and
  /// [`is_production`] for what "production-shaped" means. Counted so the
  /// boundary that remains is a number in the run's own output rather than a
  /// fact about the code that only a reader of the code can find.
  fenced: usize,
  /// Blocks holding an ODD number of quote marks — see [`Unpaired`].
  unpaired: Vec<Unpaired>,
}

/// A comment block whose quote marks do not pair, with one left over.
///
/// [`quoted_spans`] pairs left to right across the whole block, so a leftover
/// mark is not a local mistake: every quotation after the one that consumed
/// the wrong partner is cut at the wrong place, and the last one in the block
/// is not extracted at all — it becomes an opener with nothing to close on.
/// That is the disappearance [`mask_paragraph`] closed for a leaked quote,
/// arriving from the author's own prose instead of from a code span, and it is
/// the one this workspace held off with a hand-maintained convention: a
/// `gate-exempt:` marker naming a field value whose quoted-string does not
/// close is kept OUT of the doc comment it belongs to, in a block of its own,
/// because the lone mark it carries would otherwise shift every pairing in
/// that block by one. See [`UNPAIRED`] for where that convention held and the
/// place it did not.
///
/// A convention people have to remember is a guard at one entrance. This is
/// the gate saying so out loud rather than a rule about how to write a
/// comment: nothing here guesses which mark the author meant, only that the
/// block cannot be paired as written.
struct Unpaired {
  /// The first line of the block.
  at: usize,
  /// The line the leftover mark sits on.
  mark: usize,
  /// How many marks the block holds, after code spans are masked.
  quotes: usize,
}

/// The default, gitignored cache directory, relative to the workspace root.
pub const DEFAULT_DIR: &str = ".rfc-cache";

/// The specs `--fetch` downloads: the ones this workspace's comments cite.
///
/// RFC 2616 is deliberately absent. It is obsolete — superseded first by the
/// 723x series and then by the 91xx series — so a comment citing it is either
/// quoting a dead spec a live one now governs, or a deliberate historical
/// note; either way, adding an obsolete RFC to make a production pass is the
/// same shape of bending this gate as loosening the extractor would be.
///
/// An RFC belongs here as soon as the workspace has the TEXT of it on disk, not
/// when a quotation of it first lands. `--fetch` builds the cache CI grades
/// against, so a spec present in a developer's `.rfc-cache` and absent from
/// this list grades locally and reports [`Grade::Unloaded`] in CI — the
/// local-green/CI-red trap this list has already sprung once, over RFC 2046.
/// RFC 2045 was added here for that reason before anything quoted it.
///
/// RFC 6454 was added when the extractor first reached a production of it.
/// `websocket-proto` reads `Origin` as one SP-separated list because RFC 6454
/// §7.1 says so, and the rule saying so sat in a comment that WRAPPED it across
/// two lines — so until [`abnf_spans`] read a paragraph rather than a line,
/// there was no span to grade and no reason to notice the spec was missing. It
/// is live law for a field this workspace parses, which is the same footing RFC
/// 822 stands on below, and adding it moved nothing else: the untriaged
/// backlog, both citation counts and the graded total were identical either
/// side of it.
///
/// RFC 822 is here despite being obsolete, and it is not the exception the
/// paragraph above forbids. RFC 2045 §1 makes it LIVE law for a MIME body
/// part's header fields — "All of the header fields defined in this document
/// are subject to the general syntactic rules for header fields specified in
/// RFC 822." — so `http-semantics` reads a body part's `Content-Type` in RFC
/// 822's lexical classes, and those productions are gradeable only against RFC
/// 822's own text. That is the opposite of quoting a dead spec a live one now
/// governs: the live spec is what sends a reader here.
///
/// RFC 4647 stands where RFC 2046 does: RFC 9110 hands a production OUT to it.
/// §12.5.4 spells `Accept-Language`'s element
/// `language-range  = <language-range, see [RFC4647], Section 2.1>` — a
/// `prose-val`, so RFC 9110's own text holds no grammar to grade a transcription
/// of it against. `http-semantics` reads that field, so the rule it implements
/// is RFC 4647 §2.1's `language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*"`
/// and is gradeable only against RFC 4647.
const FETCHED: &[u32] = &[
  822, 2045, 2046, 3986, 4647, 5322, 6454, 6455, 7692, 8441, 9110, 9111, 9112, 9113, 9114, 9220,
];

/// The untriaged backlog, per file, as it stands — and the whole of what makes
/// that backlog a check rather than a number.
///
/// # What this closes
///
/// This gate could not fail a FABRICATED quotation, and one shipped. A sentence
/// invented and attributed to §5.5 matches no cached RFC, so it anchors in
/// nothing; an unanchored span is at best `unattributable`, which [`run`]
/// PRINTS and never fails on. Naming the RFC in the block moved such a span
/// from invisible to counted, and counted is not checked. The module doc admits
/// the hole in its own words, and this is a PARTIAL fix beside that admission:
/// it closes the ways such a span can be ADDED or MOVED without the numbers
/// disagreeing, and the section below names the one it leaves open.
///
/// # Why per-file counts rather than a triaged list
///
/// Ninety-seven spans is a week of reading, and the module doc says why the
/// backlog is not a defect list: it holds two different things a human has not
/// told apart. What can be done without that week is deny it any room to GROW
/// unnoticed, which is what a fabrication needs when it is ADDED to a file. One
/// that REPLACES a span needs no room at all; the section below names that case
/// and says plainly that this table does not close it.
///
/// # Pinned exactly, and per FILE — what each half closes, and what neither does
///
/// A file's count must EQUAL its entry, and the entries are per file rather
/// than one workspace total. The two halves close different things:
///
/// - **Per file, rather than one total.** Delete a genuine untriaged span in
///   one file and add a fabricated one in another, and a single workspace
///   total does not move. Two per-file numbers both do, and the failure names
///   both files. Cross-file substitution, and any movement of spans between
///   files, is what this half sees.
/// - **Exact, rather than a ceiling.** A budget that only fails on growth lets
///   the backlog SHRINK unrecorded — a span deleted, reworded past the
///   extractor, or moved into a fence this reads differently, with nothing
///   saying so. It also makes triage visible: reading a span and repairing or
///   exempting it reds this gate with the smaller number to write down, which
///   is the ratchet. It is the discipline `doc-check`'s committed snapshot
///   already runs on: a number that changed in EITHER direction is a change
///   someone has to look at.
///
/// **What neither half closes: substitution inside ONE file.** Delete a genuine
/// untriaged span, add a fabricated one in the same file, and the count does
/// not move — exactly as it would not under a growth-only budget. Requiring the
/// exact number changes nothing about that case, and the module doc carries the
/// hole beside the anchoring one.
///
/// So, plainly, what this gate IS: a detector of GROWTH and of PLACEMENT, and a
/// tracker of triage. It is not fabrication-proof, and a green run does not say
/// that no span in this backlog was invented — only that no file holds a
/// different number of them than the last person to look wrote down.
///
/// A file absent from this table must hold ZERO. That half is enforced only
/// when the run is not `--include-ignored`, because `docs/` is gitignored: it
/// exists on a developer's disk and not in CI, so a table listing its files
/// would be a table CI could never satisfy. The files that ARE listed are
/// tracked, present in both modes, and checked in both.
///
/// Regenerate the numbers from the run's own report: a failure names the file
/// and both counts.
const UNTRIAGED: &[(&str, usize)] = &[
  ("CHANGELOG.md", 5),
  ("http1-proto/CHANGELOG.md", 1),
  ("http1-proto/src/body/encode.rs", 4),
  ("http1-proto/src/body/mod.rs", 5),
  ("http1-proto/src/connection/inbound.rs", 5),
  ("http1-proto/src/connection/mod.rs", 10),
  ("http1-proto/src/connection/outbound.rs", 3),
  ("http1-proto/src/connection/tests.rs", 9),
  ("http1-proto/src/connection/tunnel.rs", 8),
  ("http1-proto/src/event/mod.rs", 3),
  ("http1-proto/src/head/encode.rs", 3),
  ("http1-proto/src/head/mod.rs", 1),
  ("http1-proto/src/head/view.rs", 1),
  ("http1-proto/src/validate/mod.rs", 1),
  ("http1-proto/tests/smuggling.rs", 2),
  ("http3-proto/README.md", 1),
  ("http3-proto/src/connection/mod.rs", 2),
  ("websocket-proto/src/handshake/connect.rs", 4),
  ("websocket-proto/src/handshake/fields.rs", 5),
  ("websocket-proto/src/handshake/h1/client.rs", 1),
  ("websocket-proto/src/handshake/h1/server.rs", 6),
  ("websocket-proto/src/negotiation.rs", 3),
  ("wren-compio/src/handshake/mod.rs", 1),
  ("wren-compio/src/handshake/tests.rs", 1),
  ("wren-reactor/src/handshake/mod.rs", 1),
  ("wren-reactor/src/handshake/tests.rs", 1),
  ("xtask/src/handshake_diff.rs", 1),
  ("xtask/src/quote_check.rs", 3),
];

/// The comment blocks whose quotation marks do not pair, per file, as they
/// stand — and what makes that a check rather than a printed number.
///
/// # What this closes
///
/// [`quoted_spans`] pairs marks left to right across a whole BLOCK, so one
/// leftover mark is not a local mistake: every quotation behind it is cut at
/// the wrong place and the last is not extracted at all. That is the same
/// disappearance [`mask_paragraph`] closed for a quote leaked out of a code
/// span, arriving from the author's own prose instead — and this workspace was
/// holding it off by CONVENTION. `websocket-proto/src/negotiation.rs` keeps a
/// `gate-exempt:` marker out of the doc comment below it, in a block of its
/// own, and its comment says why: the span it names carries a lone mark, and
/// writing it inside would shift every pairing in that block by one.
/// `auth-corpus/src/main.rs` does the same with the same span.
///
/// A convention people have to remember is a guard at one entrance, and the
/// third entrance was already open when this table was first filled in:
/// `http-semantics/src/auth/mod.rs`'s four markers sit directly against the
/// module doc with no blank line between them, so a `//` line continues the
/// `//!` block and the module doc's own block holds 17 marks. It is harmless
/// only by position — the lone mark is the last of the seventeen, so the
/// sixteen in front of it still pair with each other. Move a marker, or add
/// one, and the module doc's quotations start being cut somewhere else.
///
/// # Why counts per file rather than a fixed list of blocks
///
/// Same reason [`UNTRIAGED`] holds counts: a block is identified by the line
/// it starts on, and every edit above it moves that line. A count per file is
/// stable under editing and still fails on a block that APPEARS, which is the
/// case this exists to catch.
///
/// What neither table can see is one entry replacing another in the same file
/// at the same count — a block balanced and a different one unbalanced in one
/// edit here, a span triaged and another appearing there. It is ONE limit
/// shared by the two tables, not two independent oversights, and it is the
/// price of identifying a site by a count instead of by a line number that
/// every edit above it moves.
///
/// # What is in here, and why each one is
///
/// - `http-semantics/src/auth/mod.rs` — the module doc above, and the one
///   entry here that is a comment worth changing rather than a fact about
///   this extractor or a deliberate marker. It is left alone in the branch
///   that added this table because that file is not this change's to edit.
/// - `auth-corpus/src/main.rs`, `websocket-proto/src/negotiation.rs` — a
///   `gate-exempt:` marker naming a field value whose quoted-string does not
///   close, isolated in a block of its own exactly as the convention says.
///   The lone mark is the whole point of the span being named, so these are
///   deliberate and stay.
/// - `xtask/src/doc_check.rs` — four blocks that are not comments at all. They
///   are continuation lines of multi-line Rust string literals — two `format!`
///   templates, a fixture holding doc-comment text and a fixture holding
///   captured rustc stderr — whose contents include a `//` or a `///`, and the
///   lone mark is the one that CLOSES the Rust string. [`trailing_comment_at`]
///   cannot know that: a string left open at end of line ends its walk, so the
///   line after it is read as fresh code. That boundary is the extractor's, not
///   the comment's, and is recorded here rather than worked around. A fifth
///   was a real comment, `the opening '"'` describing the byte it steps over,
///   and it is spelled DQUOTE now — the same repair this table asks of anyone
///   who lands in it.
///
/// Regenerate from the run's own report: a failure names the file, both
/// counts, and every block behind them.
const UNPAIRED: &[(&str, usize)] = &[
  ("auth-corpus/src/main.rs", 1),
  ("http-semantics/src/auth/mod.rs", 1),
  ("websocket-proto/src/negotiation.rs", 1),
  ("xtask/src/doc_check.rs", 4),
];

/// How much of a span must be found in a spec for the span to be treated as a
/// quotation OF that spec.
const ANCHOR_CHARS: usize = 48;

/// The shortest quotation this check governs, in words.
const MIN_WORDS: usize = 5;

/// The shortest quotation this check governs, in characters.
const MIN_CHARS: usize = 24;

/// One spec, joined and normalised, beside an ASCII-lowercased copy of itself
/// and a second normalisation for the ABNF path.
///
/// The copy is ASCII-lowercased rather than lowercased so that an offset found
/// in one is an offset into the other: only then can a case-insensitive hit be
/// shown back to the reader in the spec's OWN characters, which is the whole
/// point of reporting it.
struct Spec {
  name: String,
  /// [`normalise`]d: what a QUOTATION is compared against.
  text: String,
  /// [`normalise_production`]d — the same text with `[ … ]` left in place.
  /// What a PRODUCTION is compared against, because RFC 5234's brackets are
  /// grammar rather than the editorial mark [`strip_bracket_insertions`]
  /// removes. Built once at load time, so grading `n` productions costs
  /// O(n + specs) of normalising rather than O(n × specs).
  grammar: String,
  lower: String,
}

/// What went wrong with one quoted span — including that it could not be
/// checked at all.
enum Grade<'a> {
  /// The spec has these words, in other cases.
  Recased(&'a Spec, String),
  /// The spec begins this way and then says something else.
  Reworded(&'a Spec, String),
  /// The span is in none of the specs its block names, and does not even
  /// BEGIN as any of them — it begins as some other loaded spec's text.
  ///
  /// Kept apart from [`Grade::Reworded`] because the two ask the reader for
  /// different things and only one of them can be answered by editing the
  /// words inside the marks. `Reworded` names a spec the block cites and the
  /// span demonstrably starts in, so the quotation drifted and the spec's own
  /// text is the fix. This one names two DIFFERENT specs — the ones cited and
  /// the one the span starts in — because which of them is wrong is a fact
  /// about the author's intent that no rule here can settle: either the
  /// quotation was mis-transcribed from a cited spec, or it is a correct
  /// quotation of a spec the block never names. Reporting it as `Reworded`
  /// would print a cited spec's text at the anchor offset the span does not
  /// have — in practice that spec's cover page — and invite the one repair
  /// that is always wrong, re-attributing the sentence to whichever spec is
  /// nearest to hand.
  Foreign {
    /// Every RFC the block named.
    cited: Vec<u32>,
    /// A loaded spec the span's opening characters DO appear in, which the
    /// block never named. The first such spec in load order when there are
    /// several, arbitrarily and for the same reason the any-spec fallback
    /// names its first: this grade's claim is that the block names none of
    /// them, not that this one is the right one.
    begins_as: &'a Spec,
  },
  /// The block cited these RFCs and no spec by any of those names was loaded
  /// — a checkable claim this run could not check, not a pass.
  Unloaded(Vec<u32>),
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
  let mut sources = Vec::new();
  let mut skipped = 0usize;
  collect_sources(&root, &mut sources, include_ignored, &mut skipped)?;
  sources.sort();

  let mut checked = 0usize;
  let mut failures = 0usize;
  // Prose-sized, in a block citing a LOADED spec, and still didn't anchor to
  // any loaded spec's text — a backlog of untriaged spans (Ruling 10a), not
  // a defect count: never silent, never a failure. A block citing nothing
  // gives no reason to expect a quotation and stays the original, uncounted
  // `None` — see `grade`'s doc comment (Ruling 9, Ruling 10a) for the full
  // three-way split.
  let mut unattributable = 0usize;
  // Ruling 11: of `checked`, how many were graded against the ONE spec their
  // block cited (`narrow`) versus against any loaded spec because the block
  // named none or several (`fallback`) — see `grade`'s doc comment for why
  // this is counted rather than guessed at.
  let mut narrow = 0usize;
  let mut fallback = 0usize;
  let mut abnf_checked = 0usize;
  let mut abnf_failures = 0usize;
  // Productions that never reached the comparison because they are not whole
  // rules — counted apart from `abnf_failures`, whose denominator is
  // `abnf_checked`, the number of productions the comparison DID read.
  let mut abnf_malformed = 0usize;
  let mut abnf_skipped = 0usize;
  let mut abnf_exempt = 0usize;
  // The fenced half of the ABNF path, both sides of it: what the info-string
  // rule read (`fences_read`, `abnf_fenced_read`) and what it left behind
  // (`fences_skipped`, `abnf_fenced`). The second pair is not a failure and
  // not a candidate — it is the printed boundary that remains.
  let mut fences_read = 0usize;
  let mut abnf_fenced_read = 0usize;
  let mut fences_skipped = 0usize;
  let mut abnf_fenced = 0usize;
  // A quotation this reads as a deliberate historical citation rather than a
  // checkable claim against a loaded spec — same marker, same mechanism as
  // `abnf_exempt`, extended to quotations (Ruling 9).
  let mut quote_exempt = 0usize;
  // The backlog split by the file it sits in, which is what `UNTRIAGED` is
  // checked against. The running total above stays as it was: one is the
  // number the report prints, the other is the number the gate holds.
  let mut untriaged_by_file: BTreeMap<String, usize> = BTreeMap::new();
  // And the spans themselves, so a file that drifts can be ACTED on. The count
  // alone told a reader which file to look in and nothing about where, and the
  // cheap answer to that is to add the file to `UNTRIAGED` — which is a bless
  // of exactly the shape this table exists to refuse. They are carried here
  // because they are already in hand: `grade` is handed the normalised span and
  // the line it sits on, and dropped both on the floor when it counted one.
  let mut untriaged_spans: BTreeMap<String, Vec<(usize, String)>> = BTreeMap::new();
  // Blocks whose quote marks do not pair, the total for the printed line and
  // the split `UNPAIRED` is held against — the same shape as the untriaged
  // backlog above, for the same reason: a number nobody can act on is a
  // number the next reader raises.
  let mut unpaired_blocks = 0usize;
  let mut unpaired_by_file: BTreeMap<String, usize> = BTreeMap::new();
  let mut unpaired_sites: BTreeMap<String, Vec<Unpaired>> = BTreeMap::new();
  for source in &sources {
    let text = fs::read_to_string(source)?;
    let shown = crate::report::site(source.strip_prefix(&root).unwrap_or(source));
    let untriaged_before = unattributable;
    let extracted = spans_for(source, &text);
    let (spans, productions) = (extracted.quoted, extracted.productions);
    abnf_skipped += extracted.uncited;
    fences_read += extracted.fences_read;
    abnf_fenced_read += extracted.fenced_read;
    fences_skipped += extracted.fences_skipped;
    abnf_fenced += extracted.fenced;
    if !extracted.unpaired.is_empty() {
      unpaired_blocks += extracted.unpaired.len();
      *unpaired_by_file.entry(shown.clone()).or_default() += extracted.unpaired.len();
      unpaired_sites
        .entry(shown.clone())
        .or_default()
        .extend(extracted.unpaired);
    }
    // Per-file: a marker in one file cannot exempt a span in another. Read
    // once and reused below for both quotations and productions. Dispatched
    // by extension exactly as `spans_for` above dispatches extraction, so a
    // `.md` file's marker is read in its own comment syntax.
    let exempt = exempted_spans_for(source, &text);
    for (line, span, cited) in spans {
      if exempt.contains(&span) {
        quote_exempt += 1;
        continue;
      }
      for segment in span.split(['…']).flat_map(|part| part.split("...")) {
        let quoted = normalise(segment);
        // `grade` answers `None` for two different things: a span too short to
        // be a quotation at all, and one it counted as untriaged. The counter
        // is what tells them apart, so it is read on both sides of the call
        // rather than inferred from the span.
        let untriaged_before_span = unattributable;
        let Some(grade) = grade(
          &quoted,
          &cited,
          &specs,
          &mut checked,
          &mut unattributable,
          &mut narrow,
          &mut fallback,
        ) else {
          if unattributable > untriaged_before_span {
            untriaged_spans
              .entry(shown.clone())
              .or_default()
              .push((line, quoted));
          }
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
          Grade::Foreign { cited, begins_as } => {
            println!("{shown}:{line}: quotation is in none of the specs its block names");
            println!("  comment: \"{quoted}\"");
            println!("  block names: {}", rfc_list(&cited));
            println!(
              "  begins as: {}, which the block never names",
              begins_as.name
            );
          }
          Grade::Unloaded(numbers) => {
            println!(
              "{shown}:{line}: cites {}, none of which was loaded",
              rfc_list(&numbers)
            );
            println!("  comment: \"{quoted}\"");
            println!(
              "  add {} to FETCHED and run \
               `cargo run -p xtask -- quote-check --fetch`",
              numbers
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
            );
          }
        }
      }
    }
    if unattributable > untriaged_before {
      untriaged_by_file.insert(shown.clone(), unattributable - untriaged_before);
    }
    for candidate in productions {
      if exempt.contains(&candidate.span) {
        abnf_exempt += 1;
        continue;
      }
      // Is this a whole RULE, before anything asks whether it is the spec's.
      // Read from `rule` rather than `span`, so a fenced rule wrapped across
      // lines is judged whole — see `read_fenced_line`. Held to the same
      // floor the comparison is held to, so one admission test decides what
      // this check is looking at at all.
      if is_checkable_production(&candidate.rule)
        && let Some(fault) = rule_fault(&candidate.rule)
      {
        abnf_malformed += 1;
        println!(
          "{shown}:{}: ABNF production is not a whole rule",
          candidate.line
        );
        println!("  comment: `{}`", candidate.rule);
        println!("  {}", fault.reason());
        continue;
      }
      // A deliberately elided production promises only that what remains is
      // verbatim — the same reading `run` already gives a quotation span.
      for segment in candidate
        .span
        .split(['…'])
        .flat_map(|part| part.split("..."))
      {
        if grade_production(segment, &specs, &mut abnf_checked).is_none() {
          continue;
        }
        abnf_failures += 1;
        // Which spec is NOT named, and the omission is the message: every
        // loaded spec was searched, so the fact reported is that none of them
        // carries these characters. Naming one would have to name it
        // arbitrarily — `grade_production` searches them all and nothing here
        // says which one a production meant to be quoting — and an arbitrary
        // name reads as an attribution, sending the reader to compare against
        // a spec that never had the rule.
        println!(
          "{shown}:{}: ABNF production is in none of the {} loaded specs",
          candidate.line,
          specs.len()
        );
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
  // failure, but it is not silence either — a fenced-off count is how a real,
  // correctly-transcribed production nothing here can grade stays VISIBLE as
  // unchecked instead of vanishing the way it did before this line existed.
  // `gate-exempt` marks the same thing where a citation cannot (Ruling 9): a
  // deliberate reference to an obsolete spec whose successor does not carry
  // the same words, so there is no loaded spec left to grade it against.
  // `negotiation.rs` holds one of each — its RFC 2616 "implied *LWS rule"
  // QUOTATION was the first, and its RFC 2616 §2.2 `qdtext` rule joined it
  // when the paragraph-wide extractor first reached that rule at all.
  //
  // The parenthesis is the whole reason now, and it was not before. This
  // number used to hold two different things under one label: a block citing
  // NOTHING, and a block citing SEVERAL — 125 spans, of which 48 were the
  // second kind, and calling them "no RFC cited" was false of every one of
  // them. `cited_rfcs`'s doc comment carries what admitting the second kind
  // bought. What remains here is the first kind alone, and the reason it is
  // unreached is the reason printed: nobody wrote a spec's name near it, so
  // there is no claim to hold it to.
  println!(
    "quote-check: {abnf_skipped} production-shaped spans in blocks citing no RFC — nothing to \
     grade them against, {abnf_exempt} marked gate-exempt, {quote_exempt} quotations marked \
     gate-exempt"
  );
  // The fence rule's own denominator, printed for the same reason the line
  // above it is. Both halves are here on purpose: a run that only announced
  // what it read would say nothing about the fences it walked past, and the
  // whole design of these lines is that a green run distinguishes CHECKED
  // from NEVER LOOKED. A non-zero remainder is a fence tagged something
  // `fence_holds_grammar` does not admit and holding grammar anyway — the
  // signal that the tag list, not the shape test, is what wants revisiting.
  println!(
    "quote-check: {abnf_fenced_read} production-shaped lines read from {fences_read} \
     `text` fenced blocks, {abnf_fenced} left UNREACHED in {fences_skipped} fenced blocks \
     tagged otherwise"
  );
  // Same shape, same reason: a span this is not silence either — it is what
  // Ruling 9 costs, stated as a number instead of merely being the case.
  // Narrowed to blocks citing a LOADED spec only (Ruling 10a): a block
  // citing nothing gave no one reason to expect a quotation, so it is the
  // original, uncounted `None`, not part of this backlog. This number is a
  // TRIAGE QUEUE, not a defect tally — see the module doc's "Attribution by
  // citation" section for what it holds and why treating it as a defect
  // count is the wrong read.
  //
  // It is not only printed. `UNTRIAGED` holds the same spans PER FILE
  // and `untriaged_drift` fails on any file that differs, which is what makes
  // a fabricated quotation reachable by this gate at all — see that constant
  // for the hole it closes and why the numbers are pinned rather than
  // bounded.
  println!(
    "quote-check: {unattributable} prose-sized spans in blocks citing a loaded spec matched \
     nothing — untriaged, and held per file against `UNTRIAGED`"
  );
  // Ruling 11, as Ruling 12 leaves it: printed every run, pass or fail — a
  // coverage claim ("a quotation is graded against the spec it cites") is
  // exactly the kind of number this check exists to stop anyone stating
  // without a denominator. What remains on the fallback is now ONE thing
  // rather than two: a block that names no spec this run loaded, which has
  // nothing to narrow with. A block naming several is no longer among them.
  println!(
    "quote-check: {checked} quotations checked — {narrow} graded against the specs their block \
     names, {fallback} against any loaded spec (block names no loaded spec)"
  );

  // The backlog's own gate. Printed above as a total; held to a number here,
  // per file — see `UNTRIAGED` for why the number is pinned rather than
  // bounded, and for what a run that could not fail a fabricated quotation
  // cost.
  let backlog = untriaged_drift(&untriaged_by_file, UNTRIAGED, include_ignored);
  for (file, line) in &backlog {
    println!("{line}");
    // Each span with the line it sits on and its own words, the way the
    // production-shape failure already names what it rejected. A count on its
    // own is a failure nobody can act on, and the cheapest response to one is
    // the bless this table exists to refuse.
    for (at, span) in untriaged_spans.get(file).into_iter().flatten() {
      println!("  {file}:{at}: \"{span}\"");
    }
  }

  // Never silent, pass or fail. A block whose marks do not pair mis-cuts every
  // quotation behind the leftover one and drops the last of them entirely, and
  // this workspace held that off with a convention its authors had to remember
  // — see `Unpaired`. The count is printed every run and the split is held per
  // file, so a block that becomes unpaired is a failure rather than a thing
  // someone might notice.
  println!(
    "quote-check: {unpaired_blocks} comment block(s) hold an odd number of quotation marks — \
     held per file against `UNPAIRED`"
  );
  let unpaired_backlog = unpaired_drift(&unpaired_by_file, UNPAIRED, include_ignored);
  for (file, line) in &unpaired_backlog {
    println!("{line}");
    for odd in unpaired_sites.get(file).into_iter().flatten() {
      println!(
        "  {file}:{}: the block beginning at line {} holds {} quotation mark(s)",
        odd.mark, odd.at, odd.quotes
      );
    }
  }

  if failures == 0
    && abnf_failures == 0
    && abnf_malformed == 0
    && backlog.is_empty()
    && unpaired_backlog.is_empty()
  {
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
  if abnf_malformed > 0 {
    reasons.push(format!(
      "{abnf_malformed} ABNF productions are not whole rules"
    ));
  }
  if !backlog.is_empty() {
    reasons.push(format!(
      "{} file(s) hold a different number of untriaged spans than `UNTRIAGED` records",
      backlog.len()
    ));
  }
  if !unpaired_backlog.is_empty() {
    reasons.push(format!(
      "{} file(s) hold a different number of unpaired quotation marks than `UNPAIRED` records",
      unpaired_backlog.len()
    ));
  }
  Err(reasons.join("; ").into())
}

/// Every file whose untriaged count differs from the one [`UNTRIAGED`] records,
/// as the lines [`run`] prints and fails on.
///
/// Both directions, and both are reported with the number to write down rather
/// than with an instruction to think: MORE than recorded is a span this run
/// could not attribute and no one has looked at — the shape a fabricated
/// quotation arrives in — and FEWER is triage done, which the table has to be
/// told about or the ratchet slips back.
///
/// `include_ignored` relaxes exactly one half: a file absent from the table is
/// required to hold zero only when the run scanned the tracked tree alone.
/// `docs/` is gitignored and quotes the RFCs heavily, so requiring its files to
/// be listed would make one command check two different sets depending on where
/// it runs — which is the failure the module doc's "Which files are walked"
/// section already refuses.
///
/// `recorded` is a parameter rather than [`UNTRIAGED`] read directly, for the
/// reason `doc-check`'s `unclaimed_snapshots` takes its crate list as one: a
/// unit test needs a table of its own, and a rule that can only be exercised
/// against this workspace's own 91 spans is a rule nothing checks.
fn untriaged_drift(
  counts: &BTreeMap<String, usize>,
  recorded: &[(&str, usize)],
  include_ignored: bool,
) -> Vec<(String, String)> {
  let mut out = Vec::new();
  for (file, moved) in drift(counts, recorded, include_ignored) {
    let line = match moved {
      Drift::Above(found, recorded) => format!(
        "quote-check: {file}: {found} untriaged span(s), `UNTRIAGED` records {recorded} — a \
         span this run could not attribute to any spec it names. Read it: repair the \
         quotation, mark it `gate-exempt`, or raise the number here once it is known to be \
         the author's own words"
      ),
      Drift::Below(found, recorded) => format!(
        "quote-check: {file}: {found} untriaged span(s), `UNTRIAGED` records {recorded} — \
         triage was done and the table was not told. Lower the number here"
      ),
      Drift::Unlisted(found) => format!(
        "quote-check: {file}: {found} untriaged span(s), and the file is not in `UNTRIAGED` — \
         a file absent from that table must hold none"
      ),
      Drift::Stale(recorded) => format!(
        "quote-check: {file}: 0 untriaged span(s), `UNTRIAGED` records {recorded} — the whole \
         entry is stale; remove it"
      ),
    };
    out.push((file, line));
  }
  out
}

/// Every file whose count of unpaired blocks differs from the one [`UNPAIRED`]
/// records, as the lines [`run`] prints and fails on.
///
/// [`untriaged_drift`]'s rule, [`Unpaired`]'s wording. The two tables ratchet
/// on the same four cases and prescribe different repairs, so the rule is one
/// function ([`drift`]) and the sentences are two — a second copy of the rule
/// is how the two tables would come to disagree about what a stale entry is.
fn unpaired_drift(
  counts: &BTreeMap<String, usize>,
  recorded: &[(&str, usize)],
  include_ignored: bool,
) -> Vec<(String, String)> {
  let mut out = Vec::new();
  for (file, moved) in drift(counts, recorded, include_ignored) {
    let line = match moved {
      Drift::Above(found, recorded) => format!(
        "quote-check: {file}: {found} block(s) with an odd number of quotation marks, \
         `UNPAIRED` records {recorded} — a block whose marks do not pair cuts every quotation \
         behind the leftover one in the wrong place and drops the last of them. Balance the \
         marks, put the lone one in a block of its own, or raise the number here once it is \
         known to be deliberate"
      ),
      Drift::Below(found, recorded) => format!(
        "quote-check: {file}: {found} block(s) with an odd number of quotation marks, \
         `UNPAIRED` records {recorded} — a block was balanced and the table was not told. \
         Lower the number here"
      ),
      Drift::Unlisted(found) => format!(
        "quote-check: {file}: {found} block(s) with an odd number of quotation marks, and the \
         file is not in `UNPAIRED` — a file absent from that table must hold none"
      ),
      Drift::Stale(recorded) => format!(
        "quote-check: {file}: 0 block(s) with an odd number of quotation marks, `UNPAIRED` \
         records {recorded} — the whole entry is stale; remove it"
      ),
    };
    out.push((file, line));
  }
  out
}

/// How one file's count stands against the table recording it.
enum Drift {
  /// Found more than recorded: `(found, recorded)`.
  Above(usize, usize),
  /// Found fewer than recorded: `(found, recorded)`.
  Below(usize, usize),
  /// Found some, and the file is not in the table.
  Unlisted(usize),
  /// Found none, and the table records some.
  Stale(usize),
}

/// Every file whose count differs from the one `recorded` holds, in the order
/// the counts are keyed.
///
/// The rule both ratchet tables run on, in one place. Both directions are
/// reported, because MORE than recorded is the thing nobody has looked at and
/// FEWER is work done that the table was not told about — a ratchet that only
/// held one way would slip back the moment a file was edited. `include_ignored`
/// relaxes exactly one half: a file absent from the table is required to hold
/// zero only when the run scanned the tracked tree alone, since `docs/` is
/// gitignored and exists on a developer's disk and not in CI.
fn drift(
  counts: &BTreeMap<String, usize>,
  recorded: &[(&str, usize)],
  include_ignored: bool,
) -> Vec<(String, Drift)> {
  let mut out = Vec::new();
  for (file, &found) in counts {
    let against = recorded
      .iter()
      .find(|(name, _)| *name == file)
      .map(|(_, count)| *count);
    match against {
      Some(against) if against == found => {}
      Some(against) if found > against => out.push((file.clone(), Drift::Above(found, against))),
      Some(against) => out.push((file.clone(), Drift::Below(found, against))),
      None if include_ignored => {}
      None => out.push((file.clone(), Drift::Unlisted(found))),
    }
  }
  for (file, recorded) in recorded {
    if !counts.contains_key(*file) {
      out.push(((*file).to_owned(), Drift::Stale(*recorded)));
    }
  }
  out
}

/// Every quotation and candidate ABNF production `path`'s contents holds,
/// dispatched by extension, as `(quoted, productions, skipped)` — each
/// `quoted` span carrying every RFC its own block cited.
///
/// `.md` is read as one long comment block ([`markdown_quotations`]);
/// anything else — in practice always `.rs`, since [`collect_sources`] hands
/// this only `.rs` or `.md` paths — is read as `.rs`-style comments
/// ([`quotations`]).
fn spans_for(path: &Path, text: &str) -> Extracted {
  if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
    markdown_quotations(text)
  } else {
    quotations(text)
  }
}

/// Grades one normalised span, counting it when it is one this check governs.
///
/// Two different questions, asked in this order (Ruling 9): first, ANCHORING
/// asks "is this demonstrably a quotation of some loaded spec at all" — the
/// span's own opening characters either appear in a loaded spec's text or
/// they do not, independent of anything the block claims. Only once that is
/// "yes" does `cited` — every RFC the span's own block named ([`cited_rfcs`])
/// — get to answer the SECOND question, "which spec is it from": an anchored
/// span is graded against the specs its block NAMES, not against whichever
/// loaded spec happens to contain it. That closes a hole this check always
/// had: a sentence attributed to RFC 9110 used to pass because RFC 9112
/// happened to contain it too, and the attribution itself was never read.
///
/// Letting the citation answer BOTH questions — this check's first attempt —
/// is exactly how a block's own rhetorical prose got graded: prose-sized,
/// sitting in a block that cites something for an unrelated point, with
/// nothing else asked. An unanchored span stays ungraded either way, but what
/// happens to it next (Ruling 10a) depends on whether anyone had REASON to
/// expect a quotation there:
///
/// - Names only specs this run does not have loaded: there is nothing else
///   to ask, and "unanchored" proves nothing — this run was never given the
///   text to match against — so [`Grade::Unloaded`] is the honest answer.
///   A claim this run could not check is a different fact from a claim with
///   nothing to check against.
/// - Names a spec this run DOES have loaded, one of however many: the block
///   gave a reason to expect a quotation and this span isn't demonstrably
///   one. Counted, not failed (`unattributable`, the caller's running total
///   — see [`run`]'s printed line for what that backlog holds). Ruling 12
///   reads "gave a reason" from the SET, as Q2 below does: a block naming
///   four RFCs gives every bit as much reason as one naming a single RFC,
///   and reading the two branches differently would put two definitions of
///   "cited" inside one function. That is what moved this backlog from 43
///   to 97 — 54 spans that had always belonged in it, in blocks the
///   "exactly one" rule had been calling uncited.
/// - Cites nothing at all: no one had reason to think this was a quotation
///   in the first place. The original, silent `None` — not counted anywhere,
///   because conflating "not my business" with "my business and I could not
///   do it" is the same category error as reporting the author's own words
///   as a failure.
///
/// This citation-narrows-the-target step is deliberately the OPPOSITE of
/// [`grade_production`], which grades an admitted candidate against every
/// loaded spec regardless of citation. That is not an inconsistency: a
/// quoted SENTENCE that anchors inside a citing block is almost always that
/// RFC's own prose, but a grammar RULE beside a citation is routinely shown
/// for comparison with a different spec's — see `grade_production`'s doc
/// comment for the worked example.
///
/// **Ruling 11: `narrow` and `fallback` count WHICH of the two anchored paths
/// graded a span** — the cited-specs comparison above, or the any-spec
/// anchored fallback below. Ruling 11 counted; Ruling 12 is what the count
/// then bought.
///
/// **Ruling 12: a quotation is graded against the SET of specs its block
/// names, and the three ways of picking ONE were measured before choosing.**
/// Ruling 11 left 233 of 493 quotations on the fallback and said the split
/// was unmeasured. It is measured now, on this workspace's own corpus. Of
/// those 233, **184 sat in a block naming SEVERAL RFCs** and 49 in a block
/// naming none; the third case a reader expects — one RFC named, that one
/// not loaded — occurs zero times here. Only the 184 could move, so the
/// three candidates were run against exactly them:
///
/// | widening | moved off the fallback | of those, FAILED |
/// |---|---|---|
/// | nearest-by-position | 174 | 34 |
/// | first-mentioned | 173 | 59 |
/// | union of the named | 184 | 2 |
///
/// The failure column is the whole decision, and it is not a tie-break on
/// size. **32 of nearest-by-position's 34 failures, and 58 of
/// first-mentioned's 59, are quotations that ARE verbatim in one of their
/// own block's other citations** — correctly transcribed, correctly
/// attributable, and failed only because a positional heuristic picked the
/// wrong one of the numbers the author actually wrote. A maintainer answers
/// a report like that by rewording a sentence that was already right, which
/// is the way a check gets switched off. Both were rejected on that
/// measurement, not on taste.
///
/// The union is not merely the smallest of the three; it is the only one
/// that never has to choose. A span verbatim in ANY spec the block names is
/// a quotation the block accounts for, so the union cannot fail a
/// correctly-attributed quotation the way a picker can — and adding a
/// citation to a block can only widen the target set, so naming one more RFC
/// in a comment can never break a quotation that passed.
///
/// **What the measurement REFUTED, recorded because it was the expected
/// answer going in.** The proposal was that grading against (specs the block
/// names) ∩ (specs the span anchors in) is monotone — it can only shrink the
/// accepted set relative to the fallback's `anchored` — so every failure it
/// surfaces must be a real mis-attribution. The monotonicity is true and the
/// conclusion does not follow, in both directions:
///
/// - That intersection surfaces NOTHING. Run against the 184 it moves 182
///   and fails 0, because a span is only ever graded against specs it
///   already anchors in, and a text belonging to one spec while the block
///   claims another is exactly when that intersection is empty. It buys
///   182 spans relabelled from `fallback` to `narrow` while checking
///   nothing new — a coverage number with no check under it, which is the
///   one outcome these printed lines exist to prevent.
/// - The union, which does grade the disjoint case, is NOT monotone, and one
///   of its two failures was a false one: `server.rs`'s verbatim RFC 6455
///   §4.2.1 quotation, in a block spelling only RFC 6454 and RFC 9110
///   because the file refers to its own spec as a bare `§4.2.1`.
///
/// Both of the union's two failures were nonetheless real comment defects,
/// and neither was repaired by re-attribution — which is why the disjoint
/// case ships as its own grade ([`Grade::Foreign`]) rather than as
/// [`Grade::Reworded`]. One was a quotation of RFC 9112 §9.5 with the word
/// "transport" dropped, passing only because RFC 6455 happens to contain the
/// shortened phrase in an unrelated sentence about closing a WebSocket — in
/// an `http1-proto` file. The other was a correct quotation whose spec the
/// block never named. The two repairs are opposite (fix the words; name the
/// spec), no rule here can tell which is wanted, and `Foreign` therefore
/// reports both sides and prescribes neither.
fn grade<'a>(
  quoted: &str,
  cited: &[u32],
  specs: &'a [Spec],
  checked: &mut usize,
  unattributable: &mut usize,
  narrow: &mut usize,
  fallback: &mut usize,
) -> Option<Grade<'a>> {
  if quoted.split_whitespace().count() < MIN_WORDS || quoted.chars().count() < MIN_CHARS {
    return None; // not prose-sized: not a quotation
  }

  // Every spec the block NAMED that this run actually loaded — the target set
  // for Q2 below, and the one place where whether this block cited anything
  // usable is decided. Both branches read this set, or there would be two
  // definitions of the word cited inside one function.
  let named: Vec<&Spec> = cited
    .iter()
    .filter_map(|number| {
      let name = format!("rfc{number}");
      specs.iter().find(|spec| spec.name == name)
    })
    .collect();

  // Q1: is this demonstrably a quotation of some loaded spec at all?
  let head = anchor(quoted);
  let anchored: Vec<&Spec> = specs
    .iter()
    .filter(|spec| spec.lower.contains(&head))
    .collect();

  if anchored.is_empty() {
    // Ruling 10a: a block citing NOTHING gave no one reason to expect a
    // quotation here at all. That is the original, silent `None` — not this
    // check's business, and not counted anywhere, the same as before this
    // task existed.
    if cited.is_empty() {
      return None;
    }
    if named.is_empty() {
      // No cited spec is loaded, so "no anchor match" proves nothing — this
      // run was never given the text to match against.
      *checked += 1;
      return Some(Grade::Unloaded(cited.to_vec()));
    }
    // Cites a spec this run DOES have, and still didn't anchor: the block
    // gave a reason to expect a quotation (it cites a live spec) and this
    // span isn't demonstrably one. Visible, not silent, and not a failure —
    // see `run`'s printed line for what this backlog holds.
    *unattributable += 1;
    return None;
  }

  // Q2: anchored — which spec is it from? The specs the block NAMES answer
  // that, all of them at once (Ruling 12).
  if !named.is_empty() {
    *checked += 1;
    *narrow += 1;
    if named.iter().any(|spec| spec.text.contains(quoted)) {
      return None;
    }
    let lowered = quoted.to_ascii_lowercase();
    if let Some(spec) = named
      .iter()
      .find(|spec| spec.lower.contains(&lowered))
      .copied()
    {
      let at = spec.lower.find(&lowered).unwrap_or(0);
      return Some(Grade::Recased(spec, excerpt(&spec.text, at, quoted.len())));
    }
    // Begins as a spec the block DOES name, then stops being it: the words
    // drifted, and that spec's own text at the anchor is the fix.
    if let Some(spec) = named
      .iter()
      .find(|spec| spec.lower.contains(&head))
      .copied()
    {
      let at = spec.lower.find(&head).unwrap_or(0);
      return Some(Grade::Reworded(
        spec,
        excerpt(&spec.text, at, quoted.len().saturating_mul(2)),
      ));
    }
    // Begins as no spec the block names — but it anchored somewhere, so it
    // begins as SOME loaded spec's. Both facts are reported and neither is
    // called the wrong one; see [`Grade::Foreign`].
    return Some(Grade::Foreign {
      cited: cited.to_vec(),
      begins_as: anchored[0],
    });
  }

  // The block named no spec this run loaded: the pre-existing any-spec
  // anchored behaviour, unchanged. Several anchored specs may hold the same
  // opening, and a verbatim match in any of them clears it, because nothing
  // here says which one is claimed.
  *checked += 1;
  *fallback += 1;
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

/// `numbers` as `RFC 9110, RFC 9112`, for a message that must name several.
fn rfc_list(numbers: &[u32]) -> String {
  numbers
    .iter()
    .map(|number| format!("RFC {number}"))
    .collect::<Vec<_>>()
    .join(", ")
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

/// The shortest production this check governs, in words.
///
/// Below it a span is not a checkable claim: `q = 1` and `realm=` are
/// production-SHAPED, and grading either against a spec's grammar would
/// report a field value as a mis-transcribed rule. It is the floor for BOTH
/// verdicts a candidate can draw — [`rule_fault`]'s and
/// [`grade_production`]'s — so that one admission test decides what this
/// check is looking at, and a span it declines is neither malformed nor
/// verbatim but simply none of its business.
///
/// Widening [`rule_fault`] past this floor was measured and rejected. Dropping
/// the floor from the shape test alone — deleting the
/// `is_checkable_production(&candidate.rule) &&` from [`run`]'s guard and
/// leaving everything else as it is — and re-running
/// `cargo run -p xtask -- quote-check` reports **23 candidates as malformed,
/// 17 for an empty right-hand side and 6 for a quotation mark that never
/// closes**. Not one of the 23 is a production: they are field values written
/// with the value left off, values the sentence around them cuts in half, and
/// this file's own metasyntax for the shape. Re-measure with that edit before
/// leaning on the number, the way `doc-check`'s table census says of its own —
/// it read `21 … 15 … 6` of the workspace it was written against, and the
/// paragraph-wide extractor found two more empty right-hand sides.
const MIN_PRODUCTION_WORDS: usize = 3;

/// Whether a production candidate says enough to be graded at all — see
/// [`MIN_PRODUCTION_WORDS`].
fn is_checkable_production(text: &str) -> bool {
  normalise_production(text).split_whitespace().count() >= MIN_PRODUCTION_WORDS
}

/// Grades one production segment. `None` when it is too short to be a
/// checkable claim, or when SOME loaded spec contains it verbatim.
///
/// Every loaded spec is searched, not only the one [`cited_rfcs`] found for
/// the block: 6455 borrows grammar from 2616 and the 723x series, and a
/// block's citation is often a COMPARISON point rather than an attribution —
/// three real, correctly-transcribed RFC 6455 productions sit in blocks whose
/// only citation is RFC 9110, discussing where the two grammars disagree.
/// That is right for a production the way it would be wrong for a quotation:
/// a quoted SENTENCE inside a citing block is almost certainly that RFC's
/// own, but a grammar RULE beside a citation is often shown for contrast.
/// [`cited_rfcs`] still decides whether a span is a candidate at all — a
/// block naming no RFC makes no checkable claim — but that is now the WHOLE
/// of what it decides for a production: the gate reads the set for
/// EMPTINESS, not for length, and it never decided which spec the candidate
/// is graded against. Requiring exactly one had it grading FEWER productions
/// the more accurate a comment's citations became; see `cited_rfcs`'s doc
/// comment for what it cost, measured.
///
/// On failure the first spec comes back, same as [`grade`] falls back to when
/// a quotation's anchor does not narrow it — arbitrarily, since nothing here
/// says which loaded spec a production was meant to be quoting. [`run`] does
/// NOT print that name for exactly that reason: an arbitrary name reads as an
/// attribution, and "is not rfc2045's" over an RFC 9110 rule sends the reader
/// to compare against a spec that never carried it. What is printed is the
/// fact this actually establishes — that none of the loaded specs holds these
/// characters.
///
/// Both sides are [`normalise_production`]d, NOT [`normalise`]d, and the
/// difference is the whole of what "verbatim" means here. `[ … ]` is RFC
/// 5234's optional-element syntax — grammar — while
/// [`strip_bracket_insertions`] removes it as the editorial mark it is in a
/// QUOTATION. Grading a production through the quotation's rule deleted part
/// of the production from both sides at once, so the comparison agreed with
/// itself about a stub and called it verbatim; that function's doc comment
/// carries the worked example. Thirteen of this workspace's graded
/// productions carry an optional group, and two of them (`expectation`,
/// `extension-param`) were stubbed down to their own name and the single word
/// `token` — three words, the floor, with the whole right-hand side gone.
fn grade_production<'a>(segment: &str, specs: &'a [Spec], checked: &mut usize) -> Option<&'a Spec> {
  if !is_checkable_production(segment) {
    return None;
  }
  let wanted = normalise_production(segment);
  *checked += 1;
  if specs.iter().any(|spec| spec.grammar.contains(&wanted)) {
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
/// One mechanism, one meaning — now two spellings, because two file types.
/// This is the `.rs` one; a later check reuses it too, so recognising it lives
/// here rather than folded into the ABNF pipeline. [`markdown_exempted_spans`]
/// is the other spelling, for a file with no `//` syntax to spell it with, and
/// [`exempted_spans_for`] is what dispatches a file to the right one.
///
/// # One syntax, two ATTACHMENT rules — written down because they differ
///
/// `doc-check` reads the identical marker under a different rule, and nothing
/// said so until a one-line edit made for this gate broke that one. Both are
/// stated here and in `doc_check`'s `exemption_reason`, in the same words:
///
/// - **`quote-check` attaches a marker to the FILE.** This function reads
///   every line of the source regardless of block, item or position, and
///   `run` suppresses any extracted span whose text is in the set — anywhere
///   in that file. A marker at the bottom exempts a span at the top.
/// - **`doc-check` attaches a marker to the ITEM**: one run of consecutive
///   comment lines plus the code beneath it, up to the next such run. A marker
///   exempts only the mentions in its own item's comments, so a blank line
///   between a marker and the mention it was written for severs them. The one
///   widening is a module: an item documented with `//!` takes the file's
///   leading comment run instead, so a module's markers are the ones at the
///   top of its file, blank lines or not.
///
/// The difference is not cosmetic. `http-semantics/src/auth/mod.rs` holds four
/// markers whose text carries a lone `"`; this gate needs a blank line above
/// them so that mark does not join the module doc's block ([`UNPAIRED`]), and
/// adding that line took the markers out of the module doc's ITEM and red
/// `doc-check` five times. The module widening on that side is what makes the
/// blank line free.
fn exempted_spans(source: &str) -> HashSet<String> {
  let mut out = HashSet::new();
  for line in source.lines() {
    let Some((body, _, _)) = comment_body(line) else {
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

/// The spans a MARKDOWN file's comments mark exempt: the same marker
/// [`exempted_spans`] reads, spelled `<!-- gate-exempt: <span> — <reason> -->`
/// because `.md` has no `//` comment syntax for it to borrow. Same meaning,
/// same shape (scan every line, find the marker, take the text up to the em
/// dash), different bracketing — the reason is discarded exactly as it is for
/// the `.rs` form, and the closing `-->` is excluded from the span the same
/// way the em dash excludes the reason.
///
/// This does NOT live inside [`comment_body`], and that is a decision rather
/// than an oversight: `comment_body` is answering a RUST question — the
/// character-by-character walk in [`trailing_comment_at`] exists solely to
/// tell a real `//` from one sitting inside a string literal, and that
/// distinction has no Markdown analogue. A `.md` file has no string literals
/// to hide a `<!--` inside, and [`markdown_quotations`] already reads the
/// whole file as one long comment block — there is no code half for an HTML
/// comment to follow the way a trailing `.rs` comment follows code. Teaching
/// `comment_body` a second, unrelated grammar would tax every `.rs` line with
/// a check that can never fire there, for a distinction Markdown does not
/// have. So this is its own function, called only for a `.md` file, the same
/// way [`markdown_quotations`] is [`quotations`]'s own sibling rather than a
/// branch inside it.
///
/// Also unlike `comment_body`, this does not track fenced code blocks —
/// deliberately matching [`exempted_spans`], which scans every physical `.rs`
/// line the same way, fence or no fence (a marker inside a fenced doc-comment
/// example is recognised there today, not specially excluded). Adding fence
/// tracking to only one of the two spellings would make them recognise the
/// marker under different rules depending on which file it sits in, which is
/// the asymmetry "one mechanism, one meaning" exists to avoid.
fn markdown_exempted_spans(source: &str) -> HashSet<String> {
  let mut out = HashSet::new();
  for line in source.lines() {
    let Some(after_open) = line.find("<!--").map(|at| &line[at + 4..]) else {
      continue;
    };
    let Some(rest) = after_open.trim_start().strip_prefix("gate-exempt:") else {
      continue;
    };
    // The closing `-->` bounds the marker the way end-of-line bounds a `//`
    // one; text found after it belongs to whatever comes next on the line,
    // not to this span. No closing `-->` on the line at all means no marker.
    let Some((body, _)) = rest.split_once("-->") else {
      continue;
    };
    let text = body.split(" — ").next().unwrap_or(body).trim();
    if !text.is_empty() {
      out.insert(text.to_string());
    }
  }
  out
}

/// Dispatches to [`exempted_spans`] or [`markdown_exempted_spans`] by
/// extension, exactly as [`spans_for`] dispatches extraction: a `.md` file's
/// marker is the HTML-comment spelling and an `.rs` file's is the `//` one,
/// never the other way around in either direction. Keeping the dispatch by
/// extension, rather than trying both spellings on every file, is what keeps
/// the two syntaxes from leaking into each other's file type — a `.rs` doc
/// comment that shows the Markdown spelling as a worked example (of the kind
/// this very module's doc comments are full of) must not be read as a live
/// marker, and the reverse for a stray `//` line inside a `.md` file.
fn exempted_spans_for(path: &Path, source: &str) -> HashSet<String> {
  if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
    markdown_exempted_spans(source)
  } else {
    exempted_spans(source)
  }
}

/// Every quoted span in `source`'s comments, with the line its opening quote
/// is on and every RFC its own block cited — beside every ABNF production
/// candidate: a backticked one whose block names any RFC at all, and a
/// production-shaped line inside a fence [`fence_holds_grammar`] admits.
/// [`Extracted::uncited`] counts the production-shaped BACKTICKED spans found
/// in a block that named no RFC — prose with no claim in it for this check to
/// grade, not a failure.
///
/// Consecutive comment lines are one block and are joined before the quotes are
/// paired, so a quotation wrapped across lines is one span rather than several.
/// A backticked production is found per PARAGRAPH — the same joining, over the
/// smaller unit a Markdown code span may wrap across ([`abnf_spans`]) — and
/// before [`mask_paragraph`] erases the spans holding a `"`. But which block it
/// belongs to, and so whether [`cited_rfcs`] admits it as a candidate at all,
/// is decided at the block's flush, once the whole block exists to be asked.
/// Every quoted span pulled from the same block carries the same citations,
/// for the same reason: the block, not the line, is what was cited. A FENCED
/// production never joins a block at all — see [`fence_holds_grammar`] for why
/// its admission is the fence's to answer.
fn quotations(source: &str) -> Extracted {
  quotations_masked(source, mask_paragraph)
}

/// [`quotations`] with the masking unit named, which is the one thing about it
/// a test may vary: `mask` decides what a paragraph's lines look like by the
/// time they are joined into a block, and nothing else here changes with it.
fn quotations_masked(source: &str, mask: Masker) -> Extracted {
  let mut out: QuotedSpans = Vec::new();
  let mut unpaired: Vec<Unpaired> = Vec::new();
  let mut productions = Vec::new();
  let mut skipped = 0usize;
  let mut fenced_productions = 0usize;
  let mut block = String::new();
  // (byte offset into `block`, source line) for the start of each joined line.
  let mut marks: Vec<(usize, usize)> = Vec::new();
  // ABNF production candidates seen in the block under construction, admitted
  // or skipped only once the block's own citation is known.
  let mut pending: Spans = Vec::new();
  // Productions read from inside a fence. Kept apart from `pending` because
  // they are not the block's to admit, and apart from `productions` because
  // `flush` borrows that one for the whole of the loop below.
  let mut from_fences: Spans = Vec::new();
  let mut fences_read = 0usize;
  let mut fences_skipped = 0usize;
  let mut fenced = false;
  // Only ever read while `fenced`: the info string of the fence now open.
  let mut grammar_fence = false;
  // Whether the last production read from the fence now open is still taking
  // continuation lines — see [`read_fenced_line`].
  let mut continuing: Option<usize> = None;
  // The comment lines of the paragraph under construction, which is the unit
  // [`abnf_spans`] reads a backticked span over: a code span may be wrapped
  // across the lines of one paragraph and may not cross a blank line, a fence
  // or the end of the comment. Finer-grained than `block`, which keeps the
  // blank comment lines a paragraph ends at, because a CITATION carries across
  // them and a code span does not.
  let mut paragraph: Vec<(usize, &str)> = Vec::new();

  let mut flush = |block: &mut String, marks: &mut Vec<(usize, usize)>, pending: &mut Spans| {
    // Computed once and reused for every span AND for the production gate
    // below: both readings are "what did this block cite", so there is only
    // one place that question is asked — see [`cited_rfcs`] for why the two
    // readings of the answer still differ.
    let cited = cited_rfcs(block);
    for (at, span) in quoted_spans(block) {
      out.push((line_of(marks, at), span.to_string(), cited.clone()));
    }
    if let Some(odd) = unpaired_mark(block, marks) {
      unpaired.push(odd);
    }
    if cited.is_empty() {
      skipped += pending.len();
      pending.clear();
    } else {
      productions.append(pending);
    }
    block.clear();
    marks.clear();
  };

  for (index, raw) in source.lines().enumerate() {
    let Some((body, own_line, indent)) = comment_body(raw) else {
      fenced = false;
      // Drained before the flush, every time: `flush` is what decides whether
      // this block's candidates are admitted or counted uncited, and a
      // paragraph still held here when it ran would be admitted by the NEXT
      // block's citations instead of its own — and its LINES would never reach
      // the block at all, since the drain is what appends them.
      take_paragraph(&mut paragraph, &mut pending, &mut block, &mut marks, mask);
      flush(&mut block, &mut marks, &mut pending);
      continue;
    };
    if own_line {
      if let Some(info) = body.strip_prefix("```") {
        fenced = !fenced;
        // A fence never continues the one before it, open or close.
        continuing = None;
        // Nor does a code span reach across one, in either direction.
        take_paragraph(&mut paragraph, &mut pending, &mut block, &mut marks, mask);
        if fenced {
          grammar_fence = fence_holds_grammar(info);
          if grammar_fence {
            fences_read += 1;
          } else {
            fences_skipped += 1;
          }
        }
        continue;
      }
      if fenced {
        // Read from a fence whose info string says text, counted where it
        // does not — and named in the module doc either way, since a boundary
        // nobody is told about is the failure this whole command exists to
        // remove.
        if grammar_fence {
          read_fenced_line(&mut from_fences, &mut continuing, index + 1, indent, body);
        } else if is_production(body) {
          fenced_productions += 1;
        }
        continue;
      }
    } else {
      // A comment that FOLLOWS code cannot be inside a doc fence: the fence
      // would have had to close before the code line that carries it.
      fenced = false;
    }
    // A `///` with nothing after it is the blank line of the comment's own
    // Markdown, and a code span may not hold one — so it ends the paragraph
    // while leaving the block, and its citations, standing. Its own separator
    // and mark are pushed AFTER the drain, which is where the paragraph it
    // ends lands: the block reads in the source's order or the marks name the
    // wrong lines.
    if body.is_empty() {
      take_paragraph(&mut paragraph, &mut pending, &mut block, &mut marks, mask);
      if !block.is_empty() {
        block.push(' ');
      }
      marks.push((block.len(), index + 1));
    } else {
      paragraph.push((index + 1, body));
    }
  }
  take_paragraph(&mut paragraph, &mut pending, &mut block, &mut marks, mask);
  flush(&mut block, &mut marks, &mut pending);
  // Merged here rather than in the loop: `flush`'s borrow of `productions`
  // ends at the call above. Re-sorted by line so one file's candidates stay
  // in the order a reader of that file would meet them.
  let fenced_read = from_fences.len();
  productions.append(&mut from_fences);
  productions.sort_by_key(|candidate| candidate.line);
  Extracted {
    quoted: out,
    productions,
    uncited: skipped,
    fences_read,
    fenced_read,
    fences_skipped,
    fenced: fenced_productions,
    unpaired,
  }
}

/// Every quotation in a Markdown file, with the line its opening quote is on
/// and every RFC its own block cited, beside every ABNF production
/// candidate — see [`quotations`] for which spans become one, what
/// [`Extracted::uncited`] counts and why, and for the citation this mirrors.
///
/// A `.md` file is comment text throughout, so there is no comment prefix to
/// find and no code half to discard — but fenced blocks are still skipped, for
/// the same reason they are in a doc comment: a fence holds code, and a
/// quotation mark inside code is not opening a quotation. The one reach into a
/// fence is the ABNF path's, on the same [`fence_holds_grammar`] rule and for
/// the same reason: one rule over both kinds of file, or the printed numbers
/// would be a `.rs`-only figure wearing a workspace-wide label.
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
fn markdown_quotations(source: &str) -> Extracted {
  markdown_quotations_masked(source, mask_paragraph)
}

/// [`markdown_quotations`] with the masking unit named, mirroring
/// [`quotations_masked`] for the same reason.
fn markdown_quotations_masked(source: &str, mask: Masker) -> Extracted {
  let mut out: QuotedSpans = Vec::new();
  let mut unpaired: Vec<Unpaired> = Vec::new();
  let mut productions = Vec::new();
  let mut skipped = 0usize;
  let mut fenced_productions = 0usize;
  let mut block = String::new();
  let mut marks: Vec<(usize, usize)> = Vec::new();
  // ABNF production candidates seen in the block under construction, admitted
  // or skipped only once the block's own citation is known — see
  // `quotations`'s `pending` for why this can't be decided per-line.
  let mut pending: Spans = Vec::new();
  // See `quotations`'s `from_fences` for why these three are kept apart.
  let mut from_fences: Spans = Vec::new();
  let mut fences_read = 0usize;
  let mut fences_skipped = 0usize;
  let mut fenced = false;
  let mut grammar_fence = false;
  // See `quotations` for what these two track. A blank line ends a Markdown
  // file's block AND its paragraph at once, so unlike `quotations` the two
  // boundaries coincide here — the buffer is still its own, because the fence
  // rule below breaks a paragraph without a blank line to do it.
  let mut continuing: Option<usize> = None;
  let mut paragraph: Vec<(usize, &str)> = Vec::new();

  let mut flush = |block: &mut String, marks: &mut Vec<(usize, usize)>, pending: &mut Spans| {
    // See `quotations`'s `flush` for why this is computed once and reused
    // for both the spans below and the production gate.
    let cited = cited_rfcs(block);
    for (at, span) in quoted_spans(block) {
      out.push((line_of(marks, at), span.to_string(), cited.clone()));
    }
    if let Some(odd) = unpaired_mark(block, marks) {
      unpaired.push(odd);
    }
    if cited.is_empty() {
      skipped += pending.len();
      pending.clear();
    } else {
      productions.append(pending);
    }
    block.clear();
    marks.clear();
  };

  for (index, raw) in source.lines().enumerate() {
    if let Some(info) = raw.trim_start().strip_prefix("```") {
      fenced = !fenced;
      // See `quotations`: a fence never continues the one before it.
      continuing = None;
      if fenced {
        grammar_fence = fence_holds_grammar(info);
        if grammar_fence {
          fences_read += 1;
        } else {
          fences_skipped += 1;
        }
      }
      take_paragraph(&mut paragraph, &mut pending, &mut block, &mut marks, mask);
      flush(&mut block, &mut marks, &mut pending);
      continue;
    }
    if fenced {
      // Same rule as `quotations` applies, for the same reason — the
      // continuation half included.
      if grammar_fence {
        read_fenced_line(
          &mut from_fences,
          &mut continuing,
          index + 1,
          raw.len().saturating_sub(raw.trim_start().len()),
          raw.trim(),
        );
      } else if is_production(raw.trim()) {
        fenced_productions += 1;
      }
      continue;
    }
    if raw.trim().is_empty() {
      take_paragraph(&mut paragraph, &mut pending, &mut block, &mut marks, mask);
      flush(&mut block, &mut marks, &mut pending);
      continue;
    }
    // Trimmed, where the block used to be handed the raw line: a paragraph's
    // lines are JOINED before [`mask_paragraph`] reads them, and the
    // indentation Markdown uses to lay a paragraph out would otherwise land
    // inside a span that wraps across one of them. One buffer now feeds both
    // the mask and [`abnf_spans`], so there is no second, untrimmed reading of
    // the same line left to disagree with this one.
    paragraph.push((index + 1, raw.trim()));
  }
  take_paragraph(&mut paragraph, &mut pending, &mut block, &mut marks, mask);
  flush(&mut block, &mut marks, &mut pending);
  // See `quotations` for why the merge waits until `flush` is done with.
  let fenced_read = from_fences.len();
  productions.append(&mut from_fences);
  productions.sort_by_key(|candidate| candidate.line);
  Extracted {
    quoted: out,
    productions,
    uncited: skipped,
    fences_read,
    fenced_read,
    fences_skipped,
    fenced: fenced_productions,
    unpaired,
  }
}

/// The comment on one source line, and whether the line is nothing but that
/// comment.
///
/// A comment that FOLLOWS code counts. Finding one means walking the code half,
/// because the only thing that distinguishes `// a comment` from the `"//!"`
/// inside `strip_prefix("//!")` is whether the slashes sit inside a string
/// literal. The code half is then DISCARDED rather than scanned, which is the
/// same argument [`mask_paragraph`] makes for an inline code span, applied to
/// a whole line: a string literal cannot be read as a quotation if it is never
/// read at all.
///
/// The `own_line` half of the answer is for the fence rule, which is a property
/// of doc comments and not of a comment beside code.
///
/// The third half is the body's own INDENT past the marker, counted before the
/// trim that throws it away. It is what tells a wrapped ABNF rule's
/// continuation from the prose that merely follows the rule
/// ([`read_fenced_line`]), and it is returned from here rather than recovered
/// by a second walk because this is the one function that knows where the
/// marker ended.
fn comment_body(line: &str) -> Option<(&str, bool, usize)> {
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
  let indent = body.len().saturating_sub(body.trim_start().len());
  Some((body.trim(), own_line, indent))
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

/// The leftover quote mark in one masked block, when the marks do not pair.
///
/// [`quoted_spans`] takes them two at a time from the left, so an ODD count
/// leaves the LAST mark without a partner and every pairing behind it one
/// place out. Which mark the author got wrong is not decidable here — the
/// leftover is reported as the one the pairing ran out on, together with the
/// line the block starts at, so a reader has both ends of the run to look
/// along.
///
/// Read on the block AFTER masking, because that is the text
/// [`quoted_spans`] reads: a mark inside a code span is not one of the block's
/// to pair, and counting before the mask would report every comment that
/// names a quote character.
///
/// # The limit, stated rather than left to be rediscovered
///
/// This sees a BLOCK, not a quotation. Parity is the whole of the test, so an
/// EVEN number of stray or leaked marks is still mis-paired and still
/// unreported: every quotation between the first stray and the last is cut at
/// the wrong place, and the count comes out even, and nothing here says a
/// word. That is the shape #84's own opening case had — the comment that
/// surfaced the leak held TWO wrapped code spans, which is why it produced
/// false spans rather than a disappearance. So this narrows the class along
/// one axis and leaves the other open. Nothing available here closes it: what
/// would is knowing which mark the author meant, and a rule that guesses that
/// is a rule that invents failures.
fn unpaired_mark(block: &str, marks: &[(usize, usize)]) -> Option<Unpaired> {
  let quotes = block.matches('"').count();
  if quotes.is_multiple_of(2) {
    return None;
  }
  let last = block.rfind('"')?;
  Some(Unpaired {
    at: marks.first().map_or(0, |(_, line)| *line),
    mark: line_of(marks, last),
    quotes,
  })
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

/// The backticked ABNF productions in one PARAGRAPH of comment, each paired
/// with the source line its opening backtick run sits on.
///
/// Runs BEFORE [`mask_paragraph`], which erases a backticked span holding a
/// `"` — and a production's terminals are quoted, so by the time a block is
/// built its productions are gone. [`quoted_spans`] would not have found them
/// either: a production without a terminal carries no `"` at all. Both read the
/// paragraph's spans through [`code_spans`], so what the mask erases and what
/// this admits are the same spans under the same rule.
///
/// A span counts when it opens with `name =` or RFC 2046's `name :=`, which is
/// what separates a grammar rule from a backticked identifier. `=/`
/// (incremental alternatives) counts too.
///
/// # Why the unit is a paragraph and not a line
///
/// It was a line, and a line is where a production could leave this gate
/// altogether. A rule too long for one comment line gets wrapped, its closing
/// backtick lands on the next line, and pairing backticks within a line found
/// no closer and gave up — so the rule had no span extracted from it, was
/// never graded, never counted and never reported. That is the escape
/// [`rule_fault`] closes one step later, arriving one step earlier: a
/// truncated production at least reached the comparison and was called
/// verbatim, while a wrapped one reached nothing.
///
/// A Markdown code span is a paragraph-level construct, and a paragraph is
/// therefore the unit that reads what rustdoc renders: a line ending inside a
/// span becomes a space, and a blank line ends the span rather than being
/// swallowed by it. Where a paragraph ends is the caller's to say — see
/// [`take_paragraph`] — because only the caller can tell a blank comment line
/// from a fence from the end of the comment.
///
/// # Backtick RUNS, not backticks
///
/// A span opened by N backticks closes on the next run of exactly N — the rule
/// [`code_spans`] walks, and joining lines is what makes it load-bearing here:
/// a comment writes a literal backtick by wrapping it in two, and one such span
/// in this very file — [`exempted_spans`]'s own doc comment — is wrapped across
/// two lines. Pairing single backticks would take that span's head from one line
/// and its tail from the next and offer the join as a grammar rule;
/// `a_doubled_backtick_span_is_not_two_single_ones` quotes those two lines
/// verbatim and holds it to reading one span, which holds backticks and is not
/// production-shaped.
///
/// An opening run that finds no closer in the paragraph is literal text, and
/// the walk resumes at the run after it: one stray backtick costs the spans
/// behind it nothing. The line-at-a-time version abandoned the rest of its line
/// at that point, which is why widening the unit had to widen the recovery with
/// it — a paragraph is a great deal more to abandon than a line.
fn abnf_spans(paragraph: &[(usize, &str)]) -> Vec<(usize, String)> {
  let (text, starts) = join_paragraph(paragraph);
  let mut out = Vec::new();
  for span in code_spans(&text) {
    let rule = code_span_text(span.content);
    if is_production(&rule) {
      out.push((line_of(&starts, span.at), rule));
    }
  }
  out
}

/// One paragraph of comment as a single text, beside the source line each
/// joined line's first byte belongs to.
///
/// Joined on `\n` rather than on a space so the join stays VISIBLE to the
/// walks over it: only a line ending INSIDE a code span becomes a space, and a
/// span has to be able to tell that space from one its author wrote.
fn join_paragraph(paragraph: &[(usize, &str)]) -> (String, Vec<(usize, usize)>) {
  let mut text = String::new();
  let mut starts: Vec<(usize, usize)> = Vec::new();
  for (line, body) in paragraph {
    if !text.is_empty() {
      text.push('\n');
    }
    starts.push((text.len(), *line));
    text.push_str(body);
  }
  (text, starts)
}

/// The source line a byte offset sits on, given the offset each line starts at
/// in increasing order.
///
/// One function for the two places that ask it — a code span inside a joined
/// paragraph, and a quoted span inside a joined block — because it is the same
/// question over two different join tables, and asking it twice is how the two
/// answers come to differ.
fn line_of(starts: &[(usize, usize)], at: usize) -> usize {
  starts
    .iter()
    .take_while(|(offset, _)| *offset <= at)
    .last()
    .map_or(0, |(_, line)| *line)
}

/// One inline code span: where its delimiters begin and end, and what they
/// enclose before [`code_span_text`] reads it.
struct CodeSpan<'a> {
  /// Byte offset of the opening backtick run.
  at: usize,
  /// One past the closing backtick run, so `at..end` is the whole span with
  /// its delimiters — which is what [`mask_paragraph`] replaces.
  end: usize,
  /// The bytes between the two runs.
  content: &'a str,
}

/// Every inline code span in one joined paragraph, in the order their opening
/// runs appear.
///
/// This is the ONE reading of a code span in this module. The ABNF path
/// ([`abnf_spans`]) asks which of these spans is a production; the quotation
/// path ([`mask_paragraph`]) asks which of them holds a `"`. They were two
/// walks under two pairing rules, and the defect lived in the gap: the
/// quotation path's walk was per LINE, so a span wrapped across two comment
/// lines met no closing backtick, and every `"` inside it leaked into the
/// block for [`quoted_spans`] to pair with a real quotation's.
///
/// A span opened by N backticks closes on the next run of exactly N, and the
/// runs between the two are content — CommonMark's rule rather than a
/// refinement of it, and [`abnf_spans`] names the doubled-backtick span in this
/// very file that makes it load-bearing. An opening run that finds no closer is
/// literal text, and the walk resumes at the run AFTER it rather than giving up
/// on what follows: one stray backtick costs the spans behind it nothing.
fn code_spans(text: &str) -> Vec<CodeSpan<'_>> {
  let runs = backtick_runs(text);
  let mut out = Vec::new();
  let mut at = 0usize;
  while let Some(&(open, len)) = runs.get(at) {
    let Some((index, &(close, _))) = runs
      .iter()
      .enumerate()
      .skip(at.saturating_add(1))
      .find(|(_, (_, other))| *other == len)
    else {
      at = at.saturating_add(1);
      continue;
    };
    at = index.saturating_add(1);
    let Some(content) = text.get(open.saturating_add(len)..close) else {
      continue;
    };
    out.push(CodeSpan {
      at: open,
      end: close.saturating_add(len),
      content,
    });
  }
  out
}

/// Every run of backticks in `text`, as the byte offset it starts at and how
/// many backticks long it is.
fn backtick_runs(text: &str) -> Vec<(usize, usize)> {
  let mut out = Vec::new();
  let bytes = text.as_bytes();
  let mut at = 0usize;
  while at < bytes.len() {
    if bytes.get(at) != Some(&b'`') {
      at = at.saturating_add(1);
      continue;
    }
    let start = at;
    while bytes.get(at) == Some(&b'`') {
      at = at.saturating_add(1);
    }
    out.push((start, at.saturating_sub(start)));
  }
  out
}

/// What a code span's delimiters actually enclose, once CommonMark is done
/// with it: every line ending inside it becomes a space, and one space is
/// dropped from each end when the span has one at BOTH ends and is not made of
/// spaces alone.
///
/// The second half is the rule that lets a span hold a backtick of its own —
/// the padding spaces belong to the delimiters rather than to the text — so
/// reading it is what keeps a span's first character from being one its author
/// never wrote.
fn code_span_text(content: &str) -> String {
  let joined: String = content
    .chars()
    .map(|ch| if ch == '\n' { ' ' } else { ch })
    .collect();
  if !joined.starts_with(' ') || !joined.ends_with(' ') || joined.trim().is_empty() {
    return joined;
  }
  joined
    .get(1..joined.len().saturating_sub(1))
    .unwrap_or(&joined)
    .to_string()
}

/// Reads the paragraph collected so far into `pending` as candidates and into
/// `block` as masked text, and empties it for the next one.
///
/// [`Candidate::rule`] is the span itself: a backticked production is whole
/// where its author left it, so unlike a fenced one ([`read_fenced_line`])
/// there is no continuation to join onto it — a span wrapped across lines was
/// already joined by [`abnf_spans`] before it reached here.
///
/// The block half lands HERE rather than in the caller's loop because masking
/// is a paragraph-wide question ([`mask_paragraph`]): a line cannot be masked
/// until the paragraph holding it is complete, so a line cannot be appended
/// until then either. The two are one call so the order stays the source's
/// own — every caller drains the paragraph at exactly the point its lines
/// would otherwise have been pushed.
///
/// `mask` is a parameter rather than [`mask_paragraph`] named directly, so the
/// differential in this module's tests can run the real extraction over the
/// LINE unit this replaced and compare. A counterfactual reimplemented beside
/// the loop would share none of the loop, and so could not grade it.
fn take_paragraph(
  paragraph: &mut Vec<(usize, &str)>,
  pending: &mut Spans,
  block: &mut String,
  marks: &mut Vec<(usize, usize)>,
  mask: Masker,
) {
  for (line, span) in abnf_spans(paragraph) {
    pending.push(Candidate {
      line,
      rule: span.clone(),
      span,
    });
  }
  let masked = mask(paragraph);
  for ((line, _), body) in paragraph.iter().zip(masked) {
    if !block.is_empty() {
      block.push(' ');
    }
    marks.push((block.len(), *line));
    block.push_str(&body);
  }
  paragraph.clear();
}

/// Reads one line of an admitted `text` fence into `from_fences` — as a new
/// candidate when it is production-shaped, and as the CONTINUATION of the one
/// before it when it is not.
///
/// ABNF wraps, and this workspace transcribes it the way the RFCs print it.
/// RFC 9110 §12.5.1 sets `media-range` over four lines and RFC 2046 §5.1 sets
/// `tspecials` over three, so the first line of a wrapped rule ends inside a
/// group it does not close. Reading that line as a whole rule would have
/// [`rule_fault`] report seven correct transcriptions in this tree as
/// truncated — and a check that invents failures gets switched off, which is
/// the argument the module doc already makes about the tail anchor. Re-derived
/// rather than inherited: replacing this function's join with nothing and
/// re-running `cargo run -p xtask -- quote-check` reds at exactly 7, in
/// `CHANGELOG.md`, `coding-corpus` twice, `media` twice and `range::multipart`
/// twice.
///
/// So a continuation is joined onto [`Candidate::rule`], the only field
/// `rule_fault` reads. [`Candidate::span`] keeps the single line, which is
/// what [`grade_production`] compares: the join is this extractor's doing
/// rather than the author's, and a spec's own text is what a transcribed line
/// is held to.
///
/// A continuation is a line that is not itself production-shaped and is
/// INDENTED PAST the rule it continues. That second half is the RFCs' own
/// typesetting rather than a heuristic about content — a wrapped rule's later
/// lines are set under its right-hand side, and all seven wrapped rules in this
/// workspace are — and it is what tells a continuation from the prose that
/// merely follows a rule. Without it the join reads whatever comes next, and a
/// truncated rule followed immediately by text carrying the closer it dropped
/// would BALANCE and pass: #75's own class, surviving inside the fix for #75.
/// The indent comes from [`comment_body`], which counts it before the trim that
/// throws it away.
///
/// Three things end a continuation, and all three are ends of the RULE: a blank
/// line, a line production-shaped enough to start its own candidate, and a line
/// back at or left of the rule's own indent. An ABNF `;` comment line indented
/// under the rule joins and costs nothing: `rule_fault` stops at an unquoted
/// `;`, so a comment can neither open nor close anything.
///
/// What remains open is narrow and stated: prose that is itself indented under
/// the rule still joins. At that point the author has written something set as
/// a continuation, and nothing here reads what a line MEANS.
///
/// A rule wrapped inside a BACKTICKED span is not this function's to join and
/// never was: [`abnf_spans`] joins that one where it extracts it, because a
/// code span's wrapping is Markdown's and is settled before anything asks what
/// the text says. The two joins are separate for that reason, and the fenced
/// one keeps [`Candidate::span`] on its single line where the backticked one
/// has no line left to keep.
fn read_fenced_line(
  from_fences: &mut Spans,
  continuing: &mut Option<usize>,
  line: usize,
  indent: usize,
  body: &str,
) {
  if is_production(body) {
    from_fences.push(Candidate {
      line,
      span: body.to_string(),
      rule: body.to_string(),
    });
    *continuing = Some(indent);
    return;
  }
  if body.trim().is_empty() {
    *continuing = None;
    return;
  }
  // Back at the rule's own indent, or left of it: the rule is over, whatever
  // this line is. Clearing rather than merely declining is the half that
  // bounds the damage — one un-indented line ends the join for the rest of the
  // paragraph instead of letting a later indented one resume it.
  let Some(opened) = *continuing else {
    return;
  };
  if indent <= opened {
    *continuing = None;
    return;
  }
  if let Some(candidate) = from_fences.last_mut() {
    candidate.rule.push(' ');
    candidate.rule.push_str(body.trim());
  }
}

// The two spans below name the SHAPE this function matches rather than any RFC's
// rule, and both are production-shaped by construction — this is the tool inside
// its own corpus, and the marker is the mechanism it documents for exactly that.
// gate-exempt: name = value — metasyntax for the shape, not a production of any RFC
// gate-exempt: name := value — the same shape in RFC 2046's spelling
/// Whether `span` opens with a grammar rule name and a single `=`, optionally
/// preceded by RFC 2046's `:`.
///
/// Two Rust shapes reach the same first character and neither is assignment:
/// a comparison (`need == out.len()`) and a match arm (`other => panic!()`).
/// Requiring the character AFTER the `=` to be neither a second `=` nor a
/// `>` is what excludes both, while `=/` — RFC 5234's incremental
/// alternative — still counts, its second character being `/`.
///
/// # `:=`, and why the SEPARATOR is the only thing widened
///
/// RFC 9110 and its siblings write `name = value`; **RFC 2046 writes
/// `name := value`**, for all 26 of its productions. §14.6 delegates the
/// `multipart/byteranges` framing to that RFC and §19.1 lists it as normative,
/// so this workspace transcribes its rules — `dash-boundary`, `delimiter`,
/// `close-delimiter`, `transport-padding`, `discard-text`, `body-part`,
/// `encapsulation`, `boundary`, `bchars` — and every one of them was
/// hand-checked and ungraded until the `:` was admitted here. An optional `:`
/// before the `=` is the WHOLE of that change.
///
/// Nothing on the right-hand side moved, and that is a ruling rather than a
/// scope decision: narrowing there was tried and rejected, because any rule
/// keyed on the right-hand side makes a BROKEN production stop looking like one
/// too, and a check whose defect makes the item disappear is worse than no
/// check. [`exempted_spans`] carries that ruling in full, and its marker is
/// what a production-shaped span that is not a production is answered with.
///
/// The `:` is not trimmed away from the `=`: RFC 2046 writes the two adjacent,
/// so `foo: = bar` is not a production and neither is a Rust path — `Self::x`
/// puts a second `:` where the `=` would have to be.
///
/// The `=>` half arrived with the fenced-line count, which is where a match
/// arm turns up: this workspace's two README fences each write one, and a
/// Rust match arm counted as unreached GRAMMAR would misstate the very
/// boundary that count exists to state. No BACKTICKED span in this workspace
/// is production-shaped only through `=>` — checked before the rule narrowed
/// — so no existing counter moved when it landed. It guards the READ path
/// now as well: a `text` fence may hold Rust ([`fence_holds_grammar`]), and a
/// match arm offered to [`grade_production`] as a rule would be a failure
/// invented out of a code sample.
fn is_production(span: &str) -> bool {
  right_hand_side(span).is_some()
}

/// Everything past the `=`, `=/` or `:=` that [`is_production`] recognises, or
/// `None` when `span` carries no such operator.
///
/// The single derivation of where a rule's name ends and its definition
/// begins. [`is_production`] is this function asked for a yes or a no, so a
/// candidate's ADMISSION and the text [`rule_fault`] reads can never disagree
/// about which character was the operator — the shape test would otherwise be
/// judging a right-hand side the admission test never granted.
///
/// The `/` of `=/` belongs to the operator and is dropped with it: RFC 5234
/// writes the two characters adjacent, so a `/` immediately behind the `=` is
/// the incremental-alternative mark rather than the first alternation of an
/// empty alternative. A `/` behind a SPACE is left alone, because that one is
/// the rule's own.
fn right_hand_side(span: &str) -> Option<&str> {
  let trimmed = span.trim_start();
  let name: String = trimmed
    .chars()
    .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
    .collect();
  if name.is_empty() || !name.starts_with(|ch: char| ch.is_ascii_alphabetic()) {
    return None;
  }
  let after_name = trimmed.get(name.len()..)?.trim_start();
  let after_name = after_name.strip_prefix(':').unwrap_or(after_name);
  let rest = after_name.strip_prefix('=')?;
  if rest.starts_with(['=', '>']) {
    return None;
  }
  Some(rest.strip_prefix('/').unwrap_or(rest))
}

/// What stops a production-shaped span from being a whole ABNF rule.
///
/// Each variant names the CHARACTER the fault is about, because the repair is
/// always a character: the one that was dropped, or the one that should not
/// have been there.
#[derive(Debug, PartialEq, Eq)]
enum RuleFault {
  /// A name and an operator with no grammar behind them — an empty
  /// right-hand side, or a span with no operator at all.
  Empty,
  /// A `(`, `[`, `"` or `<` the rule opens and never closes. This is the
  /// truncation case: a production whose tail was dropped mid-group.
  Unclosed(char),
  /// A `)` or `]` with nothing open for it to close — the truncation's
  /// mirror, a production whose head was dropped.
  Unopened(char),
  /// A `)` or `]` closing the wrong opener; the closer first, then what was
  /// actually open.
  Mismatched(char, char),
}

impl RuleFault {
  /// The line [`run`] prints under a malformed production.
  fn reason(&self) -> String {
    match *self {
      Self::Empty => "nothing on the right of the definition operator".to_string(),
      Self::Unclosed(ch) => format!("a `{ch}` this never closes"),
      Self::Unopened(ch) => format!("a `{ch}` closing nothing"),
      Self::Mismatched(close, open) => format!("a `{close}` closing a `{open}`"),
    }
  }
}

// The span below is the TRUNCATION this function rejects, quoted so the doc can
// name it — RFC 9110 §10.1.4's rule with its closing ` )` dropped. This file is
// inside the corpus it scans, and the marker is the mechanism it documents for
// exactly that.
// gate-exempt: transfer-coding = token *( OWS ";" OWS transfer-parameter — the measured truncation, quoted to name it, not a production of any RFC
/// What stops `rule` from being a whole ABNF rule, or `None` when nothing
/// does — the test a candidate passes before [`grade_production`] compares it
/// with a spec at all.
///
/// # The hole this closes
///
/// The comparison is a SUBSTRING test, so a production with its tail cut off
/// still matches: `transfer-coding = token *( OWS ";" OWS transfer-parameter`
/// is a substring of RFC 9110 §10.1.4's own text, and the run that graded it
/// said `verbatim` and meant it. That is not a hypothetical — a transcription
/// that carried §10.1.4's inner `transfer-parameter` and omitted the
/// CONTAINER it sits in passed this gate, and the container is the half where
/// the two grammars differ: §5.6.6 brackets the slot, §10.1.4 does not. It was
/// verbatim. It was also half a grammar.
///
/// # What "whole" means here, exactly
///
/// A rule is a name, an operator, and a right-hand side that BALANCES. This
/// walks the right-hand side once and asks only that:
///
/// - `(` and `[` must be closed, by `)` and `]` respectively and in that
///   nesting order. A `)` or `]` with nothing open is the same fault seen
///   from the other end.
/// - `"` opens an RFC 5234 `char-val` and `<` a `prose-val`; neither may hold
///   its own closing character, so the first `"` or `>` after one closes it
///   and nothing between them is read. That is what keeps §5.6.6's `";"` from
///   being taken for a comment and RFC 2046's `<">` from being taken for an
///   unbalanced quote.
/// - `;` outside both begins an ABNF comment, which ends the rule. Everything
///   behind it is prose about the grammar rather than grammar.
/// - Something must remain: a name and an operator with nothing behind them
///   is a rule that defines nothing.
///
/// # What it accepts that is not, in fact, a whole rule
///
/// Everything whose truncation falls on a boundary this cannot see. A rule
/// with no brackets in it — `media-type = type "/" subtype parameters` — can
/// lose its last name and still balance, still be a substring, and still pass
/// here. So can one truncated at a `/` between two complete alternatives. The
/// claim is bounded and worth stating in exactly these words: this rejects a
/// production truncated INSIDE a group, which is the shape the measured
/// defect had and the shape most truncations of an HTTP production have,
/// because HTTP's productions are mostly groups. It does not decide that a
/// transcription is the WHOLE of its rule, and nothing that reads only the
/// comment can — the rule's own name is the only thing that says how much of
/// it there should be, and matching on that is a larger design than this.
///
/// And a production carrying an ELISION mark, which is the one case this
/// declines to answer at all rather than answering wrongly. `…` and `...` are
/// this file's existing convention for an author cutting the middle out on
/// purpose, read by [`run`] as it splits a span into the segments it grades; a
/// rule that says it is not whole is not one for a wholeness test to fail.
///
/// This is also, deliberately, not part of [`is_production`]. Keying
/// ADMISSION on the right-hand side would make a broken production stop
/// looking like a production, so the gate's own defect would delete the item
/// it should be reporting — [`exempted_spans`] carries that ruling, and this
/// is the shape it demands: admitted by the name and the operator, FAILED on
/// the right-hand side.
fn rule_fault(rule: &str) -> Option<RuleFault> {
  // An ELIDED production has already said of itself that it is not whole, and
  // whole is the only thing this asks. `run` splits a span on the same two
  // marks and grades the segments either side of them, precisely because the
  // author declared the middle missing; asking the declared fragment to
  // balance would report an author's own `…` back at them, and the repair —
  // move the elision until the brackets pair — is arbitrary. The mark is as
  // visible in the source as a `gate-exempt:` marker, and reading it the same
  // way on both paths is what keeps this from being a second, quieter meaning
  // for the same three characters.
  if rule.contains('…') || rule.contains("...") {
    return None;
  }
  // Every caller hands this a candidate `is_production` already admitted, so
  // the operator is there. A span without one has no right-hand side at all,
  // which is the extreme of the same fault rather than the absence of it.
  let Some(rhs) = right_hand_side(rule) else {
    return Some(RuleFault::Empty);
  };
  let mut open: Vec<char> = Vec::new();
  // The `char-val` or `prose-val` now being passed over, if any.
  let mut inside: Option<char> = None;
  // Whether anything at all sits behind the operator.
  let mut anything = false;
  for ch in rhs.chars() {
    if let Some(delimiter) = inside {
      if (delimiter == '"' && ch == '"') || (delimiter == '<' && ch == '>') {
        inside = None;
      }
      continue;
    }
    match ch {
      ';' => break,
      '"' | '<' => {
        inside = Some(ch);
        anything = true;
      }
      '(' | '[' => {
        open.push(ch);
        anything = true;
      }
      ')' | ']' => {
        let Some(opener) = open.pop() else {
          return Some(RuleFault::Unopened(ch));
        };
        if !matches!((opener, ch), ('(', ')') | ('[', ']')) {
          return Some(RuleFault::Mismatched(ch, opener));
        }
        anything = true;
      }
      ch if ch.is_whitespace() => {}
      _ => anything = true,
    }
  }
  if let Some(delimiter) = inside {
    return Some(RuleFault::Unclosed(delimiter));
  }
  // The innermost still-open group: the one whose closer is missing first.
  if let Some(opener) = open.pop() {
    return Some(RuleFault::Unclosed(opener));
  }
  if !anything {
    return Some(RuleFault::Empty);
  }
  None
}

/// Whether a fence's `info` string says the block holds transcribed text
/// rather than code — the one question that decides whether
/// [`is_production`] gets to read the lines inside it.
///
/// The discrimination had to come from somewhere the production's right-hand
/// side is not: narrowing [`is_production`] was tried and rejected, because
/// any rule keyed on the right-hand side makes a BROKEN production stop
/// looking like one too (see [`exempted_spans`] for that ruling in full). The
/// info string is that somewhere, and it is a DECLARATION rather than an
/// inference — `text` is rustdoc's own mark for a block it will not compile,
/// and it is what this workspace tags every one of its grammar
/// transcriptions with.
///
/// Nothing else is admitted, `abnf` included. An allow-list entry with no
/// instance behind it is a guess, and it does not need to be one: a fence
/// tagged otherwise that holds grammar is still COUNTED and printed by
/// [`run`], so the next tag worth reading arrives as a number rather than as
/// an absence. The list is deliberately not "anything rustdoc will not
/// compile" either — `sh` is the concrete reason, a shell variable
/// assignment being production-shaped.
///
/// A `text` fence is not thereby grammar, and nothing here claims it is: two
/// of this workspace's hold Rust shown for a caller to copy, and
/// [`is_production`] declines every line of both. The fence answers "may
/// these lines be read at all"; the shape test still answers "is this one a
/// rule"; and a production-shaped line that is neither is what
/// [`exempted_spans`]'s marker exists for.
///
/// A production read this way is admitted WITHOUT the citation [`cited_rfcs`]
/// requires of a backticked one, and that asymmetry is the point. The
/// citation is what tells [`exempted_spans`]'s backticked Rust value from a
/// grammar rule; the info string answers that earlier and more directly, so
/// requiring both would be requiring one piece of evidence twice.
///
/// What requiring it would COST is now a small number rather than most of
/// the reading, and the two halves of that figure have different standing.
/// The denominator is printed by every run: 32 fenced productions read
/// today. The split inside it is not printed and was measured by
/// instrumenting this extractor — 3 of the 32 sit under prose naming no RFC
/// at all, so a citation requirement would withhold exactly those three. It
/// was 27 of 32 while the backticked gate demanded EXACTLY one citation, 24
/// of these productions sitting under prose that names four RFCs; that
/// collapse is the backticked gate's widening, not a change on this path.
/// An earlier revision of this sentence read "fourteen fenced productions,
/// nine" — true of the workspace it was written against — so treat the
/// unprinted half as of its measurement and re-measure before leaning on it,
/// exactly as `doc-check`'s table census says of its own count.
///
/// Nothing is lost in grading either way, because [`grade_production`] never
/// used the citation to pick a spec — an admitted production is checked
/// against every loaded one.
fn fence_holds_grammar(info: &str) -> bool {
  info.trim() == "text"
}

/// Every distinct RFC number `block` names, in first-mention order.
///
/// The SET, not one number and not a yes/no: a block naming several RFCs has
/// made several attributions, and collapsing them to "ambiguous" throws away
/// the one thing a quotation inside it can be held to — that it is one of
/// THESE specs' text and not some fourth spec's. Ruling 12 records what that
/// collapse cost, measured: 184 of this workspace's 493 checked quotations
/// sat in a block naming several RFCs, and were graded against every loaded
/// spec instead.
///
/// Its two callers read the same set differently, and the difference is
/// deliberate:
///
/// - [`grade`] takes the whole set: a quotation is that block's business
///   when the block names ANY spec this run loaded.
/// - The production gate in [`quotations`] asks only whether the set is
///   EMPTY. It is an ADMISSION test and nothing more: a block naming no RFC
///   makes no claim for this check to grade, and a production-shaped span
///   there is not its business. WHICH spec an admitted production is held to
///   is not this set's answer at all — [`grade_production`] searches every
///   loaded spec regardless — so a block naming four RFCs is exactly as
///   admissible as one naming a single RFC.
///
///   Requiring EXACTLY one, which this gate did until it was measured, made
///   the check grade FEWER productions the more accurate a citation became:
///   adding a correct second RFC to a doc block un-graded every
///   production-shaped span already in it, untouched — including spans the
///   edit never went near. It withheld 48 of this workspace's backticked
///   candidates; 44 of those clear [`grade_production`]'s three-word floor,
///   and 43 are verbatim in a loaded spec — among them
///   `chunk-size = 1*HEXDIG`, `HTTP-name = %s"HTTP"`, and
///   `field-line = field-name ":" OWS field-value OWS`. The 44th is
// gate-exempt: x = 1 — the same instance the sentence below names, quoted here to name it; this file is inside its own corpus
///   `websocket-proto/src/negotiation.rs`'s `x = 1`, an INSTANCE quoted from
///   RFC 6455 §9.1's prose rather than a rule, and it carries a
///   `gate-exempt:` marker ([`exempted_spans`]) — the mechanism this
///   workspace already has for a production-shaped non-production, and the
///   only one available, since nothing here may be keyed on a production's
///   right-hand side. Suppressing one false positive by withholding 43 real
///   checks is the trade this gate was making.
///
///   The run's own last line is where that is recountable rather than
///   asserted: it read `100 ABNF productions verbatim` before the widening
///   and `146` after. 43 of the 46 are the widening; the other three are the
///   productions this very paragraph quotes as examples, which is this file
///   being inside the corpus it scans.
///
///   See [`grade_production`]'s doc comment for why that path is the
///   asymmetric one.
fn cited_rfcs(block: &str) -> Vec<u32> {
  let mut found: Vec<u32> = Vec::new();
  let mut rest = block;
  while let Some(at) = rest.find("RFC ") {
    let after = &rest[at + 4..];
    let digits: String = after.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    rest = &after[digits.len()..];
    // No digits after the space, or more of them than an RFC number has:
    // either way this is not a citation.
    let Ok(cited) = digits.parse::<u32>() else {
      continue;
    };
    if !found.contains(&cited) {
      found.push(cited);
    }
  }
  found
}

/// What one masked code span leaves behind in the block.
///
/// Length is not preserved and does not need to be: the block's line marks are
/// recorded as the masked bodies are appended, so an offset in the block is an
/// offset into what this replacement produced.
const MASK: &str = "<code>";

/// Masks the inline code spans holding a `"` across one PARAGRAPH, returning
/// one masked body per line in the paragraph's own order.
///
/// `` `"` `` is a quote character being NAMED, not one opening a quotation, and
/// leaving it in place pairs it with a real quotation's and swallows a
/// paragraph.
///
/// # Why the unit is a paragraph and not a line
///
/// It was a line, and a line is where a QUOTATION could leave this gate
/// altogether — the same escape [`abnf_spans`] closed one path over, arriving
/// through this one. A code span too long for one comment line gets wrapped;
/// masking a line at a time met an opening backtick with no closer on that
/// line, and every `"` inside the span leaked into the block. [`quoted_spans`]
/// pairs quotes left to right, so an ODD number of leaked quotes displaces
/// every real quotation after it: the author's opening `"` is consumed as a
/// closer and their closing `"` becomes an opener. Whether anyone found out
/// depended on the prose between the two — long enough to be graded and the
/// false span surfaced as untriaged, shorter than [`MIN_WORDS`] / [`MIN_CHARS`]
/// and [`grade`] returned early without counting it, so the real quotation was
/// never graded, never counted and never reported.
///
/// # Why the unit is not the whole block
///
/// A block is several paragraphs, and a code span may not cross a blank line —
/// so pairing backticks over a whole block pairs two paragraphs' unrelated
/// stray backticks and masks everything between them, quotations included.
/// Measured on this workspace the block unit invented a span in this module's
/// own doc comment, which is one span more than the line unit it was meant to
/// improve on; `a_stray_backtick_pairs_no_further_than_its_own_paragraph` holds
/// that boundary. The paragraph is the unit rustdoc renders and the unit
/// [`abnf_spans`] already reads, so it is the unit both paths now share.
fn mask_paragraph(paragraph: &[(usize, &str)]) -> Vec<String> {
  let (text, starts) = join_paragraph(paragraph);
  // Sorted and non-overlapping, because `code_spans` resumes after the closer
  // of the span it just read — which is what lets the walk below advance a
  // cursor through them once per line.
  let masked: Vec<(usize, usize)> = code_spans(&text)
    .iter()
    .filter(|span| span.content.contains('"'))
    .map(|span| (span.at, span.end))
    .collect();
  let mut out = Vec::with_capacity(paragraph.len());
  for (index, (_, body)) in paragraph.iter().enumerate() {
    let start = starts.get(index).map_or(0, |(offset, _)| *offset);
    let end = start.saturating_add(body.len());
    let mut line = String::with_capacity(body.len());
    let mut cursor = start;
    for &(from, to) in &masked {
      if to <= start || from >= end {
        continue;
      }
      let head = from.clamp(start, end);
      if head > cursor {
        line.push_str(text.get(cursor..head).unwrap_or_default());
      }
      // The mask is emitted once, on the line the span OPENS on: a line that
      // merely holds the span's continuation contributes nothing for it, which
      // is what a wrapped span looks like once it is one span again.
      if from >= start {
        line.push_str(MASK);
      }
      cursor = to.clamp(start, end).max(cursor);
    }
    if cursor < end {
      line.push_str(text.get(cursor..end).unwrap_or_default());
    }
    out.push(line);
  }
  out
}

/// Reduces a QUOTATION to the characters a comparison may turn on.
///
/// The module docs list what goes and why; nothing here is allowed to change a
/// word. [`normalise_production`] is the ABNF path's version, differing in
/// exactly one rule — see [`strip_bracket_insertions`] for why the two cannot
/// be one function.
fn normalise(text: &str) -> String {
  squeeze(&strip_bracket_insertions(&strip_cross_references(text)))
}

/// Reduces an ABNF PRODUCTION to the characters a comparison may turn on:
/// [`normalise`] without [`strip_bracket_insertions`].
///
/// `[ … ]` is RFC 5234's optional-element syntax. It is part of the rule, so
/// removing it does not normalise a production, it deletes half of one — and
/// removing it from the spec's side too makes the comparison agree with itself
/// about a stub. Everything else is shared, because everything else is a
/// difference a Rust comment cannot avoid or the RFC's own typesetting, which
/// is as true of a production as of a sentence.
fn normalise_production(text: &str) -> String {
  squeeze(&strip_cross_references(text))
}

/// The shared half of both normalisations: collapses whitespace and drops the
/// characters neither side is allowed to differ on.
fn squeeze(text: &str) -> String {
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

/// Removes every `[bracketed]` span, and the space before it — on the
/// QUOTATION path only ([`normalise`]), never on the ABNF one
/// ([`normalise_production`]).
///
/// That split is not a refinement, it is the fix for a defect: `[ … ]` means
/// opposite things on the two paths. Here it is an editorial mark, described
/// below. In ABNF it is optional-element SYNTAX (see [`normalise_production`]
/// for the citation), so applying this rule to a production deleted part of
/// the production — and applying it to the spec's side as well made the
/// deletion invisible, because both sides then agreed about the same stub.
/// The worked example, and the reason this doc comment is where it lives:
/// `parameters` was graded with its `[ parameter ]` gone from comment and
/// spec alike, so what was actually compared was `*( OWS ; OWS )`, and
/// nothing inside the optional group was ever read. A comparison that reports
/// verbatim while comparing a stub is the exact failure this whole command
/// exists to remove, so the ABNF path keeps its brackets.
///
/// `[…]` is the standard mark for an editorial insertion in a quotation, and
/// the RFC's OWN prose uses it the same way for an inline `[RFC2616]`-style
/// reference: RFC 6455 §4.1 reads "...the client handles the response per
/// HTTP `[RFC2616]` procedures..." (`.rfc-cache/rfc6455.txt:1031`), while
/// `websocket-proto/src/handshake/h1/client.rs`'s quotation of that sentence
/// never spells the citation at all ("...per HTTP procedures..."). Stripping
/// `[RFC2616]` from the spec's side — nothing needs stripping from the
/// comment's, since it was never there — is what lets that quotation anchor
/// and match at all. `normalise` runs over a spec's text exactly as it runs
/// over a comment's, so a bracket either side chose to insert is gone from
/// both before anything else is compared.
///
/// What this does NOT fix: a bracket that SUBSTITUTES words the RFC has at
/// that exact point — `consider [it]` standing in for the RFC's own
/// `consider that data` — still fails, because the substituted words are, by
/// definition, not the RFC's own characters. Removing the bracket removes the
/// substitution, not the mismatch: the RFC's real words are still sitting
/// where the comment's gap now is. A quotation shaped like that has one fix,
/// and it is not in this function — quote the RFC's own words instead of a
/// stand-in for them, the way `inbound.rs:107` now does.
fn strip_bracket_insertions(text: &str) -> String {
  let mut out = String::with_capacity(text.len());
  let mut rest = text;
  while let Some(open) = rest.find('[') {
    let after = &rest[open + 1..];
    let Some(close) = after.find(']') else {
      // No closing bracket on the rest of this text: nothing more to strip.
      out.push_str(&rest[..open]);
      rest = after;
      break;
    };
    out.push_str(&rest[..open]);
    while out.ends_with(' ') || out.ends_with('\t') {
      out.pop();
    }
    rest = &after[close + 1..];
  }
  out.push_str(rest);
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
    // Joined once, normalised twice: the two paths differ only in the bracket
    // rule, and rejoining for each would be the same work done again.
    let joined = spec_lines(&fs::read_to_string(&path)?);
    let text = normalise(&joined);
    let grammar = normalise_production(&joined);
    let lower = text.to_ascii_lowercase();
    specs.push(Spec {
      name,
      text,
      grammar,
      lower,
    });
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
/// that pulls a TLS stack in to fetch a handful of text files has bought
/// nothing. Spelled without a count so adding one does not date the sentence.
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
///
/// Returns the joined text UNNORMALISED: [`load_specs`] runs both
/// normalisations over it, and a spec normalised the quotation way cannot be
/// re-normalised the production way — [`strip_bracket_insertions`] has already
/// taken the brackets by then.
fn spec_lines(raw: &str) -> String {
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
  joined
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
  use super::{
    MIN_CHARS, MIN_WORDS, Masker, markdown_quotations, markdown_quotations_masked, mask_paragraph,
    normalise, quotations, quotations_masked, spans_for, untriaged_drift,
  };
  use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
  };

  // ==== the masking unit, and the differential that grades the choice ====

  /// The per-line masking this command shipped before the paragraph unit,
  /// verbatim, as the counterfactual the differential below measures against.
  ///
  /// It is here rather than in the module because nothing but a measurement
  /// may run it: an opening backtick with no closer ON THAT LINE made it give
  /// up and emit the rest of the line raw, which is the leak
  /// [`super::mask_paragraph`] exists to close.
  fn mask_each_line(paragraph: &[(usize, &str)]) -> Vec<String> {
    paragraph.iter().map(|(_, body)| mask_line(body)).collect()
  }

  fn mask_line(line: &str) -> String {
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

  /// The spans one source yields under `mask` that are large enough for
  /// `grade` to have an opinion about — the same ellipsis split, the same
  /// `normalise`, and the same two floors `grade` applies before it will look
  /// at a span at all.
  ///
  /// The floors are the whole point of measuring here rather than counting
  /// what `run` prints: a span BELOW them leaves `grade` as a silent `None`
  /// that is not counted anywhere, so a quotation displaced into one
  /// disappears without moving a single printed number.
  fn graded_spans(path: &Path, source: &str, mask: Masker) -> Vec<(usize, String)> {
    let extracted = if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
      markdown_quotations_masked(source, mask)
    } else {
      quotations_masked(source, mask)
    };
    let mut out = Vec::new();
    for (line, span, _) in extracted.quoted {
      for segment in span.split(['…']).flat_map(|part| part.split("...")) {
        let quoted = normalise(segment);
        if quoted.split_whitespace().count() >= MIN_WORDS && quoted.chars().count() >= MIN_CHARS {
          out.push((line, quoted));
        }
      }
    }
    out
  }

  /// Every graded-size span the two masking units disagree about in one
  /// source, as (line, span, which unit found it).
  fn masking_disagreements(path: &Path, source: &str) -> Vec<(usize, String, &'static str)> {
    let paragraph = graded_spans(path, source, mask_paragraph);
    let line = graded_spans(path, source, mask_each_line);
    let mut out = Vec::new();
    for span in &paragraph {
      if !line.contains(span) {
        out.push((span.0, span.1.clone(), "paragraph unit only"));
      }
    }
    for span in &line {
      if !paragraph.contains(span) {
        out.push((span.0, span.1.clone(), "line unit only"));
      }
    }
    out
  }

  /// Every `.rs` and `.md` file this workspace tracks, by the same walk
  /// `run` makes — ignored trees left out, so the number this test holds is
  /// the number CI would hold.
  fn workspace_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
      .parent()
      .expect("the workspace root");
    let mut out = Vec::new();
    let mut skipped = 0usize;
    super::collect_sources(root, &mut out, false, &mut skipped).expect("the source walk");
    out.sort();
    out
  }

  fn counts(pairs: &[(&str, usize)]) -> BTreeMap<String, usize> {
    pairs
      .iter()
      .map(|(file, count)| ((*file).to_string(), *count))
      .collect()
  }

  // The backlog's gate, in every direction it has one. A fabricated quotation
  // arrives as the first row and as nothing else — it anchors in no spec, so
  // no grade can ever reach it — which is why "more than recorded" has to fail
  // rather than print. The other three rows are what keeps that number honest:
  // a file whose backlog SHRANK and a table entry with nothing behind it are
  // both the ratchet slipping, and a file absent from the table holding spans
  // is the same thing as the first row with the entry left off.
  #[test]
  fn the_untriaged_backlog_is_held_in_both_directions() {
    let table = &[("a.rs", 2), ("b.rs", 1)];

    assert!(untriaged_drift(&counts(&[("a.rs", 2), ("b.rs", 1)]), table, false).is_empty());

    let grown = untriaged_drift(&counts(&[("a.rs", 3), ("b.rs", 1)]), table, false);
    assert_eq!(grown.len(), 1, "{grown:?}");
    assert!(
      grown[0]
        .1
        .contains("a.rs: 3 untriaged span(s), `UNTRIAGED` records 2")
    );

    let shrunk = untriaged_drift(&counts(&[("a.rs", 1), ("b.rs", 1)]), table, false);
    assert_eq!(shrunk.len(), 1, "{shrunk:?}");
    assert!(shrunk[0].1.contains("Lower the number here"));

    let stale = untriaged_drift(&counts(&[("a.rs", 2)]), table, false);
    assert_eq!(stale.len(), 1, "{stale:?}");
    assert!(stale[0].1.contains("the whole entry is stale"));

    // And the FILE beside each message, which is what lets `run` print the
    // spans that drifted underneath it. A message alone names a count and a
    // file to open; the pairing is what turns that into something a reader can
    // act on, and the cheap answer to a failure nobody can act on is the bless
    // `UNTRIAGED` exists to refuse.
    assert_eq!(grown[0].0, "a.rs");
    assert_eq!(shrunk[0].0, "a.rs");
    assert_eq!(stale[0].0, "b.rs");
  }

  // The one relaxation, and its boundary. `docs/` is gitignored, so a file the
  // table does not list is required to hold nothing ONLY when the run scanned
  // the tracked tree — otherwise one command would check two different sets
  // depending on where it ran. A file the table DOES list is checked either
  // way, because it is tracked and present in both.
  #[test]
  fn an_unlisted_file_is_required_to_hold_none_only_on_the_tracked_tree() {
    let table = &[("a.rs", 2)];
    let found = counts(&[("a.rs", 2), ("docs/design.md", 9)]);

    let tracked = untriaged_drift(&found, table, false);
    assert_eq!(tracked.len(), 1, "{tracked:?}");
    assert!(tracked[0].1.contains("docs/design.md"));
    assert!(tracked[0].1.contains("not in `UNTRIAGED`"));

    assert!(untriaged_drift(&found, table, true).is_empty());

    // …and the listed file still is, with the ignored tree scanned.
    let drifted = counts(&[("a.rs", 3), ("docs/design.md", 9)]);
    let both = untriaged_drift(&drifted, table, true);
    assert_eq!(both.len(), 1, "{both:?}");
    assert!(both[0].1.contains("a.rs"));
  }

  // One candidate flattened to the three things an extraction test is about.
  // `span` and `rule` are shown separately on purpose: they are equal for
  // every candidate that is not a fenced rule with continuation lines behind
  // it, and a test that printed only one of them could not tell the two
  // cases apart.
  fn triples(productions: &[super::Candidate]) -> Vec<(usize, &str, &str)> {
    productions
      .iter()
      .map(|candidate| {
        (
          candidate.line,
          candidate.span.as_str(),
          candidate.rule.as_str(),
        )
      })
      .collect()
  }

  fn spans(source: &str) -> Vec<String> {
    quotations(source)
      .quoted
      .into_iter()
      .map(|(_, s, _)| s)
      .collect()
  }

  // `markdown_quotations` mirrors `spans` above: same shape, different source
  // function, because a `.md` file has no comment prefix to key off of.
  fn markdown_spans(source: &str) -> Vec<String> {
    markdown_quotations(source)
      .quoted
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
    let md = spans_for(Path::new("notes.md"), source);
    // The span carries its block's own citations as its third element.
    assert_eq!(
      md.quoted,
      vec![(1, "the server MUST NOT process".to_string(), vec![9112])]
    );
    assert!(md.productions.is_empty());
    assert_eq!((md.uncited, md.fenced), (0, 0));
    let rs = spans_for(Path::new("notes.rs"), source);
    assert!(rs.quoted.is_empty());
    assert!(rs.productions.is_empty());
    assert_eq!((rs.uncited, rs.fenced), (0, 0));
  }

  // One paragraph's spans without their line numbers, for the tests below
  // that are about the SHAPE a span has to have rather than about where it
  // was written. The ones about wrapping keep the numbers.
  fn one_line(line: &str) -> Vec<String> {
    super::abnf_spans(&[(1, line)])
      .into_iter()
      .map(|(_, span)| span)
      .collect()
  }

  // An ABNF production reaches neither existing path: `mask_paragraph` erases
  // a backticked span holding a `"`, and `quoted_spans` only takes `"…"`. It
  // needs its own extractor, and this is the shape that finds one.
  #[test]
  fn a_backticked_production_is_extracted() {
    let line = "  /// RFC 9110 §8.3.1: `media-type = type \"/\" subtype parameters`";
    assert_eq!(
      one_line(line),
      ["media-type = type \"/\" subtype parameters"]
    );
  }

  // Prose in backticks is not a production. The `=` is what distinguishes a
  // rule from a name, and requiring it is what keeps this extractor quiet.
  #[test]
  fn a_backticked_name_is_not_a_production() {
    assert!(one_line("  /// see `open_request` and `Connection`").is_empty());
  }

  // `is_production` once saw only the FIRST character after `name`, so a Rust
  // equality check opened a production too. Requiring the SECOND character
  // not to be `=` closes that without rejecting `=/`, RFC 5234's
  // incremental-alternative operator. A match arm's `=>` is rejected on the
  // same grounds and for the same reason — it is Rust, not RFC 5234 — which
  // is what keeps a README fence's match arm out of the fenced-line count.
  #[test]
  fn a_double_equals_is_not_a_production() {
    let line = "  // the EXACT fit, `need == out.len()`: the boundary between the two arms";
    assert!(one_line(line).is_empty());
    let arm = "  // `other => unreachable!()` is a match arm, not a rule";
    assert!(one_line(arm).is_empty());
    let incremental = "  // `rule =/ extra-alternative` still opens one";
    assert_eq!(one_line(incremental), ["rule =/ extra-alternative"]);
  }

  // The hole this closes, and it is one step earlier than the truncation one:
  // a rule too long for a comment line is WRAPPED, so pairing backticks within
  // a line found no closer, extracted nothing, and the rule was never graded
  // at all. The span comes back joined, carrying the line its OPENING backtick
  // is on, and the line ending inside it is a space — which is what CommonMark
  // says a code span does with one.
  #[test]
  fn a_span_wrapped_across_two_lines_is_still_one_span() {
    let paragraph = [
      (7, "RFC 9110 §10.1.4: `transfer-coding = token"),
      (8, "*( OWS \";\" OWS transfer-parameter )`"),
    ];
    assert_eq!(
      super::abnf_spans(&paragraph),
      vec![(
        7,
        "transfer-coding = token *( OWS \";\" OWS transfer-parameter )".to_string()
      )]
    );
  }

  // The reason the pairing counts backtick RUNS. A comment writes a literal
  // backtick by wrapping it in two, and `exempted_spans`'s own doc comment
  // wraps such a span across two lines — the two rows below are that comment,
  // verbatim. Pairing single backticks would take the head from one line and
  // the tail from the next and call the join a rule; the run rule reads one
  // span, which holds backticks and is not production-shaped.
  #[test]
  fn a_doubled_backtick_span_is_not_two_single_ones() {
    let paragraph = [
      (
        1,
        "is none) as a deliberate non-production rather than a silent one: `` `q =",
      ),
      (
        2,
        "1` `` is production-SHAPED — [`is_production`] cannot tell a grammar rule",
      ),
    ];
    assert_eq!(super::abnf_spans(&paragraph), vec![]);
    assert_eq!(
      super::code_span_text(" `q =\n1` "),
      "`q = 1`",
      "the line ending is a space, and one padding space goes from each end"
    );
  }

  // An opening run with no partner of its own length is literal text, and the
  // walk resumes at the run AFTER it rather than abandoning what is left. Over
  // a paragraph that matters more than it did over a line, which is all the
  // line-at-a-time version could give up on.
  //
  // The second half is the shape this does NOT rescue, stated because it is
  // the one a reader will expect it to: a stray SINGLE backtick pairs with the
  // next single one, so it takes the following span's opener as its closer and
  // shifts every pairing behind it. That is what CommonMark says and what
  // rustdoc renders, and reading it differently would mean grading text no
  // reader of the docs ever sees as a code span.
  #[test]
  fn an_unpartnered_run_does_not_hide_the_spans_behind_it() {
    let doubled = [
      (3, "a stray `` opens nothing, and"),
      (4, "`token = 1*tchar` is read all the same"),
    ];
    assert_eq!(
      super::abnf_spans(&doubled),
      vec![(4, "token = 1*tchar".to_string())]
    );

    let single = [
      (3, "a stray ` opens a span, and"),
      (4, "`token = 1*tchar` closes it instead of opening its own"),
    ];
    assert_eq!(super::abnf_spans(&single), vec![]);
  }

  // The fence this workspace transcribes its grammar in, read at last: a
  // `text` fence's production-shaped line becomes a candidate with its own
  // line number, and nothing is left in the unreached count.
  //
  // Written as ONE source line with escaped newlines, not as a wrapped
  // literal: a fixture spelled across real lines IS a `text` fence to this
  // file's own scanner, and this fixture is a production nobody transcribed —
  // it would now be GRADED against the specs and fail the workspace's own
  // gate, where before the widening it merely inflated a count. The same
  // reason `a_fenced_block_is_skipped_and_does_not_reach_past_code` is
  // spelled this way, with more riding on it.
  #[test]
  fn a_text_fenced_production_is_read() {
    let fenced =
      "  /// RFC 9112 §7:\n  /// ```text\n  /// transfer-parameter = token BWS\n  /// ```\n";
    let extracted = quotations(fenced);
    assert_eq!(
      triples(&extracted.productions),
      vec![(
        3,
        "transfer-parameter = token BWS",
        "transfer-parameter = token BWS"
      )]
    );
    assert_eq!((extracted.fences_read, extracted.fenced_read), (1, 1));
    assert_eq!((extracted.fences_skipped, extracted.fenced), (0, 0));

    let outside = "  /// RFC 9112 §7: `transfer-parameter = token BWS`\n";
    let read = quotations(outside);
    assert_eq!(read.productions.len(), 1, "the same line, backticked");
    assert_eq!((read.fences_read, read.fenced), (0, 0));
  }

  // The citation gate is the BACKTICKED path's, and a fenced production does
  // not inherit it: `fence_holds_grammar` is the evidence there, so requiring
  // a citation as well would be requiring one piece of evidence twice. Both
  // halves of the backticked gate are exercised here — a block naming several
  // and a block naming none — because a fenced production is admitted under
  // either. `uncited` must stay untouched, or the same line would be counted
  // as skipped and read at once.
  #[test]
  fn a_text_fenced_production_needs_no_citation() {
    let many = "  /// RFC 9110 and RFC 9112 both:\n  /// ```text\n  /// transfer-parameter = token BWS\n  /// ```\n";
    let extracted = quotations(many);
    assert_eq!(extracted.productions.len(), 1);
    assert_eq!(extracted.uncited, 0);

    let none =
      "  /// No RFC named here:\n  /// ```text\n  /// transfer-parameter = token BWS\n  /// ```\n";
    assert_eq!(quotations(none).productions.len(), 1);
  }

  // The false positive the info-string rule exists to avoid, and the one it
  // does not avoid on its own: a `text` fence may hold Rust shown for a
  // caller to copy — this workspace has two, and both lines below are one of
  // theirs — so `is_production` still decides line by line inside an admitted
  // fence. The match arm is here because the `=>` guard now keeps a code
  // sample from being GRADED, not merely from being counted.
  #[test]
  fn a_text_fence_of_rust_offers_nothing() {
    let rust = "  /// ```text\n  /// let hdrs: &[(&str, &[u8])] = &[(\"Host\", b\"x\")];\n  /// connection.finish_body(NO_TRAILERS, &mut out)?;\n  ///   other => unreachable!(),\n  /// ```\n";
    let extracted = quotations(rust);
    assert!(extracted.productions.is_empty());
    assert_eq!((extracted.fences_read, extracted.fenced_read), (1, 0));
    assert_eq!(extracted.fenced, 0, "read and declined, not left unreached");
  }

  // The boundary that REMAINS, and the reason the count outlived the
  // widening: a fence tagged anything else is still skipped whole, so grammar
  // transcribed under a tag this rule does not admit stays a printed number
  // rather than an absence.
  #[test]
  fn a_fence_tagged_otherwise_is_still_unreached() {
    let bare = "  /// ```\n  /// timeout = 30\n  /// ```\n";
    let extracted = quotations(bare);
    assert!(extracted.productions.is_empty());
    assert_eq!((extracted.fences_skipped, extracted.fenced), (1, 1));
    assert_eq!((extracted.fences_read, extracted.fenced_read), (0, 0));

    let tagged = "  /// ```abnf\n  /// timeout = 30\n  /// ```\n";
    assert_eq!(
      quotations(tagged).fenced,
      1,
      "no tag is admitted on a guess"
    );
  }

  // A `.md` fence follows the same rule, so the printed numbers are one rule
  // over both kinds of file rather than a `.rs`-only figure wearing a
  // workspace-wide label.
  #[test]
  fn a_text_fenced_production_in_markdown_is_read_too() {
    let source = "See RFC 9112 §7:\n\n```text\ntransfer-parameter = token BWS\n```\n";
    let extracted = markdown_quotations(source);
    assert_eq!(
      triples(&extracted.productions),
      vec![(
        4,
        "transfer-parameter = token BWS",
        "transfer-parameter = token BWS"
      )]
    );
    assert_eq!((extracted.fenced_read, extracted.fenced), (1, 0));

    let sh = "```sh\nPORT=8080 cargo run\n```\n";
    assert_eq!(
      markdown_quotations(sh).fenced,
      1,
      "a shell assignment fits the shape"
    );
  }

  // The `=>` half of `is_production`, at the level the count is printed: a
  // README fence full of Rust must contribute nothing, or the boundary this
  // number states would be overstated by the code samples beside it.
  #[test]
  fn a_markdown_fence_of_rust_counts_nothing() {
    let source = "```rust\nlet last = false;\nmatch outcome {\n  other => panic!(),\n}\n```\n";
    assert_eq!(markdown_quotations(source).fenced, 0);
  }

  // A block naming an RFC at all is what admits a production inside it: the
  // citation is the evidence that a bare `name =` is a grammar claim rather
  // than a Rust value, which is all the production gate reads it for.
  #[test]
  fn a_block_naming_one_rfc_is_cited() {
    let block = "RFC 6455 §9.1's extension-param = token [ \"=\" (token | quoted-string) ]";
    assert_eq!(super::cited_rfcs(block), vec![6455]);
  }

  // The same RFC named twice is still one spec, not two entries: `grade`
  // would otherwise grade against it twice, and a reader of a failure message
  // would meet one citation twice over.
  #[test]
  fn a_block_naming_the_same_rfc_twice_is_still_one() {
    let block = "RFC 6455 §9.1's grammar, restated at RFC 6455 §1.3 for the reader";
    assert_eq!(super::cited_rfcs(block), vec![6455]);
  }

  // Ruling 12: two DIFFERENT RFCs in one block are two attributions, KEPT.
  // Collapsing them to one `None` is what put 184 of this workspace's
  // quotations on the any-spec fallback, and the order is first-mention so a
  // reader of the failure message meets them as the author wrote them.
  #[test]
  fn a_block_naming_two_rfcs_keeps_both() {
    let block = "RFC 2616 §2.1's #rule, which RFC 9110 §5.6.1.2 restates";
    assert_eq!(super::cited_rfcs(block), vec![2616, 9110]);
  }

  // Prose that names no RFC at all makes no checkable claim either.
  #[test]
  fn a_block_naming_no_rfc_is_not_cited() {
    assert!(super::cited_rfcs("just an ordinary sentence about `last = false`").is_empty());
  }

  // `RFC ` with no digits behind it is prose, not a truncated citation — and
  // it must not swallow the real citation later in the same block.
  #[test]
  fn rfc_without_digits_is_not_a_citation() {
    assert!(super::cited_rfcs("the RFC says so").is_empty());
    assert_eq!(
      super::cited_rfcs("an RFC — say RFC 9110 — requires"),
      vec![9110]
    );
  }

  // The gate is applied to the WHOLE block, not the line, and what it asks
  // of the block is that it name SOME RFC. The middle case is the one that
  // moved: a block naming two used to withhold its productions, which made
  // the check grade fewer of them the more citations a comment correctly
  // carried. A block naming NONE still withholds, and not silently — it is
  // counted as skipped rather than dropped without a trace.
  #[test]
  fn a_production_survives_in_any_citing_block() {
    let cited = quotations("  /// RFC 6455 §9.1's `extension-param = token`\n");
    assert_eq!(
      triples(&cited.productions),
      vec![(1, "extension-param = token", "extension-param = token")]
    );
    assert_eq!(cited.uncited, 0);

    let several = quotations("  /// RFC 2616 and RFC 9110 both define `token = 1*tchar`\n");
    assert_eq!(
      triples(&several.productions),
      vec![(1, "token = 1*tchar", "token = 1*tchar")],
      "two citations are two attributions, not an absent one"
    );
    assert_eq!(several.uncited, 0);

    let uncited = quotations("  /// see `last = false` above\n");
    assert!(uncited.productions.is_empty());
    assert_eq!(uncited.uncited, 1);
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

  // The Markdown spelling of the same marker, read by its own function: a
  // `.md` file has no `//` syntax, so this is the only way it can reach the
  // mechanism `a_gate_exempt_marker_is_recognised_by_its_exact_span` pins for
  // `.rs`. Same property, same exactness — naming one span's text does not
  // touch a differently-spelled one.
  #[test]
  fn a_markdown_gate_exempt_marker_is_recognised_by_its_exact_span() {
    let source = "<!-- gate-exempt: q = 1 — a weight value in prose, not RFC 9110 grammar -->\n";
    let exempt = super::markdown_exempted_spans(source);
    assert!(exempt.contains("q = 1"));
    assert!(!exempt.contains("q = 2"));
  }

  // Two boundaries this bracketing adds beyond the `.rs` form's single one:
  // the em dash still ends the exemption text, and the closing `-->` must not
  // be swept in with it either — a span carrying the comment's own closing
  // delimiter could never match a production or quotation actually extracted
  // from the file.
  #[test]
  fn a_markdown_gate_exempt_marker_stops_at_the_em_dash_and_the_close() {
    let exempt = super::markdown_exempted_spans(
      "<!-- gate-exempt: answerable = false — a Rust flag, not grammar -->\n",
    );
    assert!(exempt.contains("answerable = false"));
    assert!(
      !exempt
        .iter()
        .any(|span| span.contains('—') || span.contains("-->"))
    );
  }

  // The property the brief calls out by name: naming ONE span in a marker
  // must not blanket-exempt a DIFFERENT production-shaped span sitting in the
  // same file. Both spans are real ones this task marks exempt in the `docs/`
  // corpus, so this is not a synthetic pair — it is the exact shape a marker
  // covering more than it names would silently get wrong.
  #[test]
  fn a_markdown_gate_exempt_marker_does_not_exempt_a_different_span() {
    let source = "<!-- gate-exempt: default-features = false — a Cargo manifest key -->\n";
    let exempt = super::markdown_exempted_spans(source);
    assert!(exempt.contains("default-features = false"));
    assert!(
      !exempt.contains("recv = Idle"),
      "naming one span must not blanket-exempt another"
    );
  }

  // `exempted_spans_for` is the one place the two spellings meet, and each
  // must stay confined to the file type it was made for: the HTML form is
  // inert in a `.rs` file and the `//` form is inert in a `.md` one, the same
  // "two syntaxes because two file types" split `spans_for` already draws for
  // extraction.
  #[test]
  fn exempted_spans_for_dispatches_by_extension() {
    let md = "<!-- gate-exempt: last = false — a state flag shown in prose -->\n";
    assert!(super::exempted_spans_for(Path::new("notes.md"), md).contains("last = false"));
    assert!(
      super::exempted_spans_for(Path::new("notes.rs"), md).is_empty(),
      "the HTML spelling must not be read in a .rs file"
    );

    let rs = "// gate-exempt: last = false — a state flag shown in prose\n";
    assert!(super::exempted_spans_for(Path::new("notes.rs"), rs).contains("last = false"));
    assert!(
      super::exempted_spans_for(Path::new("notes.md"), rs).is_empty(),
      "the `//` spelling must not be read in a .md file"
    );
  }

  /// A minimal, hand-built spec for testing `grade_production` directly,
  /// independent of anything the workspace's own comments happen to cite.
  fn test_spec(name: &str, text: &str) -> super::Spec {
    super::Spec {
      name: name.to_string(),
      text: text.to_string(),
      // The same relationship `load_specs` builds: one joined text, two
      // normalisations, differing only in the bracket rule.
      grammar: super::normalise_production(text),
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
    let mut checked = 0;
    assert!(
      super::grade_production("widget-param = token widget-value", &specs, &mut checked).is_none()
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
    let mut checked = 0;
    let graded = super::grade_production("gadget-param = token gadget-value", &specs, &mut checked);
    assert_eq!(graded.map(|spec| spec.name.as_str()), Some("rfc1"));
    assert_eq!(checked, 1);
  }

  // `[ … ]` means opposite things on the two paths, and grading a production
  // through the QUOTATION path's rule deleted part of the production from
  // both sides at once — so the comparison agreed with itself about a stub
  // and reported it verbatim. Thirteen of this workspace's graded productions
  // carry an optional group; two were stubbed down to a name and one word.
  #[test]
  fn a_production_keeps_its_optional_group() {
    let specs = [test_spec(
      "rfc1",
      "widget = token [ \"=\" widget-value ] CRLF",
    )];

    let mut checked = 0;
    assert!(
      super::grade_production(
        "widget = token [ \"=\" widget-value ] CRLF",
        &specs,
        &mut checked
      )
      .is_none()
    );

    let mut checked = 0;
    let corrupted = super::grade_production(
      "widget = token [ \"=\" widget-values ] CRLF",
      &specs,
      &mut checked,
    );
    assert_eq!(
      corrupted.map(|spec| spec.name.as_str()),
      Some("rfc1"),
      "a corruption INSIDE the optional group is what the old rule threw away"
    );
    assert_eq!(checked, 1);
  }

  // The quotation path's bracket rule is unchanged, and must stay so: the
  // RFCs' own prose carries inline `[RFC2616]` references that the comments
  // quoting them never spell.
  #[test]
  fn only_the_production_normalisation_keeps_brackets() {
    let text = "handled per HTTP [RFC2616] procedures";
    assert_eq!(super::normalise(text), "handled per HTTP procedures");
    assert_eq!(
      super::normalise_production(text),
      "handled per HTTP [RFC2616] procedures"
    );
  }

  // Below the three-word floor: not a checkable claim, so `checked` does not
  // move — this is what keeps a stray two-token span from inflating the
  // denominator.
  #[test]
  fn a_span_below_the_word_floor_is_not_counted() {
    let specs = [test_spec("rfc1", "x=y is mentioned in here somewhere")];
    let mut checked = 0;
    assert!(super::grade_production("x=y", &specs, &mut checked).is_none());
    assert_eq!(checked, 0);
  }

  // The accept side, and it is the whole of what keeps this rule usable: every
  // shape an RFC actually writes has to pass, or the gate reports the tree
  // instead of the defect. Each line below is a real production, and each
  // carries one character that a naive balance test gets wrong — the `;`
  // inside a quoted terminal, the backslash a terminal can hold, RFC 2046's
  // prose-val with parentheses in it, the prose-val holding a DQUOTE, and an
  // ABNF comment carrying an unbalanced quote and paren both.
  #[test]
  fn a_whole_rule_is_accepted_in_every_shape_the_rfcs_write() {
    for whole in [
      "parameters = *( OWS \";\" OWS [ parameter ] )",
      "transfer-coding = token *( OWS \";\" OWS transfer-parameter )",
      "quoted-pair = \"\\\" ( HTAB / SP / VCHAR / obs-text )",
      "media-range = ( \"*/*\" / ( type \"/\" \"*\" ) / ( type \"/\" subtype ) ) parameters",
      "token := 1*<any (US-ASCII) CHAR except SPACE, CTLs, or tspecials>",
      "tspecials :=  \"(\" / \")\" / \"<\" / \">\" / \"@\" / \",\" / \";\" / \":\" / \"\\\" / <\">",
      "DQUOTE = %x22 ; \" (Double Quote)",
      "Trailer =/ token",
      "obs-text = %x80-FF",
    ] {
      assert_eq!(super::rule_fault(whole), None, "{whole}");
    }
  }

  // The hole this closes, in the exact words the gate let through: RFC 9110
  // §10.1.4's rule with its closing ` )` dropped IS a substring of the spec,
  // so the comparison called it verbatim and meant it. Every other row is a
  // truncation the same walk catches, at the other end and in the middle.
  #[test]
  fn a_production_truncated_inside_a_group_is_not_a_whole_rule() {
    use super::RuleFault::{Empty, Mismatched, Unclosed, Unopened};

    for (broken, fault) in [
      (
        "transfer-coding = token *( OWS \";\" OWS transfer-parameter",
        Unclosed('('),
      ),
      (
        "expectation = token [ \"=\" ( token / quoted-string )",
        Unclosed('['),
      ),
      ("qdtext = <any TEXT", Unclosed('<')),
      ("chunk-ext-val = \"unterminated", Unclosed('"')),
      (
        "expectation = token \"=\" ( token / quoted-string ) parameters ]",
        Unopened(']'),
      ),
      (
        "parameters = *( OWS \";\" OWS [ parameter )",
        Mismatched(')', '['),
      ),
      ("parameters =", Empty),
      ("parameters = ; and nothing but a comment", Empty),
    ] {
      assert_eq!(super::rule_fault(broken), Some(fault), "{broken}");
    }
  }

  // An elision is the author saying the rule is not whole, and whole is the
  // only question this asks. The `Via` rule below is the one elided production
  // in this workspace; it balances, so it passes either way, and the second
  // row is what the rule is actually for — an elision that lands inside a
  // group, where refusing to answer is the difference between a gate and a
  // gate that invents failures.
  #[test]
  fn an_elided_production_is_not_asked_whether_it_is_whole() {
    assert_eq!(
      super::rule_fault("Via = #( received-protocol RWS received-by …)"),
      None
    );
    assert_eq!(super::rule_fault("Via = #( received-protocol …"), None);
    assert_eq!(super::rule_fault("Via = #( received-protocol ..."), None);
    assert_eq!(
      super::rule_fault("Via = #( received-protocol"),
      Some(super::RuleFault::Unclosed('(')),
      "without the mark the same fragment is a truncation"
    );
  }

  // The ruling this rule had to be shaped around: a broken production must
  // still LOOK like one. Keying admission on the right-hand side would make
  // the gate's own defect delete the item it should be reporting, so
  // `is_production` still says yes to every row above and `rule_fault` is
  // what says no.
  #[test]
  fn a_broken_production_is_still_admitted_as_a_candidate() {
    let truncated = "transfer-coding = token *( OWS \";\" OWS transfer-parameter";
    assert!(super::is_production(truncated));
    assert!(super::rule_fault(truncated).is_some());
  }

  // ABNF wraps, and a rule set the way the RFCs print it ends its first line
  // inside a group. The candidate keeps the LINE as its span, because that is
  // what the spec's own text must contain, and carries the joined rule for the
  // shape test — so a correct transcription of RFC 9110 §12.5.1 passes rather
  // than being reported as truncated.
  //
  // The fixture is one source line with escaped newlines for the reason
  // `a_text_fenced_production_is_read` gives: spelled across real lines it
  // would be a live `text` fence in this file.
  #[test]
  fn a_fenced_rule_wrapped_across_lines_is_judged_whole() {
    let wrapped = "  /// RFC 9110 §12.5.1:\n  /// ```text\n  /// media-range = ( \"*/*\"\n  ///                 / ( type \"/\" subtype )\n  ///               ) parameters\n  /// ```\n";
    let extracted = quotations(wrapped);
    assert_eq!(
      triples(&extracted.productions),
      vec![(
        3,
        "media-range = ( \"*/*\"",
        "media-range = ( \"*/*\" / ( type \"/\" subtype ) ) parameters"
      )]
    );
    assert_eq!(super::rule_fault(&extracted.productions[0].rule), None);
    assert_eq!(
      super::rule_fault(&extracted.productions[0].span),
      Some(super::RuleFault::Unclosed('(')),
      "the line alone is not a rule, which is why the join exists"
    );
  }

  // What ends a continuation, both ways round. A blank line is what separates
  // one rule from the next in every fence this workspace writes, and the next
  // production-shaped line starts its own candidate rather than joining the
  // one before it — without both, a rule would go on swallowing whatever
  // follows the grammar.
  #[test]
  fn a_continuation_ends_at_a_blank_line_and_at_the_next_rule() {
    let fence = "  /// ```text\n  /// mechanism := \"7bit\" /\n  ///              ietf-token\n  ///\n  /// prose about the two above\n  /// token := 1*<any CHAR>\n  ///             except tspecials>\n  /// ```\n";
    let extracted = quotations(fence);
    assert_eq!(
      triples(&extracted.productions),
      vec![
        (
          2,
          "mechanism := \"7bit\" /",
          "mechanism := \"7bit\" / ietf-token"
        ),
        (
          6,
          "token := 1*<any CHAR>",
          "token := 1*<any CHAR> except tspecials>"
        ),
      ],
      "the prose after the blank joined nothing"
    );
  }

  // The #75 class surviving inside the fix for #75, and the indent that ends
  // it. Both fixtures truncate RFC 9110 §12.5.1's `media-range` at its first
  // line — a prefix that IS a substring of the spec, so only `rule_fault` can
  // catch it — and then write the missing `)` on the next line. Set as a
  // continuation, under the rule, it joins and the truncation is hidden; set as
  // prose, back at the rule's own indent, it does not and the truncation is
  // reported.
  //
  // One source line with escaped newlines, for the reason
  // `a_text_fenced_production_is_read` gives.
  #[test]
  fn prose_after_a_truncated_fenced_rule_does_not_close_its_group() {
    let prose = "  /// ```text\n  /// media-range = ( \"*/*\"\n  /// and the group closes somewhere down here )\n  /// ```\n";
    let extracted = quotations(prose);
    assert_eq!(
      triples(&extracted.productions),
      vec![(2, "media-range = ( \"*/*\"", "media-range = ( \"*/*\"")],
      "prose at the rule's own indent joins nothing"
    );
    assert_eq!(
      super::rule_fault(&extracted.productions[0].rule),
      Some(super::RuleFault::Unclosed('(')),
      "which is what leaves the truncation visible"
    );

    let continued = "  /// ```text\n  /// media-range = ( \"*/*\"\n  ///               and the group closes somewhere down here )\n  /// ```\n";
    let extracted = quotations(continued);
    assert_eq!(
      extracted.productions[0].rule,
      "media-range = ( \"*/*\" and the group closes somewhere down here )",
      "indented under the rule it is a continuation, and this is what that costs"
    );
  }

  // `=/` is RFC 5234's incremental-alternative operator, so its `/` is part of
  // the operator; a `/` behind a space is the rule's own alternation. Getting
  // that wrong would read the first row below as a right-hand side beginning
  // with an alternation bar and nothing in front of it.
  #[test]
  fn the_incremental_alternative_slash_belongs_to_the_operator() {
    assert_eq!(super::right_hand_side("Trailer =/ token"), Some(" token"));
    assert_eq!(
      super::right_hand_side("Trailer = / token"),
      Some(" / token")
    );
    assert_eq!(
      super::right_hand_side("boundary := 0*69<bchars>"),
      Some(" 0*69<bchars>")
    );
    assert_eq!(super::right_hand_side("need == out.len()"), None);
    assert_eq!(super::right_hand_side("other => panic!()"), None);
  }

  // The three answers `grade` used to collapse into one `None`. A green run
  // must not look the same as a run that could not check anything: a block
  // citing RFC 9782 (never loaded — it is not in `FETCHED`) is a checkable
  // claim this run could not honour, and that must surface rather than vanish.
  // Empty `specs` also means the anchor can never match, so this pins Row 1
  // of Ruling 9's table (unanchored + cited-but-unloaded => `Unloaded`).
  #[test]
  fn an_unloaded_citation_grades_as_unloaded() {
    let specs: Vec<super::Spec> = Vec::new();
    let mut checked = 0;
    let mut unattributable = 0;
    let mut narrow = 0;
    let mut fallback = 0;
    let graded = super::grade(
      "the identifier is a valid URI reference and is compared",
      &[9782],
      &specs,
      &mut checked,
      &mut unattributable,
      &mut narrow,
      &mut fallback,
    );
    assert!(matches!(graded, Some(super::Grade::Unloaded(ref n)) if n == &[9782]));
    assert_eq!(
      checked, 1,
      "an unloaded citation still counts as one this check governs"
    );
    assert_eq!(unattributable, 0);
    assert_eq!(
      (narrow, fallback),
      (0, 0),
      "Unloaded is graded against no spec at all — neither path"
    );
  }

  // The hole grading-by-citation closes: `rfc1` holds these exact words, but
  // the block cites `rfc2`, which does not — so this must FAIL, not silently
  // pass the way the pre-citation any-spec match did (a sentence attributed to
  // RFC 9110 passing because RFC 9112 happened to contain it too). The
  // attribution is read, not just present. `rfc1` is what ANCHORS this span
  // (Q1, yes); `rfc2` is what the block CITES, and Ruling 9 makes citation
  // answer only Q2 once Q1 is already yes — this pins Row 3 of that table.
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
    let mut unattributable = 0;
    let mut narrow = 0;
    let mut fallback = 0;
    let graded = super::grade(
      "the widget registry must reject a duplicate identifier",
      &[2],
      &specs,
      &mut checked,
      &mut unattributable,
      &mut narrow,
      &mut fallback,
    );
    // `Foreign`, not `Reworded`: `rfc2` does not even share this span's
    // opening, so there is no offset in it to show the reader. Ruling 12
    // splits the two — `Reworded` is for a span that begins as a cited spec
    // and then drifts, and the test below covers that one.
    let Some(super::Grade::Foreign { cited, begins_as }) = graded else {
      panic!("a quotation attributed to the wrong loaded spec must fail");
    };
    assert_eq!(cited, vec![2]);
    assert_eq!(begins_as.name, "rfc1");
    assert_eq!(checked, 1);
    assert_eq!(unattributable, 0);
    assert_eq!(
      (narrow, fallback),
      (1, 0),
      "graded against the cited spec specifically (rfc2), not any anchored spec"
    );
  }

  // The other failure the cited-specs path reports, and the one `Foreign` is
  // kept apart from: the span BEGINS as a spec the block names and then stops
  // being it. Here the words drifted, that spec's own text at the anchor is
  // the fix, and naming it is the useful answer rather than a misleading one.
  #[test]
  fn a_quotation_that_drifts_from_its_cited_spec_is_reworded() {
    let specs = [test_spec(
      "rfc1",
      "the widget registry must reject a duplicate identity token",
    )];
    let mut checked = 0;
    let mut unattributable = 0;
    let mut narrow = 0;
    let mut fallback = 0;
    let graded = super::grade(
      "the widget registry must reject a duplicate identifier",
      &[1],
      &specs,
      &mut checked,
      &mut unattributable,
      &mut narrow,
      &mut fallback,
    );
    assert!(
      matches!(graded, Some(super::Grade::Reworded(spec, ref actual))
        if spec.name == "rfc1" && actual.starts_with("the widget registry"))
    );
    assert_eq!((narrow, fallback), (1, 0));
  }

  // Ruling 9, Row 2: a prose-sized span that does not anchor to ANY loaded
  // spec is not graded — even though its block cites one, and even though
  // that cited spec IS loaded. This is the case the first version of this
  // check got wrong: letting the citation alone decide "is this a quotation"
  // graded the author's own rhetorical prose against whatever the block
  // happened to cite nearby. Not a failure, but not silent either.
  #[test]
  fn an_unanchored_span_in_a_cited_block_is_not_graded() {
    let specs = [test_spec(
      "rfc1",
      "completely unrelated spec text that shares no opening",
    )];
    let mut checked = 0;
    let mut unattributable = 0;
    let mut narrow = 0;
    let mut fallback = 0;
    let graded = super::grade(
      "did this head arm this connection and answer truthfully",
      &[1],
      &specs,
      &mut checked,
      &mut unattributable,
      &mut narrow,
      &mut fallback,
    );
    assert!(
      graded.is_none(),
      "an unanchored span must not be graded, even in a cited block"
    );
    assert_eq!(checked, 0, "not graded means not counted as checked");
    assert_eq!(unattributable, 1, "but it is not silent either");
    assert_eq!((narrow, fallback), (0, 0), "not graded means neither path");
  }

  // Ruling 10a: an unanchored span in a block citing NOTHING is a different
  // fact from one in a block citing a loaded spec, and gets a different
  // answer — the original, silent `None`. Nobody had reason to expect a
  // quotation here at all, so unlike the test above, this one is not counted
  // anywhere: conflating "not my business" with "my business and I could not
  // do it" would blur exactly the distinction `unattributable` exists to
  // draw.
  #[test]
  fn an_unanchored_uncited_span_is_silently_not_this_checks_business() {
    let specs = [test_spec(
      "rfc1",
      "completely unrelated spec text that shares no opening",
    )];
    let mut checked = 0;
    let mut unattributable = 0;
    let mut narrow = 0;
    let mut fallback = 0;
    let graded = super::grade(
      "some sentence in quotes that matches nothing loaded here at all",
      &[],
      &specs,
      &mut checked,
      &mut unattributable,
      &mut narrow,
      &mut fallback,
    );
    assert!(graded.is_none());
    assert_eq!(checked, 0);
    assert_eq!(
      unattributable, 0,
      "cites nothing: never a candidate, not even counted in the backlog"
    );
    assert_eq!((narrow, fallback), (0, 0));
  }

  // Ruling 9, Row 4: a span that DOES anchor, in a block citing a spec this
  // run has not loaded, falls back to the pre-existing any-spec anchored
  // behaviour rather than reporting `Unloaded` — the anchor already found
  // something checkable, so "unloaded" would be the wrong answer (it isn't
  // that nothing could be checked; the citation just isn't the useful part
  // here). Distinguishes this from `an_unloaded_citation_grades_as_unloaded`,
  // where the anchor could not match anything because `specs` was empty.
  #[test]
  fn a_citation_to_an_unloaded_spec_falls_back_to_the_anchor_when_anchored() {
    let specs = [test_spec(
      "rfc1",
      "the widget registry must reject a duplicate identifier",
    )];
    let mut checked = 0;
    let mut unattributable = 0;
    let mut narrow = 0;
    let mut fallback = 0;
    let graded = super::grade(
      "the widget registry must reject a duplicate identifier",
      &[9782],
      &specs,
      &mut checked,
      &mut unattributable,
      &mut narrow,
      &mut fallback,
    );
    assert!(
      graded.is_none(),
      "verbatim in the anchored spec, so it passes via the fallback"
    );
    assert_eq!(checked, 1, "the anchored fallback still counts it");
    assert_eq!(unattributable, 0);
    assert_eq!(
      (narrow, fallback),
      (0, 1),
      "the cited spec (9782) was never loaded, so this counts as fallback, not narrow"
    );
  }

  // Ruling 12, the case that moved: a block naming TWO RFCs is graded
  // against BOTH, so a quotation verbatim in either one passes through
  // `narrow`. This test is the inverse of the one it replaced, which pinned
  // the old answer — that the same span fell through to the any-spec
  // fallback because the block also named something else. rfc2 is deliberately
  // the SECOND citation and rfc1 the first: a widening that picked one of the
  // several (first-mentioned, nearest-by-position) would grade this against
  // rfc1 and report a failure on a quotation that is exactly right, which is
  // the measured reason those two were rejected.
  #[test]
  fn a_block_naming_two_rfcs_is_graded_against_both() {
    let specs = [
      test_spec(
        "rfc1",
        "an unrelated spec discussing something else entirely",
      ),
      test_spec(
        "rfc2",
        "the widget registry must reject a duplicate identifier",
      ),
    ];
    let mut checked = 0;
    let mut unattributable = 0;
    let mut narrow = 0;
    let mut fallback = 0;
    let graded = super::grade(
      "the widget registry must reject a duplicate identifier",
      &[1, 2],
      &specs,
      &mut checked,
      &mut unattributable,
      &mut narrow,
      &mut fallback,
    );
    assert!(
      graded.is_none(),
      "verbatim in rfc2, which the block names: a quotation the block accounts for"
    );
    assert_eq!(checked, 1);
    assert_eq!(
      (narrow, fallback),
      (1, 0),
      "graded against the specs the block names, not against any loaded spec"
    );
  }

  // The other half of Ruling 12, and the case the any-spec fallback was
  // hiding: the span is in NONE of the specs its block names and does not
  // begin as any of them either — it begins as rfc3, which the block never
  // names. `Foreign` rather than `Reworded`, and it must carry BOTH sides:
  // the repair is either fixing the words or naming rfc3, and nothing here
  // can tell which, so the message must not imply one. Reporting it as
  // `Reworded` against rfc1 would print rfc1's text at an offset the span
  // does not have and invite the one repair that is always wrong.
  #[test]
  fn a_quotation_in_none_of_its_blocks_specs_is_foreign() {
    let specs = [
      test_spec("rfc1", "an unrelated spec discussing something else"),
      test_spec("rfc2", "a second unrelated spec, also discussing something"),
      test_spec(
        "rfc3",
        "the widget registry must reject a duplicate identifier",
      ),
    ];
    let mut checked = 0;
    let mut unattributable = 0;
    let mut narrow = 0;
    let mut fallback = 0;
    let graded = super::grade(
      "the widget registry must reject a duplicate identifier",
      &[1, 2],
      &specs,
      &mut checked,
      &mut unattributable,
      &mut narrow,
      &mut fallback,
    );
    let Some(super::Grade::Foreign { cited, begins_as }) = graded else {
      panic!("expected Foreign, got something else");
    };
    assert_eq!(cited, vec![1, 2], "the message names what the block cited");
    assert_eq!(
      begins_as.name, "rfc3",
      "and the spec it actually begins as, which the block never named"
    );
    assert_eq!(checked, 1);
    assert_eq!(
      (narrow, fallback),
      (1, 0),
      "this is the cited-specs path reporting, not the fallback declining"
    );
  }

  // The fallback's condition is that no NAMED spec was loaded — not that the
  // block named nothing. A block naming several, none of them loaded, still
  // has nothing to narrow with, so it takes the any-spec anchored behaviour
  // exactly as an uncited block does.
  #[test]
  fn a_block_naming_only_unloaded_specs_still_falls_back() {
    let specs = [test_spec(
      "rfc1",
      "the widget registry must reject a duplicate identifier",
    )];
    let mut checked = 0;
    let mut unattributable = 0;
    let mut narrow = 0;
    let mut fallback = 0;
    let graded = super::grade(
      "the widget registry must reject a duplicate identifier",
      &[9782, 9783],
      &specs,
      &mut checked,
      &mut unattributable,
      &mut narrow,
      &mut fallback,
    );
    assert!(graded.is_none(), "verbatim in the anchored spec");
    assert_eq!((narrow, fallback), (0, 1));
  }

  // ==== the masking unit ====

  // The defect, demonstrated: a code span wrapped across two comment lines
  // holds ONE `"`, the line unit meets no closing backtick and emits the rest
  // of the line raw, and `quoted_spans` pairs that leaked quote with the
  // author's opening one. The real quotation's closing mark is then an opener
  // with nothing to close on, so the quotation is not extracted AT ALL — not
  // mis-graded, not reported, absent.
  #[test]
  fn a_code_span_wrapped_across_lines_does_not_leak_its_quotes() {
    let source = concat!(
      "/// RFC 9110 §5.6.1.2: a member such as `a=\"x,\n",
      "/// y`. It says: \"Empty elements do not contribute to the count of\n",
      "/// elements present.\"\n",
    );

    assert_eq!(
      spans_under(source, mask_paragraph),
      ["Empty elements do not contribute to the count of elements present."],
      "the span is one code span, so the quotation behind it is the block's only one"
    );
    assert_eq!(
      spans_under(source, mask_each_line),
      ["x, y`. It says: "],
      "the line unit pairs the leaked quote with the quotation's opening mark"
    );
  }

  // …and why nothing found out. The false span the leak produces is below both
  // of `grade`'s floors, so `grade` returns the same silent `None` it returns
  // for a field value — it is not counted untriaged, nothing is printed, and
  // the run's numbers do not move. That is the escape #75 closed on the ABNF
  // path, reached through the quotation one.
  #[test]
  fn a_leaked_quote_can_take_a_quotation_out_of_the_gate_without_a_trace() {
    let source = concat!(
      "/// RFC 9110 §5.6.1.2: a member such as `a=\"x,\n",
      "/// y`. It says: \"Empty elements do not contribute to the count of\n",
      "/// elements present.\"\n",
    );
    let path = Path::new("demonstration.rs");

    assert!(
      graded_spans(path, source, mask_each_line).is_empty(),
      "the false span is 4 words and 15 characters: `grade` returns before it counts anything"
    );
    let graded = graded_spans(path, source, mask_paragraph);
    assert_eq!(graded.len(), 1, "{graded:?}");
    assert_eq!(
      graded[0].1,
      "Empty elements do not contribute to the count of elements present."
    );
  }

  // The differential below reports zero over this workspace, and a detector
  // that cannot fail reports zero too. This is the same helper on a source
  // that DOES leak, so the zero is a measurement rather than a property of
  // the helper.
  #[test]
  fn the_differential_reports_a_leak_it_is_given() {
    let source = concat!(
      "/// RFC 9110 §5.6.1.2: a member such as `a=\"x,\n",
      "/// y`. It says: \"Empty elements do not contribute to the count of\n",
      "/// elements present.\"\n",
    );
    let found = masking_disagreements(Path::new("demonstration.rs"), source);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].2, "paragraph unit only");
    assert_eq!(
      found[0].1,
      "Empty elements do not contribute to the count of elements present."
    );
  }

  // The measurement the fix shipped with, as a check rather than a sentence:
  // over every file this command reads, the unit that replaced the per-line
  // one changes no span large enough to be graded. Written down it decays the
  // moment somebody edits a comment; run here it cannot.
  //
  // A disagreement is not automatically a defect — the paragraph unit is the
  // right answer and a comment may legitimately become the first in this
  // workspace to wrap a code span around a quote. It is a REPORT: read the
  // block, satisfy yourself the paragraph unit's answer is the one you want,
  // and record it here. What it refuses is the same change arriving unread.
  //
  // Where it does NOT run: `ci.yml` carries `paths-ignore: '**.md'`, so a pull
  // request touching only Markdown does not reach `cargo test -p xtask`. The
  // gate itself still runs on every such request — `docs.yml` has no such
  // filter, for the reason its own comment gives — so nothing escapes the
  // check; what waits for the next non-Markdown commit is this differential's
  // notice about it.
  #[test]
  fn the_two_masking_units_agree_on_every_graded_span_in_this_workspace() {
    let sources = workspace_sources();
    let mut found = Vec::new();
    let mut graded = 0usize;
    for path in &sources {
      let text =
        std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
      graded += graded_spans(path, &text, mask_paragraph).len();
      for (line, span, which) in masking_disagreements(path, &text) {
        found.push(format!("{}:{line}: {which}: {span:?}", path.display()));
      }
    }
    assert!(found.is_empty(), "{found:#?}");

    // A walk that read nothing agrees with itself about nothing, and would
    // pass the assertion above without having compared a single comment.
    assert!(
      sources.len() >= 100,
      "the walk found {} source files",
      sources.len()
    );
    assert!(graded >= 500, "the walk found {graded} graded-size spans");
  }

  // Why the unit is the paragraph and not the whole block, which is the other
  // way to close the leak. A code span may not cross a blank line, so pairing
  // backticks over a block pairs two paragraphs' unrelated strays and masks
  // everything between them — the quotation included. Nothing in this
  // workspace spells that today (both units read its 10 000-odd blocks the
  // same way), which is exactly why the boundary is held by a constructed
  // case rather than by the corpus.
  #[test]
  fn a_stray_backtick_pairs_no_further_than_its_own_paragraph() {
    let first = [(1usize, "RFC 9110 §5.6.1.2 writes a ` in prose")];
    let second = [(
      3usize,
      "It says: \"Empty elements do not contribute to the count of elements present.\" and a ` here",
    )];
    let block: Vec<(usize, &str)> = first.iter().chain(second.iter()).copied().collect();

    let by_paragraph = [mask_paragraph(&first), mask_paragraph(&second)].concat();
    assert!(
      by_paragraph.iter().all(|line| !line.contains(super::MASK)),
      "an opening run with no closer in its own paragraph is literal text: {by_paragraph:?}"
    );
    assert_eq!(
      quoted_spans_of(&by_paragraph),
      ["Empty elements do not contribute to the count of elements present."]
    );

    let by_block = mask_paragraph(&block);
    assert!(
      by_block[0].contains(super::MASK),
      "the whole-block unit pairs the two paragraphs' strays: {by_block:?}"
    );
    assert!(
      quoted_spans_of(&by_block).is_empty(),
      "and swallows the quotation between them: {by_block:?}"
    );
  }

  /// The spans `quotations` finds under a named masking unit — [`spans`] with
  /// the unit made visible, for the two tests that need to see both answers.
  fn spans_under(source: &str, mask: Masker) -> Vec<String> {
    quotations_masked(source, mask)
      .quoted
      .into_iter()
      .map(|(_, span, _)| span)
      .collect()
  }

  // ==== blocks whose marks do not pair ====

  /// One block's unpaired report flattened to what a test is about: where the
  /// block starts, where the pairing ran out, and how many marks it held.
  fn unpaired_of(source: &str) -> Vec<(usize, usize, usize)> {
    quotations(source)
      .unpaired
      .into_iter()
      .map(|odd| (odd.at, odd.mark, odd.quotes))
      .collect()
  }

  // A leftover mark is reported with BOTH ends of the run — the line the block
  // starts on and the line the pairing ran out on — because the mark the
  // author got wrong is somewhere between them and nothing here can say which
  // it is. The count is the third thing a reader needs: two marks are a
  // quotation, three are a quotation and a mistake.
  #[test]
  fn a_block_whose_marks_do_not_pair_is_reported() {
    let source = concat!(
      "/// RFC 9110 §5.6.1.2: \"Empty elements do not contribute to the count of\n",
      "/// elements present.\" And a lone \" mark after it.\n",
    );
    assert_eq!(unpaired_of(source), [(1, 2, 3)]);
  }

  // Balanced blocks are not reported, and neither is a mark inside a code
  // span: the count is read AFTER masking, which is the text `quoted_spans`
  // reads. Counting before it would report every comment that names a quote
  // character, which is most of this file.
  #[test]
  fn a_balanced_block_and_a_masked_mark_are_not_reported() {
    let balanced = "/// RFC 9110 §5.6.1.2: \"Empty elements do not contribute.\"\n";
    assert!(unpaired_of(balanced).is_empty(), "{balanced}");

    let masked = concat!(
      "/// RFC 9110 §5.6.1.2: \"Empty elements do not contribute to the count of\n",
      "/// elements present.\" The mark itself is written `\"` in prose.\n",
    );
    assert!(unpaired_of(masked).is_empty(), "{masked}");

    // …and one mark inside a code span that WRAPS is masked too, which is the
    // whole reason the two halves of this module ship together: before the
    // paragraph unit that mark leaked, and a leaked mark is an odd block.
    let wrapped = concat!(
      "/// RFC 9110 §5.6.1.2: an element such as `x, \"y,\n",
      "/// z` and nothing else.\n",
    );
    assert!(unpaired_of(wrapped).is_empty(), "{wrapped}");
  }

  // The shape `UNPAIRED` records for `http-semantics/src/auth/mod.rs`, pinned
  // rather than asserted in prose: a `//` line is a comment like any other, so
  // a marker written directly under a `//!` doc comment does not start a block
  // of its own — it JOINS the doc comment's, and its lone mark is the doc
  // comment's to pair. The blank line is what separates them, which is why the
  // two files that got this right left one.
  #[test]
  fn a_line_comment_under_a_doc_comment_joins_its_block() {
    let joined = concat!(
      "//! RFC 9110 §5.6.1.2: \"Empty elements do not contribute.\"\n",
      "// gate-exempt: trap=\"open — a value whose string never closes\n",
    );
    assert_eq!(
      unpaired_of(joined),
      [(1, 2, 3)],
      "the marker's lone mark is counted in the module doc's own block"
    );

    let separated = concat!(
      "//! RFC 9110 §5.6.1.2: \"Empty elements do not contribute.\"\n",
      "\n",
      "// gate-exempt: trap=\"open — a value whose string never closes\n",
    );
    assert_eq!(
      unpaired_of(separated),
      [(3, 3, 1)],
      "with a blank line between them the marker is its own block, and the doc comment pairs"
    );
  }

  // `UNPAIRED`'s gate, in every direction it has one — the same four cases
  // `UNTRIAGED`'s has, because they run on one rule (`drift`) and differ only
  // in what they tell the reader to do about it.
  #[test]
  fn the_unpaired_table_is_held_in_both_directions() {
    let table = &[("a.rs", 2), ("b.rs", 1)];

    assert!(super::unpaired_drift(&counts(&[("a.rs", 2), ("b.rs", 1)]), table, false).is_empty());

    let grown = super::unpaired_drift(&counts(&[("a.rs", 3), ("b.rs", 1)]), table, false);
    assert_eq!(grown.len(), 1, "{grown:?}");
    assert_eq!(grown[0].0, "a.rs");
    assert!(grown[0].1.contains("`UNPAIRED` records 2"));
    assert!(grown[0].1.contains("Balance the marks"));

    let shrunk = super::unpaired_drift(&counts(&[("a.rs", 1), ("b.rs", 1)]), table, false);
    assert_eq!(shrunk.len(), 1, "{shrunk:?}");
    assert!(shrunk[0].1.contains("Lower the number here"));

    let stale = super::unpaired_drift(&counts(&[("a.rs", 2)]), table, false);
    assert_eq!(stale.len(), 1, "{stale:?}");
    assert_eq!(stale[0].0, "b.rs");
    assert!(stale[0].1.contains("the whole entry is stale"));

    let unlisted = super::unpaired_drift(
      &counts(&[("a.rs", 2), ("b.rs", 1), ("c.md", 1)]),
      table,
      false,
    );
    assert_eq!(unlisted.len(), 1, "{unlisted:?}");
    assert!(unlisted[0].1.contains("not in `UNPAIRED`"));
    assert!(
      super::unpaired_drift(
        &counts(&[("a.rs", 2), ("b.rs", 1), ("c.md", 1)]),
        table,
        true
      )
      .is_empty(),
      "the unlisted half is relaxed on an ignored-tree run, exactly as `UNTRIAGED`'s is"
    );
  }

  /// The quoted spans of masked lines once they are joined into a block, which
  /// is the one thing the masking unit is chosen to get right.
  fn quoted_spans_of(lines: &[String]) -> Vec<String> {
    let block = lines.join(" ");
    super::quoted_spans(&block)
      .into_iter()
      .map(|(_, span)| span.to_string())
      .collect()
  }
}
