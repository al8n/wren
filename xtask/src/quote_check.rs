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
//! An anchored, prose-sized span must then appear in full and case-sensitively
//! in one of the specs it anchored in — several may hold the same opening, and
//! a verbatim match in any of them clears it, because a quotation names one
//! spec and the tool is not told which. Failing that, the anchor tells the tool
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
  fs,
  path::{Path, PathBuf},
  process::Command,
};

type Error = Box<dyn std::error::Error>;

/// The default, gitignored cache directory, relative to the workspace root.
pub const DEFAULT_DIR: &str = ".rfc-cache";

/// The specs `--fetch` downloads: the ones this workspace's comments cite.
const FETCHED: &[u32] = &[6455, 7692, 8441, 9110, 9112, 9220];

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

/// What went wrong with one quoted span.
enum Grade<'a> {
  /// The spec has these words, in other cases.
  Recased(&'a Spec, String),
  /// The spec begins this way and then says something else.
  Reworded(&'a Spec, String),
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
  for source in &sources {
    let text = fs::read_to_string(source)?;
    let shown = source.strip_prefix(&root).unwrap_or(source).display();
    let quoted_here = if source.extension().and_then(|ext| ext.to_str()) == Some("md") {
      markdown_quotations(&text)
    } else {
      quotations(&text)
    };
    for (line, span) in quoted_here {
      for segment in span.split(['…']).flat_map(|part| part.split("...")) {
        let quoted = normalise(segment);
        let Some(grade) = grade(&quoted, &specs, &mut checked) else {
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
        }
      }
    }
  }

  let specs_shown = specs
    .iter()
    .map(|spec| spec.name.as_str())
    .collect::<Vec<_>>()
    .join(", ");
  if failures == 0 {
    println!("quote-check: {checked} quotations verbatim against {specs_shown}");
    if !include_ignored && skipped > 0 {
      println!(
        "quote-check: {skipped} git-ignored director{} not scanned — quotations \
         there are UNCHECKED (pass --include-ignored to scan them)",
        if skipped == 1 { "y" } else { "ies" }
      );
    }
    return Ok(());
  }
  Err(format!("{failures} of {checked} quotations are not the spec's own characters").into())
}

/// Grades one normalised span, counting it when it is one this check governs.
fn grade<'a>(quoted: &str, specs: &'a [Spec], checked: &mut usize) -> Option<Grade<'a>> {
  if quoted.split_whitespace().count() < MIN_WORDS || quoted.chars().count() < MIN_CHARS {
    return None;
  }
  let head = anchor(quoted);
  let anchored: Vec<&Spec> = specs
    .iter()
    .filter(|spec| spec.lower.contains(&head))
    .collect();
  if anchored.is_empty() {
    // Not a quotation of any supplied spec: an internal quotation, a quoted
    // identifier, or a spec this run was not given. Not this check's business.
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

/// Every quoted span in `source`'s comments, with the line its opening quote is
/// on — a comment that follows code on the same line included.
///
/// Consecutive comment lines are one block and are joined before the quotes are
/// paired, so a quotation wrapped across lines is one span rather than several.
fn quotations(source: &str) -> Vec<(usize, String)> {
  let mut out = Vec::new();
  let mut block = String::new();
  // (byte offset into `block`, source line) for the start of each joined line.
  let mut marks: Vec<(usize, usize)> = Vec::new();
  let mut fenced = false;

  let mut flush = |block: &mut String, marks: &mut Vec<(usize, usize)>| {
    for (at, span) in quoted_spans(block) {
      let line = marks
        .iter()
        .take_while(|(offset, _)| *offset <= at)
        .last()
        .map_or(0, |(_, line)| *line);
      out.push((line, span.to_string()));
    }
    block.clear();
    marks.clear();
  };

  for (index, raw) in source.lines().enumerate() {
    let Some((body, own_line)) = comment_body(raw) else {
      fenced = false;
      flush(&mut block, &mut marks);
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
    block.push_str(&mask_code_spans(body));
  }
  flush(&mut block, &mut marks);
  out
}

/// Every quotation in a Markdown file.
///
/// A `.md` file is comment text throughout, so there is no comment prefix to
/// find and no code half to discard — but fenced blocks are still skipped, for
/// the same reason they are in a doc comment: a fence holds code, and a
/// quotation mark inside code is not opening a quotation.
fn markdown_quotations(source: &str) -> Vec<(usize, String)> {
  let mut out = Vec::new();
  let mut block = String::new();
  let mut marks: Vec<(usize, usize)> = Vec::new();
  let mut fenced = false;

  let mut flush = |block: &mut String, marks: &mut Vec<(usize, usize)>| {
    for (at, span) in quoted_spans(block) {
      let line = marks
        .iter()
        .take_while(|(offset, _)| *offset <= at)
        .last()
        .map_or(0, |(_, line)| *line);
      out.push((line, span.to_string()));
    }
    block.clear();
    marks.clear();
  };

  for (index, raw) in source.lines().enumerate() {
    if raw.trim_start().starts_with("```") {
      fenced = !fenced;
      flush(&mut block, &mut marks);
      continue;
    }
    if fenced {
      continue;
    }
    if raw.trim().is_empty() {
      flush(&mut block, &mut marks);
      continue;
    }
    if !block.is_empty() {
      block.push(' ');
    }
    marks.push((block.len(), index + 1));
    block.push_str(&mask_code_spans(raw));
  }
  flush(&mut block, &mut marks);
  out
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
/// so the exit code is the answer and no output needs parsing.
fn is_ignored(path: &Path) -> Result<bool, Error> {
  let status = Command::new("git")
    .args(["check-ignore", "--quiet"])
    .arg(path)
    .status()
    .map_err(|err| format!("could not run git check-ignore: {err}"))?;
  Ok(status.success())
}

#[cfg(test)]
mod tests {
  use super::{markdown_quotations, quotations};

  fn spans(source: &str) -> Vec<String> {
    quotations(source).into_iter().map(|(_, s)| s).collect()
  }

  // `markdown_quotations` mirrors `spans` above: same shape, different source
  // function, because a `.md` file has no comment prefix to key off of.
  fn markdown_spans(source: &str) -> Vec<String> {
    markdown_quotations(source)
      .into_iter()
      .map(|(_, s)| s)
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
}
