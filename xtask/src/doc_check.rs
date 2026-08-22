//! Checks over the claims this workspace's documentation makes.
//!
//! `quote-check`'s sibling, and split from it at the toolchain seam rather than
//! by subject: one of these three needs rustdoc's JSON output, which is
//! nightly-only, and the other two are source scanning that any toolchain can
//! do. Running the two it can and SAYING it skipped the third is this crate's
//! rule applied to the command itself — a check that cannot examine something
//! must say so by name.
use crate::Error;
use std::{
  collections::{HashMap, HashSet},
  env, fs,
  path::{Path, PathBuf},
  process::Command,
};

/// What one run examined, could not examine, and found.
#[derive(Clone, Default)]
pub struct Report {
  lines: Vec<String>,
  skipped: Vec<String>,
  failures: Vec<String>,
}

impl Report {
  pub fn new() -> Self {
    Self::default()
  }

  // `checked`, `skip`, and `fail` are this Report's whole recording surface.
  // `continuity` and `verdicts` (below) between them call all three —
  // `checked` and `fail` from either, `skip` only from `continuity`, on a
  // toolchain that lacks nightly rustdoc's JSON output — so none of them
  // needs a dead-code allow now that this module wires them in.

  /// Records what one check examined — its denominator.
  pub fn checked(&mut self, line: impl Into<String>) {
    self.lines.push(line.into());
  }

  /// Records a check that did not run, and why.
  pub fn skip(&mut self, check: &str, why: &str) {
    self.skipped.push(format!("{check}: SKIPPED ({why})"));
  }

  /// Records a violation found by the check that is running.
  pub fn fail(&mut self, what: impl Into<String>) {
    self.failures.push(what.into());
  }

  /// Prints the run and decides it.
  ///
  /// A skip is a printed boundary by default and an error under `require_all`.
  /// CI passes `require_all`, so the nightly-only check cannot be quietly lost
  /// by an edit to the workflow that runs it.
  pub fn finish(self, require_all: bool) -> Result<(), Error> {
    for line in &self.lines {
      println!("doc-check: {line}");
    }
    for line in &self.skipped {
      println!("doc-check: {line}");
    }
    for failure in &self.failures {
      println!("{failure}");
    }
    if !self.failures.is_empty() {
      return Err(format!("doc-check: {} failures", self.failures.len()).into());
    }
    if require_all && !self.skipped.is_empty() {
      return Err(
        format!(
          "doc-check: {} check(s) skipped under --require-all",
          self.skipped.len()
        )
        .into(),
      );
    }
    Ok(())
  }
}

/// Runs every documentation check.
pub fn run(require_all: bool, bless: bool) -> Result<(), Error> {
  let mut report = Report::new();
  let root = crate::workspace_root()?;
  continuity(&root, bless, &mut report)?;
  verdicts(&root, &mut report)?;
  callees(&root, &mut report)?;
  report.finish(require_all)
}

/// Fails when a `http1-proto` item that had a doc comment no longer does.
///
/// Compares the currently-documented set against a committed snapshot rather
/// than requiring every item to be documented: `http1-proto` has a real
/// backlog of undocumented items today, so "every item must be documented"
/// is not an available rule. A delta is — "no item that had a doc has lost
/// one" — and the snapshot puts the loss in the diff, where a reviewer sees
/// it without running anything.
///
/// What this does NOT detect: a doc comment that got shorter, wrong, or had
/// a paragraph cut out of it while at least one line survives. The
/// comparison is presence/absence of `docs` on an item, not a text diff —
/// proven while building this check, not assumed: deleting one line out of a
/// multi-line doc comment left `docs` non-empty and produced no failure, and
/// only removing an item's entire doc block did. A doc that is damaged
/// rather than gone is invisible here.
fn continuity(root: &Path, bless: bool, report: &mut Report) -> Result<(), Error> {
  let path = root.join("xtask/snapshots/http1-proto-documented.txt");
  let Some(current) = documented_items(root, "http1-proto")? else {
    report.skip(
      "doc-continuity",
      "requires nightly rustdoc --output-format json",
    );
    return Ok(());
  };
  // Printed on every real run, success included: a counted blind spot in the
  // tool's own output is the point, not a fact that only lives in a report.
  let collision_note = format!(
    "{} paths carry two items each — a loss on one of a pair is not visible here",
    current.collisions
  );
  if bless {
    let mut body = String::from(
      "# Documented items in http1-proto. Regenerate with:\n\
       #   cargo run -p xtask -- doc-check --bless\n\
       # A line REMOVED by --bless means this change dropped documentation.\n",
    );
    for item in &current.paths {
      body.push_str(item);
      body.push('\n');
    }
    fs::write(&path, body)?;
    report.checked(format!(
      "doc-continuity: blessed {} documented items ({collision_note})",
      current.paths.len()
    ));
    return Ok(());
  }
  let snapshot: Vec<String> = fs::read_to_string(&path)?
    .lines()
    .filter(|line| !line.starts_with('#') && !line.is_empty())
    .map(str::to_string)
    .collect();
  let lost = lost_docs(&snapshot, &current.paths);
  for item in &lost {
    report.fail(format!(
      "{item} had a doc comment and no longer does.\n  \
       If the doc moved to an item inserted above it, put it back; `///` \
       attaches to the NEXT item and does not know the block had an owner.\n  \
       If the removal is intended, run `cargo run -p xtask -- doc-check --bless`."
    ));
  }
  report.checked(format!(
    "doc-continuity: {} documented items, {} lost ({collision_note})",
    current.paths.len(),
    lost.len()
  ));
  Ok(())
}

/// Paths in `snapshot` that are absent from `current`.
///
/// One-directional on purpose: gaining documentation is not a defect, and a
/// check that fired on it would be blessed into silence within a week.
fn lost_docs(snapshot: &[impl AsRef<str>], current: &[impl AsRef<str>]) -> Vec<String> {
  let have: std::collections::BTreeSet<&str> = current.iter().map(|item| item.as_ref()).collect();
  snapshot
    .iter()
    .map(|item| item.as_ref())
    .filter(|item| !have.contains(item))
    .map(str::to_string)
    .collect()
}

/// What `documented_items` found.
struct DocumentedItems {
  /// Every documented item, as `path::to::item`, sorted and deduplicated.
  paths: Vec<String>,
  /// How many of `paths` were reached by more than one distinct item id: a
  /// private field beside its same-named accessor method, or the same
  /// method name declared in two differently-parameterized impls (say,
  /// `Connection<General>` and `Connection<Tunnel>`) — `walk_item` builds a
  /// path from container *names*, not full type identity, so both collapse
  /// onto one string. A doc lost from one half of such a pair is invisible
  /// to `continuity`: the path stays in `paths` because its sibling still
  /// has a doc, so nothing here can report it.
  collisions: usize,
}

/// Every documented item in `crate_name`, plus how ambiguous that set is —
/// see [`DocumentedItems`].
///
/// `--document-private-items` because the hazard is not public-only: the doc
/// that went missing on #55 was on a `pub(crate)` function, which
/// `missing_docs` cannot see.
///
/// Returns `Ok(None)` when nightly rustdoc's JSON backend is unavailable —
/// no nightly toolchain, or `-Z unstable-options`/`--output-format json`
/// rejected — so the caller can `report.skip` a toolchain limitation instead
/// of failing on it.
fn documented_items(root: &Path, crate_name: &str) -> Result<Option<DocumentedItems>, Error> {
  let output = Command::new("cargo")
    .current_dir(root)
    .args([
      "+nightly",
      "rustdoc",
      "-p",
      crate_name,
      "-Z",
      "unstable-options",
      "--output-format",
      "json",
      "--",
      "--document-private-items",
    ])
    .output()
    .map_err(|err| format!("could not run cargo rustdoc: {err}"))?;
  if !output.status.success() {
    return Ok(None);
  }

  let json_path = target_dir(root)
    .join("doc")
    .join(format!("{}.json", crate_name.replace('-', "_")));
  let text = fs::read_to_string(&json_path)
    .map_err(|err| format!("could not read {}: {err}", json_path.display()))?;
  let value =
    json::parse(&text).map_err(|err| format!("could not parse {}: {err}", json_path.display()))?;

  let index = value
    .get("index")
    .and_then(json::Value::as_object)
    .ok_or("rustdoc JSON has no `index` object")?;
  let root_id = value
    .get("root")
    .and_then(json::Value::as_u64)
    .ok_or("rustdoc JSON has no `root` id")?;

  let mut documented: Vec<(u64, String)> = Vec::new();
  let mut visited = HashSet::new();
  walk_item(root_id, "", index, &mut visited, &mut documented);
  documented.sort_by(|a, b| a.1.cmp(&b.1));

  let mut paths = Vec::with_capacity(documented.len());
  let mut collisions = 0usize;
  for group in documented.chunk_by(|a, b| a.1 == b.1) {
    if group.len() > 1 {
      collisions += 1;
    }
    paths.push(group[0].1.clone());
  }
  Ok(Some(DocumentedItems { paths, collisions }))
}

/// Where `cargo` writes build artifacts for `root`'s workspace:
/// `$CARGO_TARGET_DIR` (resolved against `root` when it is relative, matching
/// Cargo's own rule), or `root/target` when the variable is unset.
fn target_dir(root: &Path) -> PathBuf {
  match env::var_os("CARGO_TARGET_DIR") {
    Some(dir) => {
      let dir = PathBuf::from(dir);
      if dir.is_relative() {
        root.join(dir)
      } else {
        dir
      }
    }
    None => root.join("target"),
  }
}

/// Walks the item tree from `id`, recording `(id, path::to::item)` in
/// `documented` for every item that has both a name and a non-empty doc
/// comment. The id travels alongside the path so the caller can tell when
/// two distinct items land on the same path — see
/// [`DocumentedItems::collisions`].
///
/// rustdoc's JSON keys every item by an opaque id and does not hand out a
/// ready-made qualified path for most of them. The obvious source, the JSON's
/// top-level `paths` table, turns out — on reading the actual output, not the
/// format's documentation — to be populated only as needed for intra-doc link
/// resolution: on `http1-proto` it is missing most methods and struct fields,
/// which are exactly the two largest categories of undocumented items here.
/// So the path is rebuilt by hand while walking the containment tree instead:
/// a module, struct, enum, trait, or union contributes its own name to the
/// prefix its children see; an impl block has no name of its own and passes
/// its container's prefix straight through to its methods and associated
/// items. A local trait implemented for a foreign type (reachable only via
/// the trait's `implementations`, not via any local struct/enum's `impls`) is
/// the one shape this does not reach; `http1-proto` has none today.
fn walk_item(
  id: u64,
  prefix: &str,
  index: &HashMap<String, json::Value>,
  visited: &mut HashSet<u64>,
  documented: &mut Vec<(u64, String)>,
) {
  use json::Value;

  if !visited.insert(id) {
    return;
  }
  let Some(item) = index.get(&id.to_string()) else {
    return;
  };
  // Foreign items pulled into the JSON only for cross-referencing — a
  // blanket impl's provided method from `core`, a re-exported type's
  // original definition in another crate — are not this crate's
  // documentation to lose.
  if item.get("crate_id").and_then(Value::as_u64) != Some(0) {
    return;
  }

  let name = item.get("name").and_then(Value::as_str);
  let path = match name {
    Some(name) if prefix.is_empty() => name.to_string(),
    Some(name) => format!("{prefix}::{name}"),
    None => prefix.to_string(),
  };
  if name.is_some() {
    let has_docs = item
      .get("docs")
      .and_then(Value::as_str)
      .is_some_and(|docs| !docs.is_empty());
    if has_docs {
      documented.push((id, path.clone()));
    }
  }

  let Some(inner) = item.get("inner").and_then(Value::as_object) else {
    return;
  };
  let Some((kind, body)) = inner.iter().next() else {
    return;
  };

  match kind.as_str() {
    "module" => walk_all(as_ids(body.get("items")), &path, index, visited, documented),
    "struct" => {
      let struct_kind = body.get("kind");
      let fields = struct_kind
        .and_then(|k| k.get("plain"))
        .and_then(|p| p.get("fields"))
        .or_else(|| struct_kind.and_then(|k| k.get("tuple")));
      walk_all(as_ids(fields), &path, index, visited, documented);
      walk_all(as_ids(body.get("impls")), &path, index, visited, documented);
    }
    "enum" => {
      walk_all(
        as_ids(body.get("variants")),
        &path,
        index,
        visited,
        documented,
      );
      walk_all(as_ids(body.get("impls")), &path, index, visited, documented);
    }
    "variant" => {
      let variant_kind = body.get("kind");
      let fields = variant_kind.and_then(|k| k.get("tuple")).or_else(|| {
        variant_kind
          .and_then(|k| k.get("struct"))
          .and_then(|s| s.get("fields"))
      });
      walk_all(as_ids(fields), &path, index, visited, documented);
    }
    "trait" => walk_all(as_ids(body.get("items")), &path, index, visited, documented),
    "union" => {
      walk_all(
        as_ids(body.get("fields")),
        &path,
        index,
        visited,
        documented,
      );
      walk_all(as_ids(body.get("impls")), &path, index, visited, documented);
    }
    "impl" => walk_all(as_ids(body.get("items")), &path, index, visited, documented),
    // Everything else (function, constant, static, macro, assoc_const,
    // assoc_type, struct_field, use, …) is a leaf: it has no children of its
    // own for a doc comment to live on. `use` in particular is deliberately
    // not followed to its target: rustdoc keys a `use` item with no name of
    // its own (the imported name lives inside `inner.use`, not at the item's
    // top level), and `--document-private-items` already makes the target
    // reachable through the module that actually declares it.
    _ => {}
  }
}

/// Walks every id in `ids`, threading the shared `path` prefix and the
/// traversal state through each.
fn walk_all(
  ids: Vec<u64>,
  path: &str,
  index: &HashMap<String, json::Value>,
  visited: &mut HashSet<u64>,
  documented: &mut Vec<(u64, String)>,
) {
  for id in ids {
    walk_item(id, path, index, visited, documented);
  }
}

/// The `u64` ids in a JSON array, dropping any `null` entries — rustdoc emits
/// `null` in a fields/variants array for an entry it stripped.
fn as_ids(value: Option<&json::Value>) -> Vec<u64> {
  value
    .and_then(json::Value::as_array)
    .map(|items| items.iter().filter_map(json::Value::as_u64).collect())
    .unwrap_or_default()
}

/// Fails when an `http1-proto` table with a `| corner |`-style header uses a
/// verdict word its own declaration does not list, or declares a word no row
/// uses — see [`verdict_problems`].
///
/// A declaration bullet is `- **VERDICT** — reason`: the bold term
/// immediately followed by an em dash. A bullet that reaches an em dash only
/// mid-sentence, or uses different punctuation (a colon, say) in its place,
/// is not read as a declaration — see [`verdict_problems`]'s own doc for the
/// real bullet that distinguishes it from a declaration, and why the guard
/// exists at all.
///
/// Scoped to that one header shape rather than every markdown table in the
/// crate. Five other tables live in `http1-proto/src` today —
/// `connection/outbound.rs`'s RFC-9112-rule table, three in
/// `connection/mod.rs` (`handle_eof`'s disposition, its EOF-ordering
/// companion, `refuse`'s call/consult table), and `media/mod.rs`'s
/// `Accept`-weight table — and none of them is governed: none has a bulleted
/// declaration above it saying a site "is one of" a closed set, the way
/// `TunnelPhase::Switched` does, so there is no single source for this check
/// to hold them to. Passing one through `verdict_problems` would report
/// every cell as undeclared, which is not a defect in that table — it is
/// this check reaching past its own subject. `| corner | site | verdict |`
/// is, today, unique to `tunnel.rs`; a second table that states an invariant
/// the same way — declared bullets, a self-policing closing sentence, a
/// table of sites — earns the same header and is picked up here without a
/// code change.
fn verdicts(root: &Path, report: &mut Report) -> Result<(), Error> {
  let dir = root.join("http1-proto/src");
  let mut files = Vec::new();
  collect_rs_files(&dir, &mut files)?;
  files.sort();

  let mut tables = 0usize;
  let mut problems = 0usize;
  for file in &files {
    let text = fs::read_to_string(file)?;
    let display = file
      .strip_prefix(root)
      .unwrap_or(file)
      .display()
      .to_string();
    for run in doc_runs(&text) {
      if !run.contains("| corner |") {
        continue;
      }
      tables += 1;
      for problem in verdict_problems(&run) {
        problems += 1;
        report.fail(format!("{display}: {problem}"));
      }
    }
  }
  report.checked(format!(
    "table-verdicts: {tables} table(s) checked, {problems} problem(s)"
  ));
  Ok(())
}

/// Every `.rs` file under `dir`, recursively.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), Error> {
  for entry in fs::read_dir(dir)? {
    let path = entry?.path();
    if path.is_dir() {
      collect_rs_files(&path, out)?;
    } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
      out.push(path);
    }
  }
  Ok(())
}

/// Splits `text` into its maximal contiguous doc-comment runs — `///` or
/// `//!` lines with the marker stripped, joined by `\n`. An ordinary `//`
/// comment or a code line ends a run without starting one; the run it ends
/// is kept and a run still open at EOF is kept too, but an empty run never
/// is.
fn doc_runs(text: &str) -> Vec<String> {
  let mut runs = Vec::new();
  let mut current: Vec<&str> = Vec::new();
  for line in text.lines() {
    let trimmed = line.trim_start();
    let stripped = trimmed
      .strip_prefix("///")
      .or_else(|| trimmed.strip_prefix("//!"));
    match stripped {
      Some(rest) => current.push(rest),
      None if !current.is_empty() => {
        runs.push(current.join("\n"));
        current.clear();
      }
      None => {}
    }
  }
  if !current.is_empty() {
    runs.push(current.join("\n"));
  }
  runs
}

/// Verdict words this doc declares, and the ones its table rows use.
///
/// A declaration is `- **VERDICT** — …`: the bold term immediately followed
/// by an em dash, the same "term — gloss" shape a table cell itself uses
/// (see [`leading_caps`]). The em dash is load-bearing, not decoration: a
/// bolded bullet that reaches one only mid-sentence is not declaring a
/// verdict, it is bolding a word for emphasis. `TunnelPhase::Switched`'s own
/// doc has both — `- **SPATIALLY** does one of three things — …` bolds an
/// axis name, `- **GUARDED** — it asks …` declares a verdict — and
/// collecting every bolded bullet without the guard reads the former as a
/// verdict too, then reports it declared-but-unused: two failures about a
/// sentence making no vocabulary claim at all. Pinned by
/// `a_bold_bullet_that_is_not_a_definition_is_not_a_declared_verdict`.
fn verdict_problems(doc: &str) -> Vec<String> {
  let mut declared: Vec<String> = Vec::new();
  let mut used: Vec<String> = Vec::new();
  for line in doc.lines() {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("- **")
      && let Some(end) = rest.find("**")
      && rest[end + 2..].trim_start().starts_with('—')
    {
      declared.push(rest[..end].to_string());
    } else if trimmed.starts_with('|')
      && !trimmed.starts_with("|---")
      && let Some(cell) = trimmed.rsplit('|').nth(1)
    {
      let verdict = leading_caps(cell.trim());
      if !verdict.is_empty() {
        used.push(verdict);
      }
    }
  }
  let mut problems = Vec::new();
  for verdict in &used {
    if !declared.contains(verdict) {
      problems.push(format!(
        "a row uses the verdict `{verdict}`, which the declaration above it does not list"
      ));
    }
  }
  for verdict in &declared {
    if !used.contains(verdict) {
      problems.push(format!(
        "the declaration lists `{verdict}`, which no row uses — remove it or the \
         self-policing sentence beneath it is false"
      ));
    }
  }
  problems
}

/// The leading run of ALL-CAPS words in `cell`.
fn leading_caps(cell: &str) -> String {
  cell
    .split_whitespace()
    .take_while(|word| {
      word.chars().any(|ch| ch.is_ascii_uppercase())
        && word.chars().all(|ch| ch.is_ascii_uppercase() || ch == '-')
    })
    .collect::<Vec<_>>()
    .join(" ")
}

/// Fails when a `http1-proto` comment path-qualifies a callee — `` `module::
/// name` `` — that the item it documents never uses; see [`callee_problems`].
///
/// Scoped to comments, not to items with a `///` doc block: the defect this
/// check exists for (see `callee_problems`'s own doc) lived in a `//` comment
/// inside a `match` arm, not on a declared item's doc block, so [`items_in`]
/// starts a fresh item at ANY comment run — `//`, `///`, or `//!` — and ends
/// it at the next one, not only at `///` runs the way [`doc_runs`] does.
///
/// What this does NOT catch: an UNQUALIFIED mention. Of the two comments in
/// the defect this exists for, only one was path-qualified; the other read
/// "through the same `ends_persistence`" — no module, so [`qualified_final_segment`]
/// never sees a `::` and this check passes over it in silence. Half a class
/// caught by a gate that stays ON beats a whole class caught by a gate that
/// gets disabled over its false-positive rate — see [`callee_problems`] for
/// why path-qualification is the line drawn — so the narrower rule is what
/// ships, with the miss stated here rather than assumed away.
fn callees(root: &Path, report: &mut Report) -> Result<(), Error> {
  let dir = root.join("http1-proto/src");
  let mut files = Vec::new();
  collect_rs_files(&dir, &mut files)?;
  files.sort();

  let mut mentions = 0usize;
  let mut exempt = 0usize;
  for file in &files {
    let text = fs::read_to_string(file)?;
    let display = file
      .strip_prefix(root)
      .unwrap_or(file)
      .display()
      .to_string();
    for item in items_in(&text) {
      let (comments, _) = split_comments(&item);
      for (path, _) in path_qualified_mentions(&comments) {
        mentions += 1;
        if exemption_reason(&comments, &path).is_some_and(|reason| !reason.trim().is_empty()) {
          exempt += 1;
        }
      }
      for problem in callee_problems(&item) {
        report.fail(format!("{display}: {problem}"));
      }
    }
  }
  report.checked(format!(
    "path-qualified callee: {mentions} mentions checked, {exempt} exempt"
  ));
  Ok(())
}

/// Splits `text` into non-overlapping items: a leading run of comment lines
/// (`//`, `///`, or `//!`, any mixture) plus the source that follows it up to
/// the next such run, or EOF.
///
/// Code with no leading comment run at all — before the file's first
/// comment, or right after an item whose own run was empty — belongs to no
/// item and is not scanned. That is not a blind spot: a path-qualified
/// mention can only ever live inside a comment, so code no item's comments
/// cover has nothing this check could find in it anyway.
fn items_in(text: &str) -> Vec<String> {
  let lines: Vec<&str> = text.lines().collect();
  let is_comment = |line: &str| line.trim_start().starts_with("//");
  let mut starts = Vec::new();
  for (index, line) in lines.iter().enumerate() {
    if is_comment(line) && (index == 0 || !is_comment(lines[index - 1])) {
      starts.push(index);
    }
  }
  starts
    .iter()
    .enumerate()
    .map(|(position, &start)| {
      let end = starts.get(position + 1).copied().unwrap_or(lines.len());
      lines[start..end].join("\n")
    })
    .collect()
}

/// `item`'s leading comment lines (`//`, `///`, or `//!`, any mixture),
/// rejoined with `\n`, and everything from the first non-comment line on.
fn split_comments(item: &str) -> (String, String) {
  let lines: Vec<&str> = item.lines().collect();
  let split_at = lines
    .iter()
    .position(|line| !line.trim_start().starts_with("//"))
    .unwrap_or(lines.len());
  (lines[..split_at].join("\n"), lines[split_at..].join("\n"))
}

/// Mentions this item asserts and does not use.
///
/// Path-qualified only, and that is the whole of why this can be a gate rather
/// than a lint: an unqualified name in prose is usually an English word — 797
/// sites, `close` 74 of them — while `module::name` is a claim that THIS
/// function, from THIS module, is what runs here. Qualified mentions: 46.
fn callee_problems(item: &str) -> Vec<String> {
  let mut problems = Vec::new();
  let (comments, body) = split_comments(item);
  for (path, name) in path_qualified_mentions(&comments) {
    if let Some(reason) = exemption_reason(&comments, &path) {
      if reason.trim().is_empty() {
        problems.push(format!(
          "`{path}` is exempted without a reason after the em dash — an \
           exemption is a statement, and one that says nothing is silence"
        ));
      }
      continue;
    }
    if !names_identifier(&body, &name) {
      problems.push(format!(
        "the comment names `{path}`, asserting it is what this item uses, but \
         the item never names `{name}`.\n  \
         If the mention is deliberate contrast, mark it:\n  \
         `// gate-exempt: {path} — <why this is not the one called>`"
      ));
    }
  }
  problems
}

/// The path-qualified backtick mentions in `comments`, as `(path, name)` —
/// the full backticked text, and its final `::`-separated segment.
///
/// Regex-free: walk the backtick pairs by hand, then classify what sits
/// between a pair with [`qualified_final_segment`].
fn path_qualified_mentions(comments: &str) -> Vec<(String, String)> {
  let mut out = Vec::new();
  let mut rest = comments;
  while let Some(open) = rest.find('`') {
    let after_open = &rest[open + 1..];
    let Some(close) = after_open.find('`') else {
      break;
    };
    let span = &after_open[..close];
    if let Some(name) = qualified_final_segment(span) {
      out.push((span.to_string(), name.to_string()));
    }
    rest = &after_open[close + 1..];
  }
  out
}

/// `span`'s final segment when every `::`-separated segment is shaped like a
/// module or function name — starts with a lowercase ASCII letter or `_`, and
/// otherwise holds only lowercase ASCII letters, digits, and `_` — the final
/// segment names neither a lint nor a module this crate declares, and `span`
/// has at least one `::` to begin with. `None` in every other case.
///
/// The case restriction is what the doc on [`callee_problems`] means by
/// `module::name`, and it is what keeps this a CALLEE check rather than a
/// path-shaped-text check: it excludes a type (`` `Item::Switched` ``,
/// `PascalCase`) and a constant (`` `u64::MAX` ``, `SCREAMING_SNAKE`), neither
/// of which is a claim about what code RUNS. Confirmed against this crate's
/// own comments, not assumed: the unrestricted rule (any backtick span with
/// `::`) matches several hundred sites here, dominated by exactly these two
/// shapes.
///
/// Two more exclusions, added after running the case-restricted rule for
/// real and reading what it found:
///
/// - A **lint's own name** (`` `clippy::integer_division` ``) is lowercase on
///   both sides of the `::`, syntactically indistinguishable from a real
///   module path, but never a place this crate's code runs — the tool, not
///   this crate, owns everything after the `::`. Every `clippy::`/`rustdoc::`
///   mention here today cites a crate-wide `deny`, not a nearby `#[allow]`,
///   so the body right below it was never going to repeat the lint's name.
/// - A **module this crate declares** (`` `head::encode` ``, the `encode`
///   submodule of `head`) is where code LIVES, not a specific place it RUNS —
///   [`KNOWN_MODULES`] lists them, and `mod` itself is excluded too for the
///   one comment that writes `` `connection::mod` `` to mean "that module's
///   own file", which is not a path any real code can name. Read against
///   this crate as it stands, not derived from its grammar: a future function
///   named the same as one of its own modules — this crate already has both a
///   `body` module and a `fn body`, though never mentioned so far in this
///   qualified-and-final shape — would be missed here, the same direction
///   every choice in this function errs: a false PASS, not a false failure.
fn qualified_final_segment(span: &str) -> Option<&str> {
  if !span.contains("::") || is_lint_namespace(span) {
    return None;
  }
  let mut final_segment = None;
  for segment in span.split("::") {
    let mut chars = segment.chars();
    let first = chars.next()?;
    if !(first.is_ascii_lowercase() || first == '_') {
      return None;
    }
    if !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_') {
      return None;
    }
    final_segment = Some(segment);
  }
  match final_segment {
    Some(name) if name == "mod" || KNOWN_MODULES.contains(&name) => None,
    other => other,
  }
}

/// Whether `span` opens with a lint tool's own namespace rather than a path
/// this crate could declare — see [`qualified_final_segment`].
fn is_lint_namespace(span: &str) -> bool {
  matches!(
    span.split("::").next(),
    Some("clippy" | "rustdoc" | "rustc")
  )
}

/// Every `mod NAME` this crate declares under `http1-proto/src`, leaf name
/// only (no path) — see [`qualified_final_segment`].
///
/// A fixed list, not a scan: keeping [`qualified_final_segment`] free of
/// filesystem access is what keeps it a pure function a unit test can call on
/// a literal string, the same way [`KNOWN_MODULES`]'s sibling exclusion
/// ([`is_lint_namespace`]) is. Regenerate by reviewing, from the workspace
/// root:
/// `grep -rhoE '(^|[[:space:]])mod [a-z_][a-z0-9_]*' http1-proto/src | awk '{print $NF}' | sort -u`
const KNOWN_MODULES: &[&str] = &[
  "__no_panic_internals",
  "body",
  "chunked",
  "connection",
  "encode",
  "error",
  "event",
  "grammar",
  "head",
  "heap",
  "heap_tests",
  "inbound",
  "macros",
  "media",
  "mode_edges",
  "outbound",
  "request_line",
  "scan",
  "sealed",
  "status_line",
  "tests",
  "tunnel",
  "validate",
  "version",
  "view",
];

/// The reason `comments` gives for exempting `path`, when one of its lines is
/// a `// gate-exempt: <path> — <reason>` marker whose `<path>` is exactly
/// `path` — `Some("")` when the marker is there but no `—` follows it on that
/// line, and `None` when no marker names `path` at all.
///
/// Same spelling `quote-check` already uses for the same idea
/// ([`exempted_spans`](crate::quote_check) reads the identical `// gate-exempt:
/// <span> — <reason>` comment for a different kind of span) — one mechanism,
/// one convention, rather than a second marker this crate's readers would
/// have to learn. The difference here is that the REASON is load-bearing: a
/// quotation's exemption only has to name its span, but an empty reason here
/// is [`callee_problems`]'s own failure, not silent success.
fn exemption_reason(comments: &str, path: &str) -> Option<String> {
  for line in comments.lines() {
    let trimmed = line.trim_start();
    let Some(rest) = trimmed.strip_prefix("//") else {
      continue;
    };
    let Some(rest) = rest.trim_start().strip_prefix("gate-exempt:") else {
      continue;
    };
    let rest = rest.trim();
    let (span, reason) = match rest.split_once('—') {
      Some((span, reason)) => (span.trim(), reason.trim()),
      None => (rest, ""),
    };
    if span == path {
      return Some(reason.to_string());
    }
  }
  None
}

/// Whether `name` appears in `haystack` as its own word — bounded on each
/// side by the string's edge or a byte that is not an identifier character
/// (ASCII alphanumeric or `_`).
///
/// Deliberately loose about WHAT counts as usage: a mention inside a string
/// literal, an attribute, or even another comment counts, as long as `name`
/// appears as its own word somewhere in `haystack`. A false PASS here costs
/// nothing; a false FAILURE costs the gate — see [`callee_problems`].
fn names_identifier(haystack: &str, name: &str) -> bool {
  if name.is_empty() {
    return false;
  }
  let bytes = haystack.as_bytes();
  let is_ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
  let mut start = 0;
  while let Some(found) = haystack[start..].find(name) {
    let index = start + found;
    let before_ok = index == 0 || !is_ident(bytes[index - 1]);
    let end = index + name.len();
    let after_ok = end == bytes.len() || !is_ident(bytes[end]);
    if before_ok && after_ok {
      return true;
    }
    start = index + 1;
  }
  false
}

/// A minimal JSON reader for rustdoc's `--output-format json` output.
///
/// Hand-rolled rather than an added `serde_json` dependency: `xtask` stays
/// dependency-free by policy, the same argument `fetch_specs` (in
/// `quote_check`) makes for shelling out to `curl` rather than pulling in an
/// HTTP client. It parses the grammar rustdoc's own output uses; a
/// well-formed document is the only kind this ever has to read.
mod json {
  use std::collections::HashMap;

  /// A JSON value, generic enough to read rustdoc's output and nothing more:
  /// no preserved key order, no distinction between integer and fractional
  /// numbers beyond what [`Value::as_u64`] needs.
  #[derive(Debug, PartialEq)]
  pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
  }

  impl Value {
    pub fn as_str(&self) -> Option<&str> {
      match self {
        Value::String(value) => Some(value),
        _ => None,
      }
    }

    pub fn as_object(&self) -> Option<&HashMap<String, Value>> {
      match self {
        Value::Object(value) => Some(value),
        _ => None,
      }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
      match self {
        Value::Array(value) => Some(value),
        _ => None,
      }
    }

    /// A non-negative, integral JSON number. rustdoc's item ids and
    /// `crate_id` are the only numbers this reader looks at, and both are
    /// always this shape.
    pub fn as_u64(&self) -> Option<u64> {
      match self {
        Value::Number(value) if *value >= 0.0 && value.fract() == 0.0 => Some(*value as u64),
        _ => None,
      }
    }

    /// `self[key]` when `self` is an object, else `None` — including when
    /// `self` is some other JSON type, so a caller can chain `.get` across a
    /// shape it merely expects rather than matching it out by hand each step.
    pub fn get(&self, key: &str) -> Option<&Value> {
      self.as_object()?.get(key)
    }
  }

  /// Parses a complete JSON document.
  ///
  /// A minimal recursive-descent parser: it reads exactly the grammar
  /// rustdoc's JSON backend emits and does not attempt to reject every
  /// malformed document a hostile input could contain.
  pub fn parse(input: &str) -> Result<Value, String> {
    let bytes = input.as_bytes();
    let mut pos = 0;
    parse_value(bytes, &mut pos)
  }

  fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while matches!(bytes.get(*pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
      *pos += 1;
    }
  }

  fn parse_value(bytes: &[u8], pos: &mut usize) -> Result<Value, String> {
    skip_ws(bytes, pos);
    match bytes.get(*pos) {
      Some(b'{') => parse_object(bytes, pos),
      Some(b'[') => parse_array(bytes, pos),
      Some(b'"') => parse_string(bytes, pos).map(Value::String),
      Some(b't') => parse_literal(bytes, pos, "true", Value::Bool(true)),
      Some(b'f') => parse_literal(bytes, pos, "false", Value::Bool(false)),
      Some(b'n') => parse_literal(bytes, pos, "null", Value::Null),
      Some(b'-' | b'0'..=b'9') => parse_number(bytes, pos),
      Some(&other) => Err(format!(
        "unexpected byte {:?} at offset {pos}",
        other as char
      )),
      None => Err("unexpected end of input".to_string()),
    }
  }

  fn parse_literal(
    bytes: &[u8],
    pos: &mut usize,
    text: &str,
    value: Value,
  ) -> Result<Value, String> {
    let end = *pos + text.len();
    if bytes.get(*pos..end) == Some(text.as_bytes()) {
      *pos = end;
      Ok(value)
    } else {
      Err(format!("expected {text:?} at offset {pos}"))
    }
  }

  fn parse_number(bytes: &[u8], pos: &mut usize) -> Result<Value, String> {
    let start = *pos;
    if bytes.get(*pos) == Some(&b'-') {
      *pos += 1;
    }
    while matches!(bytes.get(*pos), Some(b) if b.is_ascii_digit()) {
      *pos += 1;
    }
    if bytes.get(*pos) == Some(&b'.') {
      *pos += 1;
      while matches!(bytes.get(*pos), Some(b) if b.is_ascii_digit()) {
        *pos += 1;
      }
    }
    if matches!(bytes.get(*pos), Some(b'e' | b'E')) {
      *pos += 1;
      if matches!(bytes.get(*pos), Some(b'+' | b'-')) {
        *pos += 1;
      }
      while matches!(bytes.get(*pos), Some(b) if b.is_ascii_digit()) {
        *pos += 1;
      }
    }
    let text = str_slice(bytes, start, *pos)?;
    text
      .parse::<f64>()
      .map(Value::Number)
      .map_err(|err| format!("invalid number {text:?}: {err}"))
  }

  fn parse_object(bytes: &[u8], pos: &mut usize) -> Result<Value, String> {
    *pos += 1; // the opening '{'
    let mut map = HashMap::new();
    skip_ws(bytes, pos);
    if bytes.get(*pos) == Some(&b'}') {
      *pos += 1;
      return Ok(Value::Object(map));
    }
    loop {
      skip_ws(bytes, pos);
      if bytes.get(*pos) != Some(&b'"') {
        return Err(format!("expected object key at offset {pos}"));
      }
      let key = parse_string(bytes, pos)?;
      skip_ws(bytes, pos);
      if bytes.get(*pos) != Some(&b':') {
        return Err(format!("expected ':' at offset {pos}"));
      }
      *pos += 1;
      let value = parse_value(bytes, pos)?;
      map.insert(key, value);
      skip_ws(bytes, pos);
      match bytes.get(*pos) {
        Some(b',') => *pos += 1,
        Some(b'}') => {
          *pos += 1;
          break;
        }
        _ => return Err(format!("expected ',' or '}}' at offset {pos}")),
      }
    }
    Ok(Value::Object(map))
  }

  fn parse_array(bytes: &[u8], pos: &mut usize) -> Result<Value, String> {
    *pos += 1; // the opening '['
    let mut items = Vec::new();
    skip_ws(bytes, pos);
    if bytes.get(*pos) == Some(&b']') {
      *pos += 1;
      return Ok(Value::Array(items));
    }
    loop {
      items.push(parse_value(bytes, pos)?);
      skip_ws(bytes, pos);
      match bytes.get(*pos) {
        Some(b',') => *pos += 1,
        Some(b']') => {
          *pos += 1;
          break;
        }
        _ => return Err(format!("expected ',' or ']' at offset {pos}")),
      }
    }
    Ok(Value::Array(items))
  }

  fn parse_string(bytes: &[u8], pos: &mut usize) -> Result<String, String> {
    *pos += 1; // the opening '"'
    let mut out = String::new();
    let mut run_start = *pos;
    loop {
      let Some(&byte) = bytes.get(*pos) else {
        return Err("unterminated string".to_string());
      };
      match byte {
        b'"' => {
          out.push_str(str_slice(bytes, run_start, *pos)?);
          *pos += 1;
          return Ok(out);
        }
        b'\\' => {
          out.push_str(str_slice(bytes, run_start, *pos)?);
          *pos += 1;
          let Some(&escape) = bytes.get(*pos) else {
            return Err("unterminated escape".to_string());
          };
          match escape {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{8}'),
            b'f' => out.push('\u{c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
              *pos += 1;
              let unit = parse_hex4(bytes, pos)?;
              let code = if (0xD800..=0xDBFF).contains(&unit) {
                // A high surrogate must be followed by a low surrogate's own
                // `\u` escape; together they encode one codepoint above the
                // Basic Multilingual Plane (an emoji, for instance).
                if bytes.get(*pos) != Some(&b'\\') || bytes.get(*pos + 1) != Some(&b'u') {
                  return Err("unpaired UTF-16 surrogate".to_string());
                }
                *pos += 2;
                let low = parse_hex4(bytes, pos)?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                  return Err("invalid low surrogate".to_string());
                }
                0x10000 + (u32::from(unit) - 0xD800) * 0x400 + (u32::from(low) - 0xDC00)
              } else {
                u32::from(unit)
              };
              let ch =
                char::from_u32(code).ok_or_else(|| format!("invalid code point {code:#x}"))?;
              out.push(ch);
              run_start = *pos;
              continue;
            }
            other => return Err(format!("invalid escape \\{}", other as char)),
          }
          *pos += 1;
          run_start = *pos;
        }
        _ => *pos += 1,
      }
    }
  }

  fn parse_hex4(bytes: &[u8], pos: &mut usize) -> Result<u16, String> {
    if *pos + 4 > bytes.len() {
      return Err("truncated \\u escape".to_string());
    }
    let text = str_slice(bytes, *pos, *pos + 4)?;
    let value =
      u16::from_str_radix(text, 16).map_err(|err| format!("invalid \\u escape {text:?}: {err}"))?;
    *pos += 4;
    Ok(value)
  }

  fn str_slice(bytes: &[u8], start: usize, end: usize) -> Result<&str, String> {
    std::str::from_utf8(&bytes[start..end]).map_err(|err| err.to_string())
  }

  #[cfg(test)]
  mod tests {
    use super::{Value, parse};

    // Exercises every shape `documented_items` actually reads out of
    // rustdoc's JSON: nested objects and arrays, a null array entry (a
    // stripped field), and the handful of escapes a doc comment's rendered
    // HTML realistically contains.
    #[test]
    fn parses_the_shapes_rustdoc_json_uses() {
      let value = parse(
        r#"{"index": {"1": {"id": 1, "name": "a\"b\\cé", "docs": null}}, "root": 1, "ids": [1, 2, null]}"#,
      )
      .unwrap();
      assert_eq!(value.get("root").and_then(Value::as_u64), Some(1));
      assert_eq!(
        value.get("ids").and_then(Value::as_array).map(<[_]>::len),
        Some(3)
      );
      assert_eq!(
        value
          .get("index")
          .and_then(|index| index.get("1"))
          .and_then(|item| item.get("name"))
          .and_then(Value::as_str),
        Some("a\"b\\c\u{e9}")
      );
      assert_eq!(
        value
          .get("index")
          .and_then(|index| index.get("1"))
          .and_then(|item| item.get("docs")),
        Some(&Value::Null)
      );
    }
  }
}

#[cfg(test)]
mod tests {
  use super::Report;

  // The spine, as a unit: a skip is a printed boundary on a developer's
  // machine and a FAILURE under --require-all, so a check that only ever runs
  // in one CI job cannot disappear the day that job is edited.
  #[test]
  fn a_skip_is_tolerated_alone_and_fatal_under_require_all() {
    let mut report = Report::new();
    report.skip("doc-continuity", "requires nightly rustdoc");
    assert!(report.clone().finish(false).is_ok());
    assert!(report.finish(true).is_err());
  }

  // The hazard: `///` attaches to the NEXT item and Rust has no notion of a
  // block already having an owner, so inserting a documented item directly
  // above another TRANSFERS the older doc without altering a character of it.
  // The old block reads as untouched context in the diff. Only a delta sees it.
  #[test]
  fn an_item_that_lost_its_doc_fails_the_snapshot() {
    let snapshot = ["a::b", "a::c"];
    let current = ["a::b"];
    let lost = super::lost_docs(&snapshot, &current);
    assert_eq!(lost, ["a::c"]);
  }

  #[test]
  fn a_newly_documented_item_is_not_a_failure() {
    let snapshot = ["a::b"];
    let current = ["a::b", "a::c"];
    assert!(super::lost_docs(&snapshot, &current).is_empty());
  }

  // The brief's own fixture for this test declared two verdicts and used
  // neither in a row, so — under the brief's own `verdict_problems`, run
  // verbatim before this file added rows for them — it failed its own
  // `assert_eq!(problems.len(), 1)` with 3, not 1: the intended STRUCTURALLY
  // EXCLUDED failure plus GUARDED and GUARDED BY A CALLER both flagged
  // declared-but-unused. Each declared verdict below now has a row that uses
  // it, isolating the one failure this test's name is actually about.
  #[test]
  fn a_row_using_an_undeclared_verdict_is_a_failure() {
    let doc = "\
- **GUARDED** — it asks the close question itself.
- **GUARDED BY A CALLER** — an earlier gate makes the state unreachable.

| corner | site | verdict |
|---|---|---|
| originate | `open_request` | GUARDED — ok |
| receive | `into_tunnel` | GUARDED BY A CALLER — ok |
| emit | `send_response` | STRUCTURALLY EXCLUDED — cannot emit one |
";
    let problems = super::verdict_problems(doc);
    assert_eq!(problems.len(), 1);
    assert!(problems[0].contains("STRUCTURALLY EXCLUDED"));
  }

  #[test]
  fn a_declared_verdict_no_row_uses_is_a_failure() {
    let doc = "\
- **GUARDED** — it asks the close question itself.
- **DELIBERATELY EXCLUDED** — with its reason recorded at the site.

| corner | site | verdict |
|---|---|---|
| emit | `send_response` | GUARDED — [`X`] |
";
    let problems = super::verdict_problems(doc);
    assert_eq!(problems.len(), 1);
    assert!(problems[0].contains("DELIBERATELY EXCLUDED"));
  }

  // Pins a real defect found running this check on `tunnel.rs` itself:
  // `TunnelPhase::Switched`'s doc bolds two OTHER terms — SPATIALLY,
  // TEMPORALLY — before its verdict declaration, naming the two axes a site
  // is classified on. Both match `- **WORD**`, same as a real declaration
  // bullet, but neither is followed by an em dash the way every actual
  // verdict bullet is (`- **SPATIALLY** does …`, not `- **SPATIALLY** — …`).
  // Treating any bolded bullet as a declaration reported both as verdicts
  // nothing declares them to be, and then as declared verdicts no row uses:
  // two failures about a sentence that was never making a vocabulary claim.
  #[test]
  fn a_bold_bullet_that_is_not_a_definition_is_not_a_declared_verdict() {
    let doc = "\
A site belongs to this invariant when it either:

- **SPATIALLY** does one of three things — writes this variant, or
  encodes a switching head; or
- **TEMPORALLY** changes the connection's fate while a switch is ARMED.

Every such site is one of:

- **GUARDED** — it asks the close question itself.

| corner | site | verdict |
|---|---|---|
| originate | `open_request` | GUARDED — ok |
";
    assert!(super::verdict_problems(doc).is_empty());
  }

  #[test]
  fn a_path_qualified_name_the_body_never_uses_is_a_failure() {
    let item = "\
/// Decided through `validate::ends_persistence`, the predicate both modes ask.
fn switch_or_fault(view: &HeadView<'_>) -> bool {
  has_close_option(view)
}";
    let problems = super::callee_problems(item);
    assert_eq!(problems.len(), 1);
    assert!(problems[0].contains("ends_persistence"));
  }

  #[test]
  fn an_exempt_mention_is_allowed() {
    let item = "\
// gate-exempt: validate::ends_persistence — named for contrast; this arm asks
// has_close_option, and saying which one it is NOT is the point of the sentence.
/// Asks `has_close_option`, NOT `validate::ends_persistence`.
fn switch_or_fault(view: &HeadView<'_>) -> bool {
  has_close_option(view)
}";
    assert!(super::callee_problems(item).is_empty());
  }

  #[test]
  fn an_exemption_without_a_reason_is_itself_a_failure() {
    let item = "\
// gate-exempt: validate::ends_persistence
/// Asks `has_close_option`, NOT `validate::ends_persistence`.
fn switch_or_fault(view: &HeadView<'_>) -> bool { has_close_option(view) }";
    let problems = super::callee_problems(item);
    assert_eq!(problems.len(), 1);
    assert!(problems[0].contains("reason"));
  }

  // `items_in` is what feeds real files to `callee_problems`, and the defect
  // this whole check exists for lived in a `//` comment mid-function, not on
  // a declared item — so this pins that a fresh item starts at ANY comment
  // run, a blank line does not end one early, and an item's body reaches
  // forward to the NEXT comment run rather than stopping at the first blank
  // line or closing brace.
  #[test]
  fn items_in_splits_at_each_fresh_comment_run() {
    let text = "\
/// First.
fn a() {}

// Not a doc comment, still starts a fresh item.
fn b() {
  a()
}
";
    let items = super::items_in(text);
    assert_eq!(items.len(), 2);
    assert!(items[0].starts_with("/// First."));
    assert!(items[0].contains("fn a"));
    assert!(items[1].starts_with("// Not a doc comment"));
    assert!(items[1].contains("fn b"));
  }

  // Pins the case restriction `qualified_final_segment` applies: it is what
  // keeps a `PascalCase` type (`Item::Switched`) and a `SCREAMING_SNAKE`
  // constant (`u64::MAX`) from being read as callee claims, while a genuine
  // `snake_case::snake_case` mention still is — measured against this crate's
  // own comments before being drawn this way, not assumed (see
  // `qualified_final_segment`'s own doc).
  #[test]
  fn only_the_lowercase_path_is_read_as_a_callee_claim() {
    let comments = "/// See `Item::Switched` and `u64::MAX` and `validate::ends_persistence`.";
    let mentions = super::path_qualified_mentions(comments);
    assert_eq!(
      mentions,
      vec![(
        "validate::ends_persistence".to_string(),
        "ends_persistence".to_string()
      )]
    );
  }

  // Pins the two exclusions added after running the check for real: a lint's
  // own name and this crate's own module names are both syntactically
  // `lowercase::lowercase`, same as a genuine callee mention, but neither is
  // a claim about what code RUNS — see `qualified_final_segment`'s own doc.
  #[test]
  fn a_lint_name_or_a_known_module_is_not_a_callee_claim() {
    let comments = "\
/// See `clippy::integer_division`, `head::encode`, `connection::mod`, and
/// `validate::ends_persistence`.";
    let mentions = super::path_qualified_mentions(comments);
    assert_eq!(
      mentions,
      vec![(
        "validate::ends_persistence".to_string(),
        "ends_persistence".to_string()
      )]
    );
  }

  // Pins the word-boundary rule `names_identifier` promises: a longer
  // identifier that merely CONTAINS `name` as a substring — `closed`,
  // `disclosed` — must not count as naming it.
  #[test]
  fn names_identifier_requires_a_word_boundary() {
    assert!(!super::names_identifier(
      "this connection is disclosed and closed",
      "close"
    ));
    assert!(super::names_identifier("fn close(&mut self)", "close"));
  }
}
