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
  let current = match documented_items(root, "http1-proto")? {
    RustdocJson::Items(items) => items,
    RustdocJson::Unavailable(why) => {
      report.skip("doc-continuity", &why);
      return Ok(());
    }
    RustdocJson::Failed(what) => {
      report.fail(what);
      return Ok(());
    }
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

/// What one attempt to read rustdoc's JSON produced.
///
/// Three answers, not two, and the third is the point: a check that could not
/// run must not report the SAME reason whatever stopped it. `Unavailable` is
/// the toolchain limitation this command is designed to skip for;
/// `Failed` is everything else, which is a run this check owes an accurate
/// account of rather than a skip that sends its reader to install a toolchain
/// they already have.
enum RustdocJson {
  /// The documented set, read from `<target>/doc/<crate>.json`.
  Items(DocumentedItems),
  /// This toolchain cannot produce the JSON at all, with the reason to print.
  Unavailable(String),
  /// rustdoc ran on a toolchain that CAN produce the JSON and failed anyway —
  /// most often because the crate did not build. Carries rustdoc's own words.
  Failed(String),
}

/// Every documented item in `crate_name`, plus how ambiguous that set is —
/// see [`DocumentedItems`].
///
/// `--document-private-items` because the hazard is not public-only: the doc
/// that went missing on #55 was on a `pub(crate)` function, which
/// `missing_docs` cannot see.
///
/// The two ways this does not produce a set are told apart by ASKING, not by
/// assuming: on failure it probes whether `cargo +nightly` runs at all. If it
/// does not, the nightly toolchain really is missing and the caller skips
/// ([`RustdocJson::Unavailable`]). If it does, the toolchain is present and
/// something else went wrong — a crate that does not compile, most often — and
/// the caller FAILS with rustdoc's own output ([`RustdocJson::Failed`]).
/// Returning the toolchain reason for both was this check's own version of the
/// defect it exists to catch: one answer covering two different facts, sending
/// a reader with a broken tree to install a toolchain they already have.
///
/// The boundary that leaves, stated: a future nightly that REMOVED
/// `--output-format json` would land in `Failed` rather than `Unavailable`,
/// because the probe only asks whether the toolchain exists. The message
/// carries rustdoc's own words, so the reader is told what was rejected
/// instead of being told to install nightly — which is the property that
/// matters here; classifying it as a skip as well would mean matching on
/// rustdoc's wording, and a matcher that guesses wrong turns a broken build
/// back into a silent skip.
fn documented_items(root: &Path, crate_name: &str) -> Result<RustdocJson, Error> {
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
    if !nightly_runs(root) {
      return Ok(RustdocJson::Unavailable(
        "requires nightly rustdoc --output-format json".to_string(),
      ));
    }
    let status = output
      .status
      .code()
      .map_or_else(|| "a signal".to_string(), |code| format!("status {code}"));
    return Ok(RustdocJson::Failed(format!(
      "doc-continuity could not run: `cargo +nightly rustdoc -p {crate_name}` exited with \
       {status}.\n  \
       This is NOT the nightly-toolchain limitation this check skips for — `cargo +nightly` \
       runs here. The crate most likely does not build.\n  \
       What it printed:\n{}",
      indented_tail(&String::from_utf8_lossy(&output.stderr))
    )));
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
  Ok(RustdocJson::Items(DocumentedItems { paths, collisions }))
}

/// Whether `cargo +nightly` runs at all in `root`.
///
/// The one question that tells a missing toolchain from a failure that merely
/// happened on one — asked directly rather than inferred from what rustdoc
/// printed, because a matcher over another tool's wording is a guess and this
/// is a fact a process exit code already answers.
fn nightly_runs(root: &Path) -> bool {
  Command::new("cargo")
    .current_dir(root)
    .args(["+nightly", "--version"])
    .output()
    .is_ok_and(|probe| probe.status.success())
}

/// The last few non-empty lines of `text`, each indented, for quoting another
/// tool's output inside a failure message.
///
/// The TAIL rather than the head: cargo prints the summary error last, and a
/// long build log's opening lines are progress rather than diagnosis.
fn indented_tail(text: &str) -> String {
  const LINES: usize = 12;
  let lines: Vec<&str> = text
    .lines()
    .filter(|line| !line.trim().is_empty())
    .collect();
  lines[lines.len().saturating_sub(LINES)..]
    .iter()
    .map(|line| format!("    {line}"))
    .collect::<Vec<_>>()
    .join("\n")
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

/// The header substring that marks a table as governed by its own
/// declaration — the whole of this check's discovery rule, named once so
/// [`verdicts`] and the test that pins the real table cannot drift apart.
const GOVERNED_HEADER: &str = "| corner |";

/// Fails when an `http1-proto` table with a [`GOVERNED_HEADER`] header uses a
/// verdict word its own declaration does not list, declares a word no row
/// uses, or carries a row whose verdict cell yields no verdict at all — see
/// [`verdict_problems`]. Fails, too, when NO governed table is found.
///
/// A declaration bullet is `- **VERDICT** — reason`: the bold term
/// immediately followed by an em dash. A bullet that reaches an em dash only
/// mid-sentence, or uses different punctuation (a colon, say) in its place,
/// is not read as a declaration — see [`verdict_problems`]'s own doc for the
/// real bullet that distinguishes it from a declaration, and why the guard
/// exists at all.
///
/// **Zero governed tables is a failure, not a quiet zero.** Discovery is a
/// literal header substring, so renaming one word of it un-governs the
/// crate's only governed table and every later run reports `0 table(s)
/// checked, 0 problem(s)` and exits 0 — `--require-all` included, since that
/// flag gates skips and this check never skips. A check whose subject can
/// silently cease to exist is the class this whole command was built to
/// remove, so the floor is here and
/// `the_real_switched_table_is_discovered` pins the live table as well: the
/// rename fails the suite instead of emptying the check.
///
/// Scoped to that one header shape rather than every markdown table in the
/// crate. SIX other tables live in `http1-proto/src` today —
/// `connection/outbound.rs`'s RFC-9112-rule table, three in
/// `connection/mod.rs` (`handle_eof`'s disposition, its EOF-ordering
/// companion, `refuse`'s call/consult table), `media/mod.rs`'s
/// `Accept`-weight table, and `connection/tunnel.rs`'s own `handle_eof`
/// Ordering/Result table, further down the same file as the governed one and
/// the one this sentence has twice failed to name — and none of them
/// is governed: none has a bulleted declaration above it saying a site "is
/// one of" a closed set, the way `TunnelPhase::Switched` does, so there is no
/// single source for this check to hold them to. Passing one through
/// [`verdict_problems`] would report every cell as undeclared, which is not a
/// defect in that table — it is this check reaching past its own subject.
/// That census is a count of files on disk, not a rule, so recount it rather
/// than trusting this sentence: from the workspace root,
/// `grep -rn -- "|---" http1-proto/src` lists every table, governed one
/// included. It has been wrong twice by being written from memory.
/// `| corner | site | verdict |` is, today, unique to `tunnel.rs`; a second
/// table that states an invariant the same way — declared bullets, a
/// self-policing closing sentence, a table of sites — earns the same header
/// and is picked up here without a code change.
///
/// **The rule from the design this does NOT implement.** §5.2 states three;
/// the two above are rules 1 and 2. Rule 3 — no comment ELSEWHERE in the
/// crate assigns a different verdict word to a site the table names — is not
/// here and is not planned as a heuristic: matching a prose sentence to a
/// table row needs a rule for when two texts name the same site, and a fuzzy
/// one either misses the case it exists for or reports every neighbouring
/// paragraph. It is deferred with that reasoning recorded, and named here
/// rather than only in the ledger, because a reader of this check would
/// otherwise take the vocabulary for policed everywhere it is written.
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
      if !run.contains(GOVERNED_HEADER) {
        continue;
      }
      tables += 1;
      for problem in verdict_problems(&run) {
        problems += 1;
        report.fail(format!("{display}: {problem}"));
      }
    }
  }
  if tables == 0 {
    problems += 1;
    report.fail(format!(
      "table-verdicts governed nothing: no doc comment under {} carries the \
       `{GOVERNED_HEADER}` header this check discovers a governed table by.\n  \
       `TunnelPhase::Switched` in `connection/tunnel.rs` is the one this crate \
       has. If its header was reworded, restore it (or move the wording here); \
       if the table was deliberately removed, remove this check with it.\n  \
       A run reporting zero tables and zero problems is this check governing \
       nothing while still reporting success.",
      dir.strip_prefix(root).unwrap_or(&dir).display()
    ));
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
///
/// **A row whose verdict cell yields no verdict is a problem, not a pass.**
/// [`leading_caps`] reads only a LEADING run of ALL-CAPS words, so a cell
/// written in lower case contributes nothing to `used` — and rule 2 stays
/// quiet as long as some other row still uses the declared word. The rule
/// would then be opt-in by capitalisation: the one row that steps outside the
/// vocabulary is the one row not held to it. Every row after the header
/// separator must therefore yield a verdict, and a cell that does not is
/// reported with its own text.
///
/// A row is a line inside the table BODY: the `|---` separator opens it and
/// the first line that is not a `|` row closes it. That is what keeps the
/// HEADER row (`| corner | site | verdict |`, whose last cell names a column
/// rather than a verdict) out of the rule the header row would otherwise be
/// the first to break.
fn verdict_problems(doc: &str) -> Vec<String> {
  let mut declared: Vec<String> = Vec::new();
  let mut used: Vec<String> = Vec::new();
  let mut problems = Vec::new();
  let mut in_body = false;
  for line in doc.lines() {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("- **")
      && let Some(end) = rest.find("**")
      && rest[end + 2..].trim_start().starts_with('—')
    {
      declared.push(rest[..end].to_string());
      continue;
    }
    if trimmed.starts_with("|---") {
      in_body = true;
      continue;
    }
    if !trimmed.starts_with('|') {
      in_body = false;
      continue;
    }
    if !in_body {
      continue;
    }
    let Some(cell) = trimmed.rsplit('|').nth(1) else {
      continue;
    };
    let cell = cell.trim();
    let verdict = leading_caps(cell);
    if verdict.is_empty() {
      problems.push(format!(
        "a row's verdict cell begins with no verdict: `{cell}`.\n  \
         The vocabulary is read from a LEADING run of ALL-CAPS words, so a cell \
         that opens in lower case is held to nothing — write the declared \
         verdict, or the declaration above this table governs every row but \
         this one"
      ));
    } else {
      used.push(verdict);
    }
  }
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
/// name` `` — ON AN ASSERTIVE SENTENCE, that the item it documents never
/// uses, or that the named module does not hold; see [`callee_problems`].
///
/// BOTH halves of the path are verified, because both halves are claimed.
/// `module::name` asserts two things — that `name` is what runs here, and
/// that `name` is the one from `module` — and checking only the final segment
/// leaves the second unread: `grammar::ends_persistence` then passes exactly
/// where `validate::ends_persistence` would, though no such item exists. See
/// [`module_index`] for how the module half is resolved, and for the mentions
/// it cannot resolve, which are counted rather than assumed correct.
///
/// Scoped to comments, not to items with a `///` doc block: the defect this
/// check exists for (see `callee_problems`'s own doc) lived in a `//` comment
/// inside a `match` arm, not on a declared item's doc block, so [`items_in`]
/// starts a fresh item at ANY comment run — `//`, `///`, or `//!` — and ends
/// it at the next one, not only at `///` runs the way [`doc_runs`] does.
///
/// TWO things this does NOT catch, both stated rather than assumed away —
/// see [`callee_problems`]'s own doc for the measurement behind each:
///
/// - An **UNQUALIFIED** mention. Of the two comments in the defect this
///   exists for, only one was path-qualified; the other read "through the
///   same `ends_persistence`" — no module, so [`qualified_final_segment`]
///   never sees a `::` and this check passes over it in silence.
/// - A **path-qualified mention on a sentence with none of
///   [`ASSERTIVE_VERBS`]** (Ruling 13). Most of this crate's cross-referential
///   prose — a shared-invariant paragraph, a send/receive counterpart, a note
///   to a field's future writer — path-qualifies a name without one of these
///   verbs, and is invisible here by design: it is a "see also", not a claim
///   this check can verify against the item's own body.
///
/// Half a class caught by a gate that stays ON beats a whole class caught by
/// a gate that gets disabled over its false-positive rate — see
/// [`callee_problems`] for why both lines are drawn where they are — so the
/// narrower rule is what ships, with both misses named here rather than left
/// for a reader to assume "comment names the wrong callee" is fully covered.
fn callees(root: &Path, report: &mut Report) -> Result<(), Error> {
  let dir = root.join("http1-proto/src");
  let mut files = Vec::new();
  collect_rs_files(&dir, &mut files)?;
  files.sort();
  let modules = module_index(&files)?;

  let mut mentions = 0usize;
  let mut exempt = 0usize;
  let mut unresolved = 0usize;
  for file in &files {
    let text = fs::read_to_string(file)?;
    let display = file
      .strip_prefix(root)
      .unwrap_or(file)
      .display()
      .to_string();
    for item in items_in(&text) {
      let (comments, _) = split_comments(&item);
      for (path, _) in assertive_mentions(&comments) {
        mentions += 1;
        if exemption_reason(&comments, &path).is_some_and(|reason| !reason.trim().is_empty()) {
          exempt += 1;
        } else if matches!(module_half(&modules, &path), ModuleHalf::Unresolvable) {
          unresolved += 1;
        }
      }
      for problem in callee_problems(&item, &modules) {
        report.fail(format!("{display}: {problem}"));
      }
    }
  }
  report.checked(format!(
    "path-qualified callee: {mentions} mentions checked, {exempt} exempt, \
     {unresolved} whose module half is not this crate's to resolve"
  ));
  Ok(())
}

/// Every module `http1-proto/src` declares as a FILE, by leaf name, beside
/// that file's text.
///
/// `foo.rs` and `foo/mod.rs` are both module `foo`; `lib.rs` is the crate root
/// and names no module. Two files that land on the same leaf name — every
/// `tests.rs` in the crate — are joined, which errs towards a false PASS, the
/// direction every judgement in this check errs.
///
/// A file, not the rustdoc JSON `continuity` reads: this check runs on stable
/// too, and it would be an odd trade to make the cheapest of the three
/// nightly-only for a lookup that a directory listing answers.
fn module_index(files: &[PathBuf]) -> Result<HashMap<String, String>, Error> {
  let mut index: HashMap<String, String> = HashMap::new();
  for file in files {
    let stem = file.file_stem().and_then(|stem| stem.to_str());
    let name = match stem {
      Some("mod") => file.parent().and_then(Path::file_name),
      Some("lib") => None,
      _ => file.file_stem(),
    };
    let Some(name) = name.and_then(|name| name.to_str()) else {
      continue;
    };
    let text = fs::read_to_string(file)?;
    index.entry(name.to_string()).or_default().push_str(&text);
  }
  Ok(index)
}

/// What [`module_index`] can say about the module half of a path-qualified
/// mention.
enum ModuleHalf {
  /// The module this crate declares under that name does name the item.
  Holds,
  /// It exists, and never names the item — the claim is checkable and false.
  Absent,
  /// No module of this crate answers to that name, so nothing here can
  /// settle it: `core::str`'s modules, a `crate`/`self`/`super` prefix, a
  /// module of another crate. Counted by [`callees`] rather than passed over
  /// in silence — the mention is checked on its final segment and NOT on its
  /// module half, and a run should say how many of its mentions are in that
  /// position.
  Unresolvable,
}

/// Whether the module `path` names holds `path`'s final segment.
///
/// The module half is the segment immediately before the last one, which is
/// the one the path claims the item lives in. Membership is the same
/// deliberately loose test [`names_identifier`] applies to an item's own body,
/// applied to the module's file: a re-export, a declaration, or a mention in
/// that file all count. A false PASS here costs nothing; a false FAILURE
/// costs the gate.
fn module_half(index: &HashMap<String, String>, path: &str) -> ModuleHalf {
  let segments: Vec<&str> = path.split("::").collect();
  let (Some(name), Some(module)) = (
    segments.last(),
    segments
      .len()
      .checked_sub(2)
      .and_then(|at| segments.get(at)),
  ) else {
    return ModuleHalf::Unresolvable;
  };
  let Some(text) = index.get(*module) else {
    return ModuleHalf::Unresolvable;
  };
  if names_identifier(text, name) {
    ModuleHalf::Holds
  } else {
    ModuleHalf::Absent
  }
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
/// Two conditions, both required, and neither alone is enough:
///
/// - **Path-qualified**, which is the whole of why this can be a gate rather
///   than a lint: an unqualified name in prose is usually an English word —
///   797 sites, `close` 74 of them — while `module::name` is a claim that
///   THIS function, from THIS module, is what runs here. Both halves of that
///   claim are checked ([`module_half`]): the module must hold the name, and
///   the item must use it. Reading only the final segment left the module
///   half — half of the very claim the qualified form is admitted here for —
///   taken on trust.
/// - **On an assertive sentence** ([`assertive_mentions`], Ruling 13): the
///   original defect's comment read "Tunnel mode decides the same thing
///   about the same fact, through `` `validate::has_close_option` ``", and
///   "through" is the whole claim. The SAME path-qualified name in a
///   "see also" sentence — a shared-invariant paragraph, a send/receive
///   counterpart, a note to a field's future writer — refers to a
///   NEIGHBOUR, not to what this item itself does, and is not a claim this
///   check can verify locally at all.
///
/// Path-qualified mentions of a crate function in `http1-proto/src`: 46.
/// Of those, on an assertive sentence: 5.
///
/// ## The limit this leaves, stated rather than assumed away
///
/// Two mentions this rule does not reach, both real: an UNQUALIFIED name (no
/// `module::` in front — the second comment in the defect this check exists
/// for read "through the same `ends_persistence`", and has no `::` for
/// [`qualified_final_segment`] to see) and a path-qualified name on a
/// sentence with NONE of [`ASSERTIVE_VERBS`] — a comment could still name the
/// wrong callee using a verb this list does not carry. Neither is "comment
/// names the wrong callee" caught in full; a reader must not take this check
/// for that. Half a class caught by a gate that stays ON beats a whole class
/// caught by a gate that gets disabled over its false-positive rate.
///
/// A third, narrower limit, and it is COUNTED rather than merely stated: a
/// mention whose module half names no module of this crate — another crate's,
/// or a `crate`/`self`/`super` prefix — has that half checked by nothing
/// ([`ModuleHalf::Unresolvable`]). [`callees`] prints how many of a run's
/// mentions are in that position, so the number this check verified in full
/// is never inferred from the number it looked at.
fn callee_problems(item: &str, modules: &HashMap<String, String>) -> Vec<String> {
  let mut problems = Vec::new();
  let (comments, body) = split_comments(item);
  for (path, name) in assertive_mentions(&comments) {
    if let Some(reason) = exemption_reason(&comments, &path) {
      if reason.trim().is_empty() {
        problems.push(format!(
          "`{path}` is exempted without a reason after the em dash — an \
           exemption is a statement, and one that says nothing is silence"
        ));
      }
      continue;
    }
    if matches!(module_half(modules, &path), ModuleHalf::Absent) {
      let module = path.rsplit("::").nth(1).unwrap_or_default();
      problems.push(format!(
        "the comment names `{path}`, asserting `{name}` is the one from \
         `{module}`, but `{module}` never names `{name}`.\n  \
         Name the module that declares it, or — if the mention is deliberate \
         contrast — mark it:\n  \
         `// gate-exempt: {path} — <why this path is written this way>`"
      ));
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

/// The path-qualified mentions in `comments` that sit on an ASSERTIVE
/// sentence — one that also carries one of [`ASSERTIVE_VERBS`] — as
/// `(path, name)`.
///
/// Splits `comments` into flowing [`prose`], then that prose into
/// [`sentences`], keeps only the sentences [`has_assertive_verb`] admits, and
/// runs [`path_qualified_mentions`] over each of THOSE — never over a
/// non-assertive sentence, so a mention there is invisible to this check by
/// construction rather than found and then set aside.
fn assertive_mentions(comments: &str) -> Vec<(String, String)> {
  let text = prose(comments);
  sentences(&text)
    .into_iter()
    .filter(|sentence| has_assertive_verb(sentence))
    .flat_map(path_qualified_mentions)
    .collect()
}

/// `comments` flattened to continuous prose: each line's `//`, `///`, or
/// `//!` prefix stripped, blank lines dropped, and the survivors rejoined
/// with a single space.
///
/// [`assertive_mentions`] needs this because `comments` (as
/// [`split_comments`] returns it) keeps each line's own prefix — a sentence
/// that word-wraps across two `///` lines has that second line's `///`
/// sitting, still attached, in the middle of the flowing text. Fine for
/// [`path_qualified_mentions`]'s backtick-pairing, which does not care what
/// sits between a pair, but fatal for [`sentences`] and a verb search, which
/// read the text as a human does and would otherwise see a literal `///`
/// where a space belongs.
fn prose(comments: &str) -> String {
  let mut out = String::new();
  for line in comments.lines() {
    let trimmed = line.trim_start();
    let stripped = trimmed
      .strip_prefix("///")
      .or_else(|| trimmed.strip_prefix("//!"))
      .or_else(|| trimmed.strip_prefix("//"))
      .unwrap_or(trimmed)
      .trim();
    if stripped.is_empty() {
      continue;
    }
    if !out.is_empty() {
      out.push(' ');
    }
    out.push_str(stripped);
  }
  out
}

/// Splits `text` into sentences.
///
/// A `.`, `!`, or `?` ends a sentence when a whitespace character follows it
/// immediately AND what comes after that whitespace is either nothing or an
/// uppercase letter. Approximate rather than a real grammar — this crate's
/// own "deliberately loose" rule applied to punctuation instead of identifier
/// search — but the two conditions together are what keep it from splitting
/// `§9.3`, `9.3.6`, or `HTTP/1.0` mid-number: none of those periods has
/// whitespace immediately after it, so the check never even reaches the
/// case-of-the-next-word question for them.
fn sentences(text: &str) -> Vec<&str> {
  let bytes = text.as_bytes();
  let mut out = Vec::new();
  let mut start = 0usize;
  for (i, &byte) in bytes.iter().enumerate() {
    if byte != b'.' && byte != b'!' && byte != b'?' {
      continue;
    }
    let end = i + 1;
    let rest = &text[end..];
    let starts_with_ws = rest.starts_with(char::is_whitespace);
    if !starts_with_ws && !rest.is_empty() {
      continue;
    }
    let after_ws = rest.trim_start();
    let is_boundary = after_ws.is_empty() || after_ws.starts_with(char::is_uppercase);
    if is_boundary {
      let sentence = text[start..end].trim();
      if !sentence.is_empty() {
        out.push(sentence);
      }
      start = end;
    }
  }
  let tail = text[start..].trim();
  if !tail.is_empty() {
    out.push(tail);
  }
  out
}

/// The verbs (or verb phrases) that turn a path-qualified mention into a
/// checkable CLAIM — "this is what runs here" — rather than a cross-reference
/// to a neighbour. Closed and printed here, not left for a reader to
/// reconstruct from behavior — the same lesson `verdicts`'s em-dash rule
/// already learned (Task 6).
///
/// Ruling 13's own seed list: `through`, `asks`, `reads`, `calls`, `via`,
/// `uses`, `answered by`. Matched case-insensitively and at a word boundary
/// (via [`names_identifier`]), so `Asks` at a sentence's start still counts
/// and `via` does not fire inside `trivial`.
const ASSERTIVE_VERBS: &[&str] = &[
  "through",
  "asks",
  "reads",
  "calls",
  "via",
  "uses",
  "answered by",
];

/// Whether `sentence` carries one of [`ASSERTIVE_VERBS`], case-insensitively.
fn has_assertive_verb(sentence: &str) -> bool {
  let lower = sentence.to_ascii_lowercase();
  ASSERTIVE_VERBS
    .iter()
    .any(|verb| names_identifier(&lower, verb))
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
  use std::collections::HashMap;

  // The module half `callee_problems` now resolves, as a literal: the crate's
  // real index is built from files, and a unit test that read the filesystem
  // would be pinning the crate's layout rather than this function's rule.
  fn modules(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
      .iter()
      .map(|(name, text)| ((*name).to_string(), (*text).to_string()))
      .collect()
  }

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
    let modules = modules(&[("validate", "pub(crate) fn ends_persistence() {}")]);
    let problems = super::callee_problems(item, &modules);
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
    let modules = modules(&[("validate", "pub(crate) fn ends_persistence() {}")]);
    assert!(super::callee_problems(item, &modules).is_empty());
  }

  #[test]
  fn an_exemption_without_a_reason_is_itself_a_failure() {
    let item = "\
// gate-exempt: validate::ends_persistence
/// Asks `has_close_option`, NOT `validate::ends_persistence`.
fn switch_or_fault(view: &HeadView<'_>) -> bool { has_close_option(view) }";
    let modules = modules(&[("validate", "pub(crate) fn ends_persistence() {}")]);
    let problems = super::callee_problems(item, &modules);
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

  // Ruling 13: a path-qualified mention alone is not yet a checkable claim.
  // This sentence is exactly the "see also" shape the ruling distinguishes
  // from the original defect's "through `validate::ends_persistence`" —
  // naming a TWIN function over shared grammar, no assertive verb anywhere —
  // so it must produce nothing even though the item's body never uses
  // `ends_persistence` either. Paired with
  // `a_path_qualified_name_the_body_never_uses_is_a_failure` (same unused
  // name, but sitting after `through`), which still fails: the two together
  // pin that assertiveness, not mere non-use, is what this check now keys on.
  #[test]
  fn a_path_qualified_mention_on_a_non_assertive_sentence_is_not_flagged() {
    let item = "\
/// The send-side twin of `validate::ends_persistence`, over the same grammar.
fn open_request(view: &HeadView<'_>) -> bool {
  has_close_option(view)
}";
    let modules = modules(&[("validate", "pub(crate) fn ends_persistence() {}")]);
    assert!(super::callee_problems(item, &modules).is_empty());
  }

  // `sentences` must not treat a section or version number's internal
  // periods as sentence ends — RFC 9110 §9.3.6 and HTTP/1.0 are both common
  // in this crate's comments, and a false split there would separate an
  // assertive verb from a mention that legitimately follows it later in the
  // SAME sentence.
  #[test]
  fn sentences_does_not_split_on_a_section_or_version_number() {
    let text = "RFC 9110 §9.3.6 and HTTP/1.0 both matter here. A new sentence follows.";
    let parts = super::sentences(text);
    assert_eq!(parts.len(), 2);
    assert!(parts[0].contains("§9.3.6"));
    assert!(parts[0].contains("HTTP/1.0"));
  }

  // Case-insensitive (a sentence-initial "Asks" still counts) and
  // word-bounded (`via` must not fire merely because it is a substring of
  // `trivial`) — the same guarantee `names_identifier_requires_a_word_boundary`
  // pins for body-usage, now pinned for the verb search too.
  #[test]
  fn has_assertive_verb_is_case_insensitive_and_word_bounded() {
    assert!(super::has_assertive_verb("Asks the predicate directly."));
    assert!(!super::has_assertive_verb(
      "This is a trivial, obvious detail."
    ));
  }

  // The floor under discovery. Renaming one word of the header substring
  // un-governs the crate's only governed table, and every run after that
  // reports zero tables and zero problems and exits 0 — a check governing
  // nothing while still reporting success. `verdicts` reads the filesystem,
  // so this hands it a crate root whose only table is not a governed one.
  #[test]
  fn a_run_that_governs_no_table_fails() {
    let root = std::env::temp_dir().join(format!("xtask-verdicts-floor-{}", std::process::id()));
    let src = root.join("http1-proto").join("src");
    std::fs::create_dir_all(&src).expect("a scratch crate root");
    std::fs::write(
      src.join("lib.rs"),
      "\
/// | side | verdict |
/// |---|---|
/// | a | GUARDED |
fn f() {}
",
    )
    .expect("a source file whose table is not governed");
    let mut report = Report::new();
    let ran = super::verdicts(&root, &mut report);
    std::fs::remove_dir_all(&root).ok();
    ran.expect("the check itself runs");
    assert_eq!(report.failures.len(), 1);
    assert!(
      report.failures[0].contains("governed nothing"),
      "{}",
      report.failures[0]
    );
    assert!(report.lines[0].contains("0 table(s) checked, 1 problem(s)"));
  }

  // And the other half of that floor: the LIVE table, read from the crate
  // itself. A unit test over literals cannot notice a rename in `tunnel.rs`,
  // which is exactly the edit that empties this check — so this one scans the
  // real file, through the same constant `verdicts` discovers by, and fails
  // the suite when the header stops matching from either side.
  #[test]
  fn the_real_switched_table_is_discovered() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("..")
      .join("http1-proto")
      .join("src")
      .join("connection")
      .join("tunnel.rs");
    let text = std::fs::read_to_string(&path).expect("http1-proto's tunnel.rs");
    let governed: Vec<String> = super::doc_runs(&text)
      .into_iter()
      .filter(|run| run.contains(super::GOVERNED_HEADER))
      .collect();
    assert_eq!(
      governed.len(),
      1,
      "TunnelPhase::Switched's table is the one governed table this crate has"
    );
    assert!(
      governed[0].contains("- **GUARDED** —"),
      "the governed run must be the one carrying the verdict declaration"
    );
    assert!(super::verdict_problems(&governed[0]).is_empty());
  }

  // A cell that opens in lower case yields no verdict, so before this rule it
  // contributed nothing and rule 2 stayed quiet — the declared word was still
  // used by the row above. The vocabulary was opt-in by capitalisation. The
  // count also pins that the HEADER row is not itself read as a row: its last
  // cell names a column, and reading it would make every governed table fail.
  #[test]
  fn a_row_whose_verdict_cell_is_not_a_verdict_is_a_failure() {
    let doc = "\
- **GUARDED** — it asks the close question itself.

| corner | site | verdict |
|---|---|---|
| originate | `open_request` | GUARDED — ok |
| emit | `send_response` | guarded — the same word, in lower case |
";
    let problems = super::verdict_problems(doc);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("no verdict"), "{}", problems[0]);
  }

  // The module half of `module::name` is half the claim, and it was the
  // unverified half: a path naming a module that does not hold the item read
  // exactly like one that does. The body here DOES use `ends_persistence`, so
  // the only thing left to fail on is the module.
  #[test]
  fn a_module_that_does_not_hold_the_name_is_a_failure() {
    let item = "\
/// Decided through `grammar::ends_persistence`, the predicate both modes ask.
fn switch_or_fault(view: &HeadView<'_>) -> bool {
  ends_persistence(view)
}";
    let modules = modules(&[
      ("grammar", "pub(crate) fn token_is_valid() {}"),
      ("validate", "pub(crate) fn ends_persistence() {}"),
    ]);
    let problems = super::callee_problems(item, &modules);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("grammar"), "{}", problems[0]);
  }

  // The boundary that rule leaves, pinned rather than described: a module
  // this crate does not declare cannot be resolved here, so the mention is
  // checked on its final segment only — and `callees` counts it, so a run
  // never implies it verified more than it did.
  #[test]
  fn a_module_half_this_crate_does_not_declare_is_unresolvable() {
    let item = "\
/// Reads the field through `core::str::from_utf8` before it commits.
fn f(bytes: &[u8]) {
  from_utf8(bytes);
}";
    let modules = modules(&[("validate", "pub(crate) fn ends_persistence() {}")]);
    assert!(super::callee_problems(item, &modules).is_empty());
    assert!(matches!(
      super::module_half(&modules, "core::str::from_utf8"),
      super::ModuleHalf::Unresolvable
    ));
  }

  // The two ways doc-continuity can fail to produce a set are different facts
  // and must not print the same sentence. A missing nightly is a boundary and
  // skips; anything else — a crate that does not build, most often — is a
  // failure carrying the tool's own words, and a failure is fatal with or
  // without --require-all.
  #[test]
  fn a_rustdoc_failure_is_fatal_where_a_toolchain_skip_is_not() {
    let mut skipped = Report::new();
    skipped.skip(
      "doc-continuity",
      "requires nightly rustdoc --output-format json",
    );
    assert!(skipped.finish(false).is_ok());
    let mut failed = Report::new();
    failed.fail("doc-continuity could not run: the crate did not build");
    assert!(failed.finish(false).is_err());
  }

  // What that failure quotes: the TAIL of the tool's output, indented, blank
  // lines dropped — cargo prints its summary error last, and a build log's
  // opening lines are progress rather than diagnosis.
  #[test]
  fn indented_tail_keeps_the_last_lines_and_indents_them() {
    let text = "first\n\n  \nsecond\nthird\n";
    assert_eq!(
      super::indented_tail(text),
      "    first\n    second\n    third"
    );
    let long: String = (0..20).map(|n| format!("line {n}\n")).collect();
    let tail = super::indented_tail(&long);
    assert_eq!(tail.lines().count(), 12);
    assert!(tail.starts_with("    line 8"));
  }
}
