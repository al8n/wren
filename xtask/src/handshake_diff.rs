//! `cargo run -p xtask -- handshake-diff <base> [head]` — the differential
//! harness behind every "did this refactor move a verdict?" claim about
//! `websocket-proto`'s handshakes.
//!
//! # What it does
//!
//! It builds `handshake-corpus` — ONE source file, always the working tree's —
//! against each of two revisions of `websocket-proto`, and diffs the records.
//! Only the crate under test differs between the two runs, so a record that
//! moved is the revision range's doing and nothing else's.
//!
//! It answers two questions:
//!
//! - **Which verdicts moved**, grouped by `(role, field, reason)`. A refactor
//!   that was meant to move none should print none; one that was meant to move a
//!   named set should print that set and nothing beside it.
//! - **Do equivalent spellings still agree** — the corpus marks the cases that
//!   are one logical field value written several ways (RFC 9110 §5.2/§5.3, RFC
//!   6455 §9.1's "MAY be split or combined across multiple lines"), and a group
//!   whose members disagree is a reader making a distinction the grammar does
//!   not. That defect has been found in this crate three times, always between a
//!   gate and a reader that resolved one field separately; a violation ON THE
//!   HEAD SIDE fails the command.
//!
//! # Why a revision is extracted rather than checked out
//!
//! `git archive` writes a tree and touches nothing else: no second worktree to
//! register and leak, no index, no chance of disturbing the caller's checkout.
//! The extracted tree is only ever READ — the corpus and its manifest are
//! written beside it, never into it.
//!
//! The work directory is `$TMPDIR`; both sides share one Cargo target directory
//! under it, and the whole thing is removed on the way out.

use std::{
  collections::{BTreeMap, BTreeSet},
  env, fs,
  path::{Path, PathBuf},
  process::{Command, Stdio},
};

type Error = Box<dyn std::error::Error>;

/// One corpus record: the verdict, and the equivalence group the case belongs to
/// (`None` when it carries no equivalence claim).
#[derive(PartialEq, Eq)]
struct Record {
  group: Option<String>,
  outcome: String,
  detail: String,
}

/// The corpus keyed by `(role, field, case)`.
type Records = BTreeMap<(String, String, String), Record>;

/// Runs the corpus at `base` and at `head` (the working tree when `None`) and
/// reports the difference.
pub fn run(base_rev: &str, head_rev: Option<&str>) -> Result<(), Error> {
  let root = crate::workspace_root()?;
  let corpus = root.join("handshake-corpus/src/main.rs");
  if !corpus.is_file() {
    return Err(format!("{} is missing", corpus.display()).into());
  }

  let work = work_dir()?;
  let result = compare(&root, &corpus, &work, base_rev, head_rev);
  // The work directory is this command's alone, so removing it cannot take
  // anything else with it; a failure to remove is not a failure of the run.
  let _ = fs::remove_dir_all(&work);
  result
}

fn compare(
  root: &Path,
  corpus: &Path,
  work: &Path,
  base_rev: &str,
  head_rev: Option<&str>,
) -> Result<(), Error> {
  let target = work.join("cargo-target");

  let base_tree = extract(root, base_rev, &work.join("base-tree"))?;
  let base = read_corpus(corpus, &base_tree, &work.join("base-probe"), &target)?;

  let (head_label, head_tree) = match head_rev {
    Some(rev) => (
      describe(root, rev)?,
      extract(root, rev, &work.join("head-tree"))?,
    ),
    // The working tree, uncommitted edits included — which is the shape this is
    // run in while a refactor is still being written.
    None => (String::from("working tree"), root.to_path_buf()),
  };
  let head = read_corpus(corpus, &head_tree, &work.join("head-probe"), &target)?;

  report(&describe(root, base_rev)?, &base, &head_label, &head)
}

/// Prints the comparison; `Err` when the head side broke an equivalence group.
fn report(base_label: &str, base: &Records, head_label: &str, head: &Records) -> Result<(), Error> {
  println!("corpus: {} cases", head.len());

  let base_groups = equivalence_violations(base);
  let head_groups = equivalence_violations(head);
  println!("equivalence groups: {} claimed", group_count(head));
  // The base side's violations are what the range FIXED, so they are named as
  // well: a range that claims to have unified a reader is answered here.
  print_violations("base", base_label, &base_groups);
  print_violations("head", head_label, &head_groups);

  // A key on one side only means the two runs did not measure the same corpus —
  // impossible while both sides are built from one source file, so it is
  // reported as a fault of the harness rather than as a moved verdict.
  let only_base: Vec<_> = base.keys().filter(|key| !head.contains_key(*key)).collect();
  let only_head: Vec<_> = head.keys().filter(|key| !base.contains_key(*key)).collect();
  if !only_base.is_empty() || !only_head.is_empty() {
    return Err(
      format!(
        "the two runs disagree about the corpus: {} case(s) only in base, {} only in head",
        only_base.len(),
        only_head.len()
      )
      .into(),
    );
  }

  // (role, field, reason) -> (count, first case, first detail pair)
  let mut moved: BTreeMap<(String, String, String), (usize, String)> = BTreeMap::new();
  for (key, before) in base {
    let Some(after) = head.get(key) else { continue };
    if before == after {
      continue;
    }
    let reason = format!("{} -> {}", before.outcome, after.outcome);
    let entry = moved
      .entry((key.0.clone(), key.1.clone(), reason))
      .or_insert((0, key.2.clone()));
    entry.0 = entry.0.saturating_add(1);
  }

  let total: usize = moved.values().map(|(count, _)| *count).sum();
  println!("\nmoved verdicts: {total}");
  for ((role, field, reason), (count, example)) in &moved {
    println!("  {count:>4}  {role:<20} {field:<24} {reason}");
    println!("        e.g. {example}");
  }

  if head_groups.is_empty() {
    Ok(())
  } else {
    Err(
      format!(
        "{} equivalence group(s) disagree at {head_label}: \
         spellings of one field value reached different verdicts",
        head_groups.len()
      )
      .into(),
    )
  }
}

/// Names one side's violated groups, and the verdicts its members reached.
fn print_violations(
  side: &str,
  label: &str,
  violations: &BTreeMap<(String, String, String), BTreeSet<String>>,
) {
  println!("  {side}  {label}");
  println!("        {} violation(s)", violations.len());
  for ((role, field, group), verdicts) in violations {
    println!("        {role} {field} {group}");
    for verdict in verdicts {
      println!("          {verdict}");
    }
  }
}

/// How many equivalence groups the corpus claims.
fn group_count(records: &Records) -> usize {
  let mut groups = BTreeSet::new();
  for (key, record) in records {
    if let Some(group) = &record.group {
      groups.insert((key.0.clone(), key.1.clone(), group.clone()));
    }
  }
  groups.len()
}

/// The groups whose members did NOT all reach one verdict, with the verdicts
/// they reached.
fn equivalence_violations(
  records: &Records,
) -> BTreeMap<(String, String, String), BTreeSet<String>> {
  let mut verdicts: BTreeMap<(String, String, String), BTreeSet<String>> = BTreeMap::new();
  for (key, record) in records {
    if let Some(group) = &record.group {
      verdicts
        .entry((key.0.clone(), key.1.clone(), group.clone()))
        .or_default()
        .insert(format!("{}\t{}", record.outcome, record.detail));
    }
  }
  verdicts.retain(|_, answers| answers.len() > 1);
  verdicts
}

// ────────────────────────────── running a side ───────────────────────────────

/// Builds the corpus against `tree`'s `websocket-proto` and parses what it
/// printed.
fn read_corpus(corpus: &Path, tree: &Path, probe: &Path, target: &Path) -> Result<Records, Error> {
  let websocket_proto = tree.join("websocket-proto");
  if !websocket_proto.join("Cargo.toml").is_file() {
    return Err(format!("{} has no websocket-proto crate", tree.display()).into());
  }

  fs::create_dir_all(probe.join("src"))?;
  fs::copy(corpus, probe.join("src/main.rs"))?;
  fs::write(probe.join("Cargo.toml"), probe_manifest(&websocket_proto))?;

  let manifest = probe.join("Cargo.toml");
  let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
  let output = Command::new(cargo)
    .args(["run", "--quiet", "--features", "deflate", "--manifest-path"])
    .arg(&manifest)
    // The corpus writes its case count to stderr; let it through so a long
    // build does not look like a hang.
    .stderr(Stdio::inherit())
    .env("CARGO_TARGET_DIR", target)
    .output()?;
  if !output.status.success() {
    return Err(
      format!(
        "the corpus did not run against {}: {}",
        tree.display(),
        output.status
      )
      .into(),
    );
  }

  parse(&String::from_utf8(output.stdout)?)
}

/// The probe's manifest.
///
/// Written rather than copied because the in-tree one inherits from the
/// workspace, and the probe is deliberately NOT in one: it is built beside a
/// checkout it must not modify. The two must state the same dependencies, and a
/// drift between them is a build failure rather than a silent difference.
fn probe_manifest(websocket_proto: &Path) -> String {
  let path = websocket_proto.display().to_string();
  format!(
    "# @generated by `cargo run -p xtask -- handshake-diff`; a scratch copy of\n\
     # handshake-corpus/Cargo.toml with the workspace inheritance resolved.\n\
     [package]\n\
     name = \"handshake-corpus\"\n\
     version = \"0.0.0\"\n\
     edition = \"2024\"\n\
     \n\
     [features]\n\
     default = []\n\
     deflate = [\"websocket-proto/deflate\"]\n\
     \n\
     [dependencies]\n\
     websocket-proto = {{ path = {path:?}, default-features = false, features = [\"std\"] }}\n\
     rand_core = {{ version = \"0.10\", default-features = false }}\n\
     \n\
     [workspace]\n"
  )
}

fn parse(records: &str) -> Result<Records, Error> {
  let mut out = Records::new();
  for (number, line) in records.lines().enumerate() {
    if line.is_empty() {
      continue;
    }
    let mut columns = line.split('\t');
    let (Some(role), Some(field), Some(case), Some(group), Some(outcome), Some(detail)) = (
      columns.next(),
      columns.next(),
      columns.next(),
      columns.next(),
      columns.next(),
      columns.next(),
    ) else {
      return Err(format!("corpus line {} is not six columns: {line:?}", number + 1).into());
    };
    let record = Record {
      group: (group != "-").then(|| group.to_owned()),
      outcome: outcome.to_owned(),
      detail: detail.to_owned(),
    };
    if out
      .insert((role.to_owned(), field.to_owned(), case.to_owned()), record)
      .is_some()
    {
      return Err(format!("corpus case {role}/{field}/{case} is not unique").into());
    }
  }
  if out.is_empty() {
    return Err("the corpus produced no records".into());
  }
  Ok(out)
}

// ─────────────────────────────── git plumbing ────────────────────────────────

/// Writes `rev`'s tree into `into` and returns it. Read-only with respect to the
/// repository: `git archive` neither registers a worktree nor touches the index.
fn extract(root: &Path, rev: &str, into: &Path) -> Result<PathBuf, Error> {
  fs::create_dir_all(into)?;
  let tarball = into.with_extension("tar");
  git(
    root,
    &[
      "archive",
      "--format=tar",
      &format!("--output={}", tarball.display()),
      rev,
    ],
  )?;
  let status = Command::new("tar")
    .arg("-xf")
    .arg(&tarball)
    .arg("-C")
    .arg(into)
    .status()?;
  if !status.success() {
    return Err(format!("could not unpack {rev}: tar exited with {status}").into());
  }
  fs::remove_file(&tarball)?;
  Ok(into.to_path_buf())
}

/// `<short-sha> <subject>`, so the report names what it compared rather than
/// echoing whatever the caller typed.
fn describe(root: &Path, rev: &str) -> Result<String, Error> {
  let output = Command::new("git")
    .arg("-C")
    .arg(root)
    .args(["log", "-1", "--format=%h %s", rev])
    .output()?;
  if !output.status.success() {
    return Err(format!("{rev} is not a revision in this repository").into());
  }
  Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn git(root: &Path, args: &[&str]) -> Result<(), Error> {
  let status = Command::new("git")
    .arg("-C")
    .arg(root)
    .args(args)
    .status()?;
  if !status.success() {
    return Err(format!("git {} exited with {status}", args.join(" ")).into());
  }
  Ok(())
}

/// A private directory under `$TMPDIR` for this run.
fn work_dir() -> Result<PathBuf, Error> {
  let dir = env::temp_dir().join(format!("websockit-handshake-diff-{}", std::process::id()));
  if dir.exists() {
    fs::remove_dir_all(&dir)?;
  }
  fs::create_dir_all(&dir)?;
  Ok(dir)
}
