//! `cargo run -p xtask -- auth-diff <base> [head]` — the differential harness
//! behind every claim that a change did or did not move an answer of
//! `http-semantics`'s RFC 9110 §11 authentication fields.
//!
//! # What it does
//!
//! It builds `auth-corpus` — ONE source, always the working tree's — against
//! each of two revisions of `http-semantics`, and diffs the records. Only the
//! crate under test differs between the two runs, so a record that moved is
//! the revision range's doing and nothing else's.
//!
//! It answers three questions:
//!
//! - **Which answers moved**, grouped by what moved about them: the axis
//!   verdict, and how many challenges and how many faults the caller gained or
//!   lost. A range that was meant to move none should print none.
//! - **Did any answer LOSE a challenge or a fault.** The `#challenge` walk's
//!   documented direction is more faults and never fewer challenges, so a loss
//!   is a regression whatever else the range did, and it is reported on its own
//!   line.
//! - **What the axis says**, per corpus and per side: how many inputs hide a
//!   challenge a conforming reading would have shown, how many of those are
//!   excused by a quoted-string that never closes, and how many challenges the
//!   reader shows that no derivation puts there.
//!
//! # Why the digests are here rather than in the corpus
//!
//! Because the number that is worth publishing is a digest of the ANSWER
//! column, taken by the same code on both sides in one run. A digest published
//! out of a harness that is then deleted can never be recomputed by anybody;
//! this one is recomputable from a checkout.
//!
//! # Why a revision is extracted rather than checked out
//!
//! `git archive` writes a tree and touches nothing else: no second worktree to
//! register and leak, no index, no chance of disturbing the caller's checkout.
//! The extracted tree is only ever READ.

use std::{
  collections::BTreeMap,
  env, fs,
  io::{BufRead, BufReader},
  path::{Path, PathBuf},
  process::{Command, Stdio},
};

use crate::sha256::Sha256;

type Error = Box<dyn std::error::Error>;

/// How many example cases are printed for each kind of moved answer.
const EXAMPLES: usize = 4;

/// Runs the corpus at `base` and at `head` (the working tree when `None`) and
/// reports the difference.
pub fn run(base_rev: &str, head_rev: Option<&str>) -> Result<(), Error> {
  let root = crate::workspace_root()?;
  let corpus = root.join("auth-corpus/src");
  if !corpus.join("main.rs").is_file() {
    return Err(format!("{} is missing", corpus.join("main.rs").display()).into());
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
  let base_dump = work.join("base.tsv");
  run_corpus(
    corpus,
    &base_tree,
    &work.join("base-probe"),
    &target,
    &base_dump,
  )?;

  let (head_label, head_tree) = match head_rev {
    Some(rev) => (
      describe(root, rev)?,
      extract(root, rev, &work.join("head-tree"))?,
    ),
    // The working tree, uncommitted edits included — which is the shape this is
    // run in while a change is still being written.
    None => (String::from("working tree"), root.to_path_buf()),
  };
  let head_dump = work.join("head.tsv");
  run_corpus(
    corpus,
    &head_tree,
    &work.join("head-probe"),
    &target,
    &head_dump,
  )?;

  report(
    &describe(root, base_rev)?,
    &base_dump,
    &head_label,
    &head_dump,
  )
}

// ─────────────────────────────── the comparison ──────────────────────────────

/// One side's totals: the digests, the record count per corpus, and the axis.
#[derive(Default)]
struct Side {
  records: usize,
  whole: String,
  answers: String,
  per_corpus: BTreeMap<String, usize>,
  axis: BTreeMap<(String, String), usize>,
}

/// What moved about one answer.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Move {
  axis: String,
  challenges: i64,
  faults: i64,
}

fn report(base_label: &str, base: &Path, head_label: &str, head: &Path) -> Result<(), Error> {
  let mut base_side = Side::default();
  let mut head_side = Side::default();
  let mut moved: BTreeMap<Move, (usize, Vec<String>)> = BTreeMap::new();
  let mut lost_challenges = Vec::new();

  let mut base_lines = BufReader::new(fs::File::open(base)?).lines();
  let mut head_lines = BufReader::new(fs::File::open(head)?).lines();
  let mut base_whole = Sha256::new();
  let mut base_answers = Sha256::new();
  let mut head_whole = Sha256::new();
  let mut head_answers = Sha256::new();

  loop {
    let (Some(left), Some(right)) = (base_lines.next(), head_lines.next()) else {
      if base_lines.next().is_some() || head_lines.next().is_some() {
        return Err("the two runs did not produce the same number of records".into());
      }
      break;
    };
    let (left, right) = (left?, right?);
    base_whole.update(left.as_bytes());
    base_whole.update(b"\n");
    head_whole.update(right.as_bytes());
    head_whole.update(b"\n");

    let left = Record::parse(&left)?;
    let right = Record::parse(&right)?;
    if left.key != right.key {
      return Err(format!("the two runs disagree about the corpus at {}", left.key).into());
    }
    base_answers.update(left.answer.as_bytes());
    base_answers.update(b"\n");
    head_answers.update(right.answer.as_bytes());
    head_answers.update(b"\n");

    left.tally(&mut base_side);
    right.tally(&mut head_side);

    if left.answer != right.answer {
      let challenges = count(right.answer, "Ok[") as i64 - count(left.answer, "Ok[") as i64;
      let faults = count(right.answer, "Err(") as i64 - count(left.answer, "Err(") as i64;
      if challenges < 0 && lost_challenges.len() < EXAMPLES {
        lost_challenges.push(left.key.clone());
      }
      let kind = Move {
        axis: if left.axis == right.axis {
          left.axis.to_owned()
        } else {
          format!("{} -> {}", left.axis, right.axis)
        },
        challenges,
        faults,
      };
      let slot = moved.entry(kind).or_insert_with(|| (0, Vec::new()));
      slot.0 = slot.0.saturating_add(1);
      if slot.1.len() < EXAMPLES {
        slot.1.push(format!(
          "{}\n      {} -> {}",
          left.key, left.answer, right.answer
        ));
      }
    }
  }

  base_side.whole = base_whole.finish();
  base_side.answers = base_answers.finish();
  head_side.whole = head_whole.finish();
  head_side.answers = head_answers.finish();

  println!("corpus: {} records", head_side.records);
  for (name, count) in &head_side.per_corpus {
    println!("  {name}: {count}");
  }
  println!();
  print_side("base", base_label, &base_side);
  print_side("head", head_label, &head_side);

  println!();
  let total: usize = moved.values().map(|(count, _)| *count).sum();
  println!("answers moved: {total}");
  for (kind, (count, examples)) in &moved {
    println!(
      "  {count:>7}  axis {}  challenges {:+}  faults {:+}",
      kind.axis, kind.challenges, kind.faults
    );
    for example in examples {
      println!("      {example}");
    }
  }

  println!();
  if lost_challenges.is_empty() {
    println!("no answer lost a challenge");
  } else {
    println!("ANSWERS LOST A CHALLENGE:");
    for key in &lost_challenges {
      println!("  {key}");
    }
    return Err("the head side hides a challenge the base side showed".into());
  }
  Ok(())
}

/// One record of the dump, borrowed out of the line it was read from.
struct Record<'a> {
  key: String,
  axis: &'a str,
  answer: &'a str,
  corpus: &'a str,
}

impl<'a> Record<'a> {
  fn parse(line: &'a str) -> Result<Self, Error> {
    let mut columns = line.split('\t');
    let (Some(corpus), Some(case), Some(spelling), Some(axis), Some(answer)) = (
      columns.next(),
      columns.next(),
      columns.next(),
      columns.next(),
      columns.next(),
    ) else {
      return Err(format!("a record is not five columns: {line:?}").into());
    };
    Ok(Self {
      key: format!("{corpus}/{spelling}/{case}"),
      axis,
      answer,
      corpus,
    })
  }

  fn tally(&self, side: &mut Side) {
    side.records = side.records.saturating_add(1);
    *side.per_corpus.entry(self.corpus.to_owned()).or_default() += 1;
    if self.axis != "-" {
      *side
        .axis
        .entry((self.corpus.to_owned(), self.axis.to_owned()))
        .or_default() += 1;
    }
  }
}

fn print_side(which: &str, label: &str, side: &Side) {
  println!("{which} ({label})");
  println!("  sha256 of the whole dump:    {}", side.whole);
  println!("  sha256 of the answer column: {}", side.answers);
  for ((corpus, axis), count) in &side.axis {
    println!("  axis {corpus} {axis:<20} {count}");
  }
}

fn count(haystack: &str, needle: &str) -> usize {
  haystack.matches(needle).count()
}

// ────────────────────────────── running a side ───────────────────────────────

/// Builds the corpus against `tree`'s `http-semantics` and writes its dump to
/// `dump`.
fn run_corpus(
  corpus: &Path,
  tree: &Path,
  probe: &Path,
  target: &Path,
  dump: &Path,
) -> Result<(), Error> {
  let http_semantics = tree.join("http-semantics");
  if !http_semantics.join("Cargo.toml").is_file() {
    return Err(format!("{} has no http-semantics crate", tree.display()).into());
  }

  fs::create_dir_all(probe.join("src"))?;
  for source in fs::read_dir(corpus)? {
    let source = source?.path();
    if source.extension().is_some_and(|ext| ext == "rs")
      && let Some(name) = source.file_name()
    {
      fs::copy(&source, probe.join("src").join(name))?;
    }
  }
  fs::write(probe.join("Cargo.toml"), probe_manifest(&http_semantics))?;

  let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
  let status = Command::new(cargo)
    .args(["run", "--quiet", "--release", "--manifest-path"])
    .arg(probe.join("Cargo.toml"))
    .arg("--")
    .arg(dump)
    // The corpus writes its per-corpus counts to stderr; let them through so a
    // long build does not look like a hang.
    .stderr(Stdio::inherit())
    .env("CARGO_TARGET_DIR", target)
    .status()?;
  if !status.success() {
    return Err(
      format!(
        "the corpus did not run against {}: {status}",
        tree.display()
      )
      .into(),
    );
  }
  Ok(())
}

/// The probe's manifest.
///
/// Written rather than copied because the in-tree one inherits from the
/// workspace, and the probe is deliberately NOT in one: it is built beside a
/// checkout it must not modify. The two must state the same dependencies, and a
/// drift between them is a build failure rather than a silent difference.
fn probe_manifest(http_semantics: &Path) -> String {
  let path = http_semantics.display().to_string();
  format!(
    "# @generated by `cargo run -p xtask -- auth-diff`; a scratch copy of\n\
     # auth-corpus/Cargo.toml with the workspace inheritance resolved.\n\
     [package]\n\
     name = \"auth-corpus\"\n\
     version = \"0.0.0\"\n\
     edition = \"2024\"\n\
     \n\
     [dependencies]\n\
     http-semantics = {{ path = {path:?}, default-features = false, features = [\"std\"] }}\n\
     \n\
     [workspace]\n"
  )
}

// ─────────────────────────────── git plumbing ────────────────────────────────

/// Writes `rev`'s tree into `into` and returns it. Read-only with respect to
/// the repository: `git archive` neither registers a worktree nor touches the
/// index.
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
  let dir = env::temp_dir().join(format!("websockit-auth-diff-{}", std::process::id()));
  if dir.exists() {
    fs::remove_dir_all(&dir)?;
  }
  fs::create_dir_all(&dir)?;
  Ok(dir)
}
