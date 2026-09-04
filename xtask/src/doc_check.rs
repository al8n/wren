//! Checks over the claims this workspace's documentation makes.
//!
//! `quote-check`'s sibling, and split from it at the toolchain seam rather than
//! by subject: one of these five needs rustdoc's JSON output, which is
//! nightly-only, and the other four run on any toolchain. Running the four it
//! can and SAYING it skipped the fifth is this crate's rule applied to the
//! command itself — a check that cannot examine something must say so by name.
//!
//! [`unclaimed_snapshots`] is the one that watches the others' SUBJECT rather
//! than their content: [`continuity`], [`verdicts`] and [`callees`] each
//! iterate [`GATED_CRATES`], so a name deleted from that list deletes the
//! iteration that would have examined it, and the run gets shorter and stays
//! green. A directory walk is the only set that edit cannot shrink.
//!
//! [`intra_doc_links`] is the newest and takes no list at all, for that same
//! reason one step further: it runs rustdoc over `--workspace` with
//! `--document-private-items`, which is the set no edit here can narrow. It
//! exists because the workspace's `-Dwarnings` doc build denies
//! `rustdoc::broken_intra_doc_links` on the PUBLIC surface only — `cargo doc`
//! documents no private item, so it resolves no private item's links — and
//! this crate is mostly private.
use crate::{
  Error,
  report::{self, Report},
};
use std::{
  collections::{HashMap, HashSet},
  env, fs,
  path::{Path, PathBuf},
  process::Command,
};

/// Runs every documentation check.
pub fn run(require_all: bool, bless: bool) -> Result<(), Error> {
  let mut report = Report::new("doc-check");
  let root = crate::workspace_root()?;
  unclaimed_snapshots(&root, GATED_CRATES, &mut report)?;
  for name in GATED_CRATES {
    continuity(&root, name, bless, &mut report)?;
  }
  verdicts(&root, &mut report)?;
  callees(&root, &mut report)?;
  intra_doc_links(&root, &mut report)?;
  report.finish(require_all)
}

/// The crates whose documented-item sets are compared against a committed
/// snapshot, one snapshot per crate at
/// `xtask/snapshots/<crate>-documented.txt`.
///
/// A LIST rather than a directory walk: a crate added to the workspace and
/// forgotten here would be silently ungated, and a walk would hide that by
/// making the set look automatic. Adding a crate is a deliberate edit, and
/// `the_gated_crate_list_names_every_crate_with_a_snapshot` fails when its
/// snapshot is missing.
///
/// REMOVING one is not a free edit either, and that is the harder direction to
/// hold: any assertion written over this list shrinks along with it, so a check
/// that iterates these names cannot notice a name that is gone. The same test
/// therefore also walks `xtask/snapshots/` — a set this list cannot shorten —
/// and fails on any snapshot no crate here claims, which is exactly what a
/// dropped crate leaves behind.
///
/// [`verdicts`] and [`callees`] scan this same set, so a crate named here is
/// gated by all three checks at once rather than by whichever one its author
/// remembered.
const GATED_CRATES: &[&str] = &["http1-proto", "http-semantics"];

/// Fails when `xtask/snapshots/` holds a snapshot no crate in `gated` claims.
///
/// This is [`GATED_CRATES`]'s own doc comment made executable, and the
/// direction it names as the harder one: every other check in this command
/// ITERATES that list, so deleting an entry deletes the iteration that would
/// have examined it. The crate silently loses [`continuity`], [`verdicts`]
/// and [`callees`] at once — three checks — its snapshot stays committed and
/// unread, and the run still prints success over the shorter set. A directory
/// walk is the only set an edit to the list cannot shrink, so the walk is
/// what asks the question.
///
/// `the_gated_crate_list_names_every_crate_with_a_snapshot` asserts the same
/// thing over the real tree, and that is not this being written twice. The
/// test fails in `cargo test -p xtask`; this fails in the BINARY, which is
/// what the docs workflow runs and what a developer runs by hand. A gate
/// audible only from a different job is one whose message never reaches the
/// person who broke it, and the removal it catches is exactly the edit that
/// makes every list-driven assertion get shorter and stay green.
///
/// Recorded on `report` rather than returned as an `Err`, for the reason
/// [`gated_files`] gives: an `Err` here would discard the whole report,
/// including whatever [`continuity`] has to say about the same
/// misconfiguration. It fails under `--bless` too — blessing writes a
/// snapshot for a gated crate and cannot delete one for a crate that is no
/// longer gated, so it is not a way past this.
///
/// `gated` is a parameter rather than [`GATED_CRATES`] read directly, so a
/// test can hand it a list it controls. Reading the constant here would make
/// every test of this function a test of the live workspace, which is the
/// one thing it must not need in order to fail.
fn unclaimed_snapshots(root: &Path, gated: &[&str], report: &mut Report) -> Result<(), Error> {
  let dir = root.join("xtask/snapshots");
  let entries = match fs::read_dir(&dir) {
    Ok(entries) => entries,
    Err(err) => {
      report.fail(format!(
        "doc-snapshots: could not read {}: {err}.\n  \
         That directory is where every gated crate's committed snapshot lives, \
         so a run that cannot read it has not checked the continuity of any of \
         them — `continuity` will say so per crate, and this says the set \
         itself was unreachable.",
        dir.display()
      ));
      return Ok(());
    }
  };
  // Both failure shapes below feed `unclaimed`, because both are the same
  // fact about the file: nothing in `gated` reads it. An orphan is not read
  // because its crate left the list; a misnamed file is not read because no
  // crate name spells that path. One counter, one meaning.
  let (mut found, mut unclaimed) = (0usize, 0usize);
  for entry in entries {
    // Recorded rather than returned, exactly as the failures below are: an
    // `Err` out of this loop would discard the whole report over one
    // unreadable directory entry.
    let path = match entry {
      Ok(entry) => entry.path(),
      Err(err) => {
        unclaimed += 1;
        report.fail(format!(
          "doc-snapshots: an entry of {} could not be read: {err}.\n  \
           An entry this walk cannot see is one it cannot say is claimed, so \
           it is counted with the unclaimed rather than passed over.",
          dir.display()
        ));
        continue;
      }
    };
    if path.extension().and_then(std::ffi::OsStr::to_str) != Some("txt") {
      continue;
    }
    found += 1;
    let stem = path
      .file_stem()
      .and_then(std::ffi::OsStr::to_str)
      .unwrap_or_default()
      .to_owned();
    let Some(name) = stem.strip_suffix("-documented") else {
      unclaimed += 1;
      report.fail(format!(
        "doc-snapshots: {} is not named `<crate>-documented.txt`.\n  \
         `continuity` builds a snapshot path from a crate name, so a file \
         spelled any other way is never read by anything — it is a snapshot \
         nobody compares against, which is the same defect as an orphan with \
         a tidier name.",
        path.display()
      ));
      continue;
    };
    if gated.contains(&name) {
      continue;
    }
    unclaimed += 1;
    report.fail(format!(
      "doc-snapshots: `{name}` has a committed snapshot at {} that no crate in \
       `GATED_CRATES` claims.\n  \
       A crate dropped from that list keeps its snapshot and stops being read \
       against it, losing doc-continuity, table-verdicts and path-qualified \
       callee in one edit — and every check that iterates the list simply gets \
       shorter, so nothing else in this command would have said a word.\n  \
       Either put `{name}` back in `GATED_CRATES`, or delete that snapshot \
       along with it.",
      path.display()
    ));
  }
  report.checked(format!(
    "doc-snapshots: {found} committed snapshot(s), {unclaimed} claimed by no \
     crate in GATED_CRATES ({})",
    gated.join(", ")
  ));
  Ok(())
}

/// Fails when an item in `crate_name` that had a doc comment no longer does.
///
/// Compares the currently-documented set against a committed snapshot rather
/// than requiring every item to be documented: `http1-proto` has a real
/// backlog of undocumented items today, so "every item must be documented"
/// is not an available rule. A delta is — "no item that had a doc has lost
/// one" — and the snapshot puts the loss in the diff, where a reviewer sees
/// it without running anything.
///
/// One call per crate in [`GATED_CRATES`], each naming its crate in every
/// line it prints, so a failure says which snapshot moved and a run that
/// examined one crate cannot be read as having examined both.
///
/// What this does NOT detect: a doc comment that got shorter, wrong, or had
/// a paragraph cut out of it while at least one line survives. The
/// comparison is presence/absence of `docs` on an item, not a text diff —
/// proven while building this check, not assumed: deleting one line out of a
/// multi-line doc comment left `docs` non-empty and produced no failure, and
/// only removing an item's entire doc block did. A doc that is damaged
/// rather than gone is invisible here.
fn continuity(
  root: &Path,
  crate_name: &str,
  bless: bool,
  report: &mut Report,
) -> Result<(), Error> {
  let path = root
    .join("xtask/snapshots")
    .join(format!("{crate_name}-documented.txt"));
  let current = match documented_items(root, crate_name)? {
    RustdocJson::Items(items) => items,
    RustdocJson::Unavailable(why) => {
      report.skip(&format!("doc-continuity[{crate_name}]"), &why);
      return Ok(());
    }
    RustdocJson::Failed(what) => {
      report.fail(what);
      return Ok(());
    }
  };
  // Printed on every real run, success included: a counted blind spot in the
  // tool's own output is the point, not a fact that only lives in a report.
  let collision_note = current.collision_note();
  if bless {
    let mut body = format!(
      "# Documented items in {crate_name}. Regenerate with:\n\
       #   cargo run -p xtask -- doc-check --bless\n\
       # A line REMOVED by --bless means this change dropped documentation.\n"
    );
    for item in &current.paths {
      body.push_str(item);
      body.push('\n');
    }
    fs::write(&path, body)?;
    report.checked(format!(
      "doc-continuity[{crate_name}]: blessed {} documented items ({collision_note})",
      current.items
    ));
    return Ok(());
  }
  let snapshot: Vec<String> = fs::read_to_string(&path)
    .map_err(|err| {
      format!(
        "doc-continuity[{crate_name}] could not read {}: {err}.\n  \
         A gated crate with no snapshot yet is blessed into one with \
         `cargo run -p xtask -- doc-check --bless`.",
        path.display()
      )
    })?
    .lines()
    .filter(|line| !line.starts_with('#') && !line.is_empty())
    .map(str::to_string)
    .collect();
  // The snapshot is this check's SUBJECT, and an empty one is not an empty
  // result — it is no subject at all. `lost_docs` is one-directional, so a
  // snapshot truncated to nothing reports zero lost items over however many the
  // crate currently documents, and the line below would print a healthy
  // denominator for a comparison against nothing. The same shape as
  // `verdicts`'s `tables == 0` floor, one file over.
  if snapshot.is_empty() {
    report.fail(format!(
      "doc-continuity[{crate_name}]: {} holds no items.\n  \
       A gated crate's snapshot is what this check compares against; empty, it \
       can lose nothing, and every later run reports zero lost over whatever \
       the crate documents today. Restore it, or bless a fresh one with \
       `cargo run -p xtask -- doc-check --bless`.",
      path.display()
    ));
  }
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
    "doc-continuity[{crate_name}]: {} documented items against {} snapshotted, \
     {} lost ({collision_note})",
    current.items,
    snapshot.len(),
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
  /// How many documented items there were BEFORE that deduplication — the
  /// honest denominator, and the one [`continuity`] prints. It exceeds
  /// `paths.len()` by exactly the number of items the snapshot cannot hold a
  /// separate line for, so the two numbers printed together are the
  /// collision count's own arithmetic rather than a claim to be taken on
  /// faith.
  items: usize,
  /// How many of `paths` were reached by more than one distinct item id.
  ///
  /// [`walk_item`] spells a path from names and normalized impl arguments,
  /// not from full type identity, so two items that differ only in something
  /// the spelling drops still collapse onto one string. #62's two shapes — a
  /// private field beside its same-named accessor, and one method name in two
  /// differently-parameterized impls — are spelled apart now; what remains
  /// is: two trait impls of one self type providing the same method name (the
  /// trait is not in the path, so `<Foo as Display>::fmt` and
  /// `<Foo as Debug>::fmt` are both `Foo::fmt`); two types with the same
  /// final path segment used as impl arguments; an argument shape
  /// [`type_name`] renders as `_`; and a module and a function sharing one
  /// name in a parent module, which sit in different namespaces and so are
  /// legal Rust.
  ///
  /// A doc lost from one member of such a group is invisible to
  /// [`continuity`]: the path stays in `paths` because a sibling still has a
  /// doc, so nothing here can report it. Which is why this is counted and
  /// PRINTED rather than filed away — see
  /// [`DocumentedItems::collision_note`].
  collisions: usize,
}

impl DocumentedItems {
  /// The blind spot this run leaves, in the words [`continuity`] prints
  /// beside its result — on success as much as on failure.
  ///
  /// Zero collisions gets a sentence of its own rather than an empty string.
  /// A check that prints nothing when it found nothing reads exactly like a
  /// check that never looked, and telling those two apart is the whole reason
  /// this command exists; so the zero case still names the denominator it
  /// compared and states, in as many words, that nothing collapsed.
  fn collision_note(&self) -> String {
    let paths = self.paths.len();
    match self.collisions {
      0 => format!("{paths} distinct paths, none reached by more than one item"),
      collisions => format!(
        "{paths} distinct paths, {collisions} reached by more than one item — a loss on one \
         member of a group is not visible here"
      ),
    }
  }
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
  walk_item(
    root_id,
    "",
    Join::Path,
    index,
    &mut visited,
    &mut documented,
  );
  documented.sort_by(|a, b| a.1.cmp(&b.1));

  let items = documented.len();
  let mut paths = Vec::with_capacity(items);
  let mut collisions = 0usize;
  for group in documented.chunk_by(|a, b| a.1 == b.1) {
    if group.len() > 1 {
      collisions += 1;
    }
    paths.push(group[0].1.clone());
  }
  Ok(RustdocJson::Items(DocumentedItems {
    paths,
    items,
    collisions,
  }))
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

/// The rustdoc flags [`intra_doc_links`]'s pass runs under, set rather than
/// inherited.
///
/// SET, because the ambient value is what hid the defect this check exists
/// for: `RUSTDOCFLAGS` leaking out of a shell was the only reason the dangling
/// link was ever seen, and a gate whose answer depends on the caller's
/// environment is not a gate. `Command::env` replaces the variable for the
/// child, so this run asks the same question from CI, from a developer's
/// shell, and from a shell that happens to export something else.
///
/// ONE lint rather than `-Dwarnings`, and the boundary is deliberate. rustdoc
/// has other lints that fire on private items and each is its own backlog with
/// its own argument: run this same pass with `RUSTDOCFLAGS` set to
/// `-W rustdoc::all` and `redundant_explicit_link` alone warns twelve times, plus one
/// `missing_crate_level_docs`. This check's name is the whole of what it
/// denies, so a green run here says exactly one thing and does not imply the
/// others.
const PRIVATE_DOC_RUSTDOCFLAGS: &str = "-D rustdoc::broken_intra_doc_links";

/// Fails when an intra-doc link does not resolve — over the workspace's
/// PRIVATE items as well as its public ones.
///
/// # The hole this closes
///
/// CI already documents the workspace under `RUSTDOCFLAGS: --cfg docsrs
/// -Dwarnings`, so `rustdoc::broken_intra_doc_links` is denied there. But
/// `cargo doc` does not document PRIVATE items, and rustdoc resolves links
/// only in the items it documents — so that denial covers the public surface
/// and nothing else. A dangling `[is_mechanism]` written onto a private item
/// in `http-semantics/src/range/multipart.rs` — a file that is almost entirely
/// private, as much of that crate is — passed that build, and was seen only
/// because an ambient `RUSTDOCFLAGS` leaked into [`documented_items`]'s own
/// `--document-private-items` pass. The green was narrower than the name: "no
/// broken doc links" meant "no broken doc links where a doc link was
/// documented".
///
/// Turning it on found sixteen, in five of the workspace's nine crates.
///
/// # Why not [`documented_items`]'s pass, which already carries the flag
///
/// It was the cheaper place and it is the wrong one, for three reasons that
/// each show up in the numbers above. That pass iterates [`GATED_CRATES`], two
/// crates holding three of the sixteen; the other thirteen are outside it and
/// a lint carried there would still be green on them. It needs nightly
/// and SKIPS without it, so the stable `docs.yml` job would carry none of this.
/// And its failure arm says "The crate most likely does not build" — a true
/// sentence about a build failure and a false one about a lint, which is one
/// exit code standing for two different facts, the shape this command exists
/// to remove.
///
/// # What decides it, and what only describes it
///
/// The VERDICT is `cargo`'s exit status and nothing else. [`unresolved_links`]
/// reads rustdoc's wording to name the sites, and a matcher over another
/// tool's output is a guess — the same argument [`nightly_runs`] makes. So a
/// rustdoc that reworded its diagnostic costs this check its per-site
/// messages and cannot cost it the failure: a non-zero exit with nothing
/// matched is reported as a failure that names what it could not parse, never
/// as a pass.
///
/// `--keep-going` so one crate's denied lint does not stop the workspace and
/// leave the rest unexamined; the run reports every site it found rather than
/// the first crate's.
fn intra_doc_links(root: &Path, report: &mut Report) -> Result<(), Error> {
  let members = workspace_members(root)?;
  let output = Command::new("cargo")
    .current_dir(root)
    .env("RUSTDOCFLAGS", PRIVATE_DOC_RUSTDOCFLAGS)
    .args([
      "doc",
      "--workspace",
      "--all-features",
      "--no-deps",
      "--document-private-items",
      "--keep-going",
    ])
    .output()
    .map_err(|err| format!("could not run cargo doc: {err}"))?;
  let stderr = String::from_utf8_lossy(&output.stderr);
  let found = unresolved_links(&stderr);
  for (site, link) in &found {
    report.fail(format!(
      "{site}: unresolved intra-doc link to `{link}`.\n  \
       Give it a path that resolves (`Self::name`, `module::name`, \
       `crate::path::Name`), or escape the brackets as `\\[` and `\\]` where the \
       text is a citation rather than a link."
    ));
  }
  if !output.status.success() && found.is_empty() {
    report.fail(format!(
      "doc-links: `cargo doc --document-private-items` failed and named no \
       unresolved link.\n  \
       That is NOT this check's finding: it denies one lint, and a failure it \
       cannot attribute to that lint is a build failure or a rustdoc whose \
       diagnostic no longer reads the way this parses. Either way the run is \
       reported rather than passed.\n  \
       What it printed:\n{}",
      indented_tail(&stderr)
    ));
  }
  report.checked(format!(
    "doc-links: {} workspace crate(s) documented with `--document-private-items` \
     under `{PRIVATE_DOC_RUSTDOCFLAGS}`, {} unresolved link(s)",
    members.len(),
    found.len()
  ));
  Ok(())
}

/// What [`unresolved_links`] reports in place of a `file:line` rustdoc did not
/// print — see that function for why it is not guessed.
const NO_LOCATION: &str = "<rustdoc printed no location>";

/// Every `(site, link)` pair rustdoc named in `stderr`.
///
/// rustdoc prints the diagnostic and the location on two separate lines —
/// ``error: unresolved link to `name` `` then `  --> path:line:col` — so the
/// pair is assembled across them. A diagnostic whose location line never
/// arrives (rustdoc omits it for a doc comment whose span it cannot map, which
/// happens where an outer `///` on a `mod` declaration merges with the file's
/// own `//!`) is still reported, under [`NO_LOCATION`] in place of a site,
/// because a finding this cannot place is still a finding — and a site GUESSED
/// from the last `Documenting <crate>` line cargo printed would be a wrong
/// `file:line` under `--keep-going`'s interleaving, which is worse than none.
///
/// It matches the diagnostic at BOTH levels, `error` and `warning`, though
/// this command only ever runs the lint denied. A pass that ran it as a
/// warning would otherwise report nothing at all and read as clean.
fn unresolved_links(stderr: &str) -> Vec<(String, String)> {
  const HEAD: &str = "unresolved link to `";
  let mut found: Vec<(String, String)> = Vec::new();
  for line in stderr.lines() {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed
      .strip_prefix("error: ")
      .or_else(|| trimmed.strip_prefix("warning: "))
      .and_then(|rest| rest.strip_prefix(HEAD))
      && let Some(link) = rest.strip_suffix('`')
    {
      found.push((NO_LOCATION.to_string(), link.to_string()));
      continue;
    }
    if let Some(site) = trimmed.strip_prefix("--> ")
      && let Some(last) = found.last_mut()
      && last.0 == NO_LOCATION
    {
      last.0 = site.trim().to_string();
    }
  }
  found
}

/// The workspace's own packages, by name, asked of `cargo` rather than read
/// off a list in this file.
///
/// This check's denominator, and the reason it is not a constant: every other
/// check here iterates [`GATED_CRATES`], and [`unclaimed_snapshots`] exists
/// because an edit to that list silently shrinks what a run examines. A gate
/// added to close a too-narrow green must not be given a set that can be
/// narrowed the same way, so the set is `--workspace`'s own and the count is
/// cargo's answer about it.
fn workspace_members(root: &Path) -> Result<Vec<String>, Error> {
  let output = Command::new("cargo")
    .current_dir(root)
    .args(["metadata", "--no-deps", "--format-version", "1"])
    .output()
    .map_err(|err| format!("could not run cargo metadata: {err}"))?;
  if !output.status.success() {
    return Err(
      format!(
        "`cargo metadata --no-deps` failed:\n{}",
        indented_tail(&String::from_utf8_lossy(&output.stderr))
      )
      .into(),
    );
  }
  let text = String::from_utf8_lossy(&output.stdout);
  let value = json::parse(&text).map_err(|err| format!("could not parse cargo metadata: {err}"))?;
  let packages = value
    .get("packages")
    .and_then(json::Value::as_array)
    .ok_or("cargo metadata has no `packages` array")?;
  let mut names: Vec<String> = packages
    .iter()
    .filter_map(|package| package.get("name").and_then(json::Value::as_str))
    .map(str::to_string)
    .collect();
  names.sort();
  if names.is_empty() {
    return Err("cargo metadata named no workspace package".into());
  }
  Ok(names)
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

/// How a child's name attaches to the path of the item that contains it.
///
/// Two variants because two namespaces: a struct's field and a method of the
/// same name are different items that Rust lets coexist, and joining both with
/// `::` gave them one path — see [`walk_item`]'s "Two items, two paths".
#[derive(Clone, Copy)]
enum Join {
  /// `container::name`: a module item, an associated item, an enum variant —
  /// everything Rust itself reaches through `::`.
  Path,
  /// `container.name`: a field of a struct, union, or enum variant, written
  /// the way Rust writes reading one. A tuple field keeps its numeric name,
  /// so it comes out as `Head.0`, which is also how it is read.
  Field,
}

impl Join {
  const fn as_str(self) -> &'static str {
    match self {
      Self::Path => "::",
      Self::Field => ".",
    }
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
/// prefix its children see; an impl block has no name of its own and
/// contributes its self type's arguments in place of one. A local trait
/// implemented for a foreign type (reachable only via the trait's
/// `implementations`, not via any local struct/enum's `impls`) is the one
/// shape this does not reach; `http1-proto` has none today.
///
/// # Two items, two paths
///
/// A path built from names alone is not an identity. Nine paths in
/// `http1-proto` were reached by two documented items each (#62), and a doc
/// comment deleted from one of a pair left the path in the regenerated set
/// and failed nothing — the exact loss [`continuity`] exists to catch. Two
/// spellings tell them apart, and both are applied UNCONDITIONALLY. A
/// discriminator added only where a collision happens to exist today would
/// re-spell a path the day a neighbouring item arrives, and the snapshot is
/// compared line by line, so that re-spelling reads as documentation lost.
///
/// - **A field joins with `.`, everything else with `::`.** `BodyDecoder`'s
///   private `limit` field and the `limit()` that returns it are two items in
///   two namespaces; `BodyDecoder.limit` and `BodyDecoder::limit` are how
///   Rust itself writes that difference, so a snapshot line says which one it
///   means without a legend to look up. The item's kind is the
///   discriminator; field-access syntax is only how it is spelled.
/// - **An impl contributes its self type's arguments**, so
///   `Connection<Server, General>::send_interim` and
///   `Connection<Server, Tunnel>::send_interim` are two lines rather than
///   one. Arguments come from the self type rather than from the impl's own
///   generic parameters: `impl<Ro> Connection<Ro, Tunnel>` declares one
///   parameter and applies two arguments, and it is the arguments that tell
///   it from `impl<Ro> Connection<Ro, General>`. They are re-rendered by
///   [`type_name`] and never passed through raw — see there for why the
///   JSON's own spelling is not stable enough to commit to a snapshot.
fn walk_item(
  id: u64,
  prefix: &str,
  join: Join,
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

  // Read BEFORE the name, because for one kind of item the name is inside it.
  let Some(inner) = item.get("inner").and_then(Value::as_object) else {
    return;
  };
  let Some((kind, body)) = inner.iter().next() else {
    return;
  };

  // A re-export carries `name: null`, and the name it is imported UNDER lives
  // in `inner.use.name` — the alias for `pub use X as Y`, and `X`'s own last
  // segment otherwise. Guarding the push on the top-level `name` alone
  // therefore made every documented re-export invisible to this gate, and
  // `http1-proto`'s `pub use http_semantics::status::Status as SuggestedStatus`
  // is the one that found it: turning a documented enum into a documented
  // re-export moved its six-line doc comment out of the snapshot without
  // removing a line from it, so that prose could be deleted and nothing here
  // would fire. Before the move the same doc surface WAS gated, as
  // `http1_proto::error::SuggestedStatus`, which is the path it is gated under
  // again.
  //
  // A GLOB re-export (`pub use foo::*`) spells its MODULE there rather than any
  // imported name, so its path would name an item that does not exist. Nothing
  // is done about that here: this workspace's only globs are the private
  // `use super::*` in test modules, which carry no doc comment and so never
  // reach the push below. A documented glob is the shape to revisit this for,
  // and a rule written for one that does not exist would be untested.
  let name = item.get("name").and_then(Value::as_str).or_else(|| {
    (kind == "use")
      .then(|| body.get("name"))
      .flatten()?
      .as_str()
  });
  let path = match name {
    Some(name) if prefix.is_empty() => name.to_string(),
    Some(name) => format!("{prefix}{}{name}", join.as_str()),
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

  match kind.as_str() {
    "module" => walk_all(
      as_ids(body.get("items")),
      &path,
      Join::Path,
      index,
      visited,
      documented,
    ),
    "struct" => {
      let struct_kind = body.get("kind");
      let fields = struct_kind
        .and_then(|k| k.get("plain"))
        .and_then(|p| p.get("fields"))
        .or_else(|| struct_kind.and_then(|k| k.get("tuple")));
      walk_all(
        as_ids(fields),
        &path,
        Join::Field,
        index,
        visited,
        documented,
      );
      walk_all(
        as_ids(body.get("impls")),
        &path,
        Join::Path,
        index,
        visited,
        documented,
      );
    }
    "enum" => {
      walk_all(
        as_ids(body.get("variants")),
        &path,
        Join::Path,
        index,
        visited,
        documented,
      );
      walk_all(
        as_ids(body.get("impls")),
        &path,
        Join::Path,
        index,
        visited,
        documented,
      );
    }
    "variant" => {
      let variant_kind = body.get("kind");
      let fields = variant_kind.and_then(|k| k.get("tuple")).or_else(|| {
        variant_kind
          .and_then(|k| k.get("struct"))
          .and_then(|s| s.get("fields"))
      });
      walk_all(
        as_ids(fields),
        &path,
        Join::Field,
        index,
        visited,
        documented,
      );
    }
    "trait" => walk_all(
      as_ids(body.get("items")),
      &path,
      Join::Path,
      index,
      visited,
      documented,
    ),
    "union" => {
      walk_all(
        as_ids(body.get("fields")),
        &path,
        Join::Field,
        index,
        visited,
        documented,
      );
      walk_all(
        as_ids(body.get("impls")),
        &path,
        Join::Path,
        index,
        visited,
        documented,
      );
    }
    "impl" => walk_all(
      as_ids(body.get("items")),
      &format!("{path}{}", impl_arguments(body)),
      Join::Path,
      index,
      visited,
      documented,
    ),
    // Everything else (function, constant, static, macro, assoc_const,
    // assoc_type, struct_field, use, …) is a leaf: it has no children of its
    // own for a doc comment to live on. `use` in particular is deliberately
    // not FOLLOWED to its target, which is a different thing from not being
    // read: its own doc comment is collected above, under the name
    // `inner.use.name` gives it, while `--document-private-items` already makes
    // the TARGET reachable through the module that actually declares it.
    // Following it as well would push the target's items a second time under
    // the importing module's path.
    _ => {}
  }
}

/// Walks every id in `ids`, threading the shared `path` prefix, the way they
/// attach to it, and the traversal state through each.
fn walk_all(
  ids: Vec<u64>,
  path: &str,
  join: Join,
  index: &HashMap<String, json::Value>,
  visited: &mut HashSet<u64>,
  documented: &mut Vec<(u64, String)>,
) {
  for id in ids {
    walk_item(id, path, join, index, visited, documented);
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

/// The `<A, B>` an impl block contributes to the path of every item inside
/// it, or `""` when its self type takes no type or const arguments.
///
/// Read off the impl's SELF TYPE, which is where the arguments that separate
/// two impls of one type live; `body` is the `impl` object out of rustdoc's
/// JSON. An impl whose self type is not a resolved path — `impl Trait for
/// [u8]`, of which `http1-proto` has two — has no argument list to read and
/// contributes nothing, exactly as before #62.
fn impl_arguments(body: &json::Value) -> String {
  arguments(
    body
      .get("for")
      .and_then(|self_type| self_type.get("resolved_path"))
      .and_then(|resolved| resolved.get("args")),
  )
}

/// rustdoc's angle-bracketed argument list rendered as `<A, B>`, or `""` when
/// there is none and when every argument in it is a lifetime.
///
/// Lifetimes are dropped rather than rendered. Two impls of one type cannot
/// differ by lifetime alone, so a lifetime never discriminates anything here,
/// and a lifetime's NAME is exactly the kind of detail an unrelated edit
/// renames — which would re-spell a committed snapshot line into a loss that
/// did not happen. `Items<'a, 'c>` therefore stays `Items::input`, and its
/// accessor is told from the `input` field by [`Join`] instead.
///
/// A generic type parameter's name IS kept — `Connection<Ro, Mo>`,
/// `ParameterisedList<I>` — and the paragraph above is the argument against
/// keeping it, so here is why it loses. The hazard transfers whole: rename
/// `Ro` and every path under every impl that names it re-spells, and
/// [`continuity`] reports each one as a documentation loss that did not
/// happen. Nor is the name load-bearing for telling two items apart. Two
/// impls whose self types differ only in what their parameters are NAMED are
/// one impl and Rust rejects the pair, exactly as for lifetimes, so rendering
/// every parameter as `_` would hold the collision count at zero too.
///
/// What decides it is the other thing a path here has to be: readable by a
/// human diagnosing a lost doc comment. `Connection<Ro, Mo>::poll_event`
/// names the parameters the impl header names, so its reader lands on
/// `impl<Ro, Mo> Connection<Ro, Mo>`; `Connection<_, _>::poll_event` sends the
/// same reader to sort `Connection`'s impl blocks by hand. A lifetime buys
/// nothing on that side of the scale — so it is pure churn and goes — and a
/// parameter name buys the diagnosis. The two renames are not the same event
/// either. A type parameter is renamed by a deliberate edit to a signature,
/// and its bless diff moves every line under that impl in lockstep, which
/// reads as the rename it is; `--bless` is the answer, and the failure message
/// already says so. A lifetime name churns incidentally — elision, a
/// `single_use_lifetimes` fix — with no such signal, and nothing would be the
/// answer to that.
fn arguments(args: Option<&json::Value>) -> String {
  let Some(list) = args
    .and_then(|args| args.get("angle_bracketed"))
    .and_then(|angle| angle.get("args"))
    .and_then(json::Value::as_array)
  else {
    return String::new();
  };
  let rendered: Vec<String> = list
    .iter()
    .filter_map(|arg| {
      arg.get("type").map(type_name).or_else(|| {
        arg.get("const").map(|value| {
          value
            .get("expr")
            .and_then(json::Value::as_str)
            .unwrap_or("_")
            .to_string()
        })
      })
    })
    .collect();
  if rendered.is_empty() {
    String::new()
  } else {
    format!("<{}>", rendered.join(", "))
  }
}

/// One generic argument, spelled for a human reading a snapshot line.
///
/// Only the FINAL segment of a resolved path is kept, because the JSON's own
/// spelling is not stable enough to commit: rustdoc writes the same type as
/// `crate::connection::Tunnel` in one impl of `Connection` and as `Tunnel` in
/// the next, within one crate's output. The final segment is the item's own
/// name, which is the part that does not vary with how rustdoc chose to
/// qualify it — and it is also the part a reader of a failure message needs.
///
/// Deliberately narrow beyond that. `resolved_path` and `generic` are every
/// shape `http1-proto`'s impl self types use today — read out of the JSON,
/// not assumed — `primitive` is the obvious next one and one line, and every
/// other shape renders as `_`. That fallback is not a silent loss: two
/// arguments that both render `_` collapse onto one path, which is precisely
/// what [`DocumentedItems::collisions`] counts and
/// [`DocumentedItems::collision_note`] prints on every run. Reporting the
/// blind spot is this command's rule; growing a renderer for shapes this
/// workspace does not have is not.
fn type_name(ty: &json::Value) -> String {
  let Some((kind, body)) = ty.as_object().and_then(|shape| shape.iter().next()) else {
    return "_".to_string();
  };
  match kind.as_str() {
    "generic" | "primitive" => body.as_str().unwrap_or("_").to_string(),
    "resolved_path" => {
      let name = body
        .get("path")
        .and_then(json::Value::as_str)
        .map_or("_", final_segment);
      format!("{name}{}", arguments(body.get("args")))
    }
    _ => "_".to_string(),
  }
}

/// The last `::`-separated segment of `path`, or all of it when there is no
/// separator.
fn final_segment(path: &str) -> &str {
  path.rsplit_once("::").map_or(path, |(_, name)| name)
}

/// The header substring that marks a table as governed by its own
/// declaration — the whole of this check's discovery rule, named once so
/// [`verdicts`] and the test that pins the real table cannot drift apart.
const GOVERNED_HEADER: &str = "| corner |";

/// Fails when a table with a [`GOVERNED_HEADER`] header uses a verdict word
/// its own declaration does not list, declares a word no row uses, or carries
/// a row whose verdict cell yields no verdict at all — see
/// [`verdict_problems`] — and when a doc comment anywhere else in the scanned
/// set writes one of the words that declaration lists, see "The vocabulary is
/// reserved to the table" below. Fails, too, when NO governed table is found.
///
/// The scanned set is the `src` of every crate in [`GATED_CRATES`], not one
/// crate: the reservation is about a vocabulary, and a vocabulary a second
/// crate may write freely is not reserved. `http1-proto` holds the only
/// governed table today; a crate joining the list is held to it from its
/// first file, which is why the set is widened here rather than a second
/// per-crate copy of this check being written.
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
/// remove, so the floor is under the WHOLE scanned set — zero governed tables
/// across all of [`GATED_CRATES`], not zero in some one crate — and
/// `the_real_switched_table_is_discovered` pins the live table as well: the
/// rename fails the suite instead of emptying the check.
///
/// Scoped to that one header shape rather than every markdown table in the
/// scanned set. SIX other tables live in `http1-proto/src` today —
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
/// `grep -rn -- "|---" http1-proto/src http-semantics/src` — the `src` of
/// each crate in [`GATED_CRATES`] — lists every table in the scanned set,
/// governed one included. It has been wrong twice by being written from
/// memory.
/// `| corner | site | verdict |` is, today, unique to `http1-proto`'s
/// `tunnel.rs`; a second
/// table that states an invariant the same way — declared bullets, a
/// self-policing closing sentence, a table of sites — earns the same header
/// and is picked up here without a code change.
///
/// # The vocabulary is reserved to the table
///
/// The design's §5.2 states three rules; the two above are rules 1 and 2.
/// The third — no comment ELSEWHERE in the crate assigns a DIFFERENT verdict
/// to a site the table names — is implemented here in its exclusive form:
///
/// > a declared verdict word written in a doc run that is not the governed
/// > table's own is a failure.
///
/// No site matching, and none needed. If the vocabulary can appear only
/// inside the table, then no comment outside it can assign a DIFFERENT
/// verdict to a governed site, because no comment outside it can assign a
/// verdict at all — which is also what makes rules 1 and 2 worth more than
/// the table's own internal consistency.
///
/// Three properties of how the words are read, each load-bearing:
///
/// - **They come from the table, never from a constant here.** The
///   vocabulary is whatever the declaration this run just parsed lists. A
///   literal in `xtask` would mean a reworded declaration silently stops
///   being enforced, which is the `tables == 0` defect one level in;
///   `the_reserved_vocabulary_comes_from_the_table_not_a_constant` pins it.
/// - **A caps run is matched WHOLE, never by substring.** `GUARDED` is a
///   prefix of `GUARDED BY A CALLER`, so a substring search reports every
///   legitimate long form as a bare `GUARDED`. [`caps_runs`] reads maximal
///   runs of ALL-CAPS words — the shape [`leading_caps`] already reads a
///   cell's verdict with — and a run has to EQUAL a declared word. The
///   boundary that leaves, stated: a caps run carrying an extra word,
///   `NOT GUARDED`, equals nothing and is not read as a verdict claim.
/// - **The declaration bullets are exempt by construction**, not by a
///   special case. They sit in the same doc run as the table they declare,
///   and the whole of that run is what is skipped —
///   `the_declaration_bullets_are_not_their_own_violation`.
///
/// ## Why not the comparison §5.2 states literally
///
/// Because its candidate set is empty. Measured over `http1-proto/src`
/// before this was built — a census of the corpus on the day it was taken,
/// not a rule, so recount both numbers before reversing the decision:
///
/// - The three declared words occur on exactly **11 lines**, every one of
///   them `connection/tunnel.rs`'s own declaration and rows, and on ZERO
///   lines anywhere else. A check that fires only when some other comment
///   writes `STRUCTURALLY EXCLUDED` about a site the table names would
///   therefore govern nothing — today, and on the #55 defect it would have
///   been written for, where the contradicting comment used no vocabulary
///   word at all.
/// - Matching a row's SITE identifier instead widens the candidate set on
///   the wrong side: the ten identifiers the table names appear in **56 doc
///   comments** outside `tunnel.rs`, nearly all of them ordinary API
///   cross-references, against roughly three that discuss the close
///   invariant. Telling those apart is the fuzzy matching #63 asks a design
///   for, and 56 against 3 is that design's answer — a hard gate on such a
///   ratio reports neighbouring paragraphs and is blessed into silence
///   inside a week.
///
/// ## What still slips through
///
/// A prose PARAPHRASE that contradicts a row without writing a vocabulary
/// word. That is the shape #63 was filed for and this does NOT close it.
/// #55's own defect is the worked example: `SWITCH_AFTER_CLOSE`'s doc
/// described the CONNECT corners as "deliberately excluded because `close`
/// there admits a benign reading a 101's cannot", while
/// `TunnelPhase::Switched`'s table stated the invariant unqualified, with no
/// such exclusion — two documents, one rule, opposite answers. Every word of
/// that prose is lower case, so the reservation above passes over it in
/// silence. A reader who takes this check for "the table and the crate
/// cannot disagree" has been told more than it does.
fn verdicts(root: &Path, report: &mut Report) -> Result<(), Error> {
  let (files, census) = gated_files(root, "table-verdicts", report)?;

  let mut governed: Vec<(String, DocRun)> = Vec::new();
  let mut elsewhere: Vec<(String, DocRun)> = Vec::new();
  for file in &files {
    let text = fs::read_to_string(file)?;
    let display = report::site(file.strip_prefix(root).unwrap_or(file));
    for run in doc_runs(&text) {
      if run.text.contains(GOVERNED_HEADER) {
        governed.push((display.clone(), run));
      } else {
        elsewhere.push((display.clone(), run));
      }
    }
  }

  let mut problems = 0usize;
  let mut vocabulary: Vec<(String, String)> = Vec::new();
  for (display, run) in &governed {
    for problem in verdict_problems(&run.text) {
      problems += 1;
      report.fail(format!("{display}: {problem}"));
    }
    for (offset, verdict) in declarations(&run.text) {
      if !vocabulary.iter().any(|(word, _)| word == verdict) {
        vocabulary.push((
          verdict.to_string(),
          format!("{display}:{}", run.line + offset),
        ));
      }
    }
  }

  let tables = governed.len();
  if tables == 0 {
    problems += 1;
    report.fail(format!(
      "table-verdicts governed nothing: no doc comment under the `src` of {} \
       carries the `{GOVERNED_HEADER}` header this check discovers a governed \
       table by.\n  \
       `TunnelPhase::Switched` in `http1-proto/src/connection/tunnel.rs` is the \
       one this workspace has. If its header was reworded, restore it (or move \
       the wording here); if the table was deliberately removed, remove this \
       check with it.\n  \
       A run reporting zero tables and zero problems is this check governing \
       nothing while still reporting success.",
      GATED_CRATES.join(", ")
    ));
  }

  let mut carrying = 0usize;
  for (display, run) in &elsewhere {
    let mut carried = false;
    for (offset, caps) in caps_runs(&run.text) {
      let Some((_, declared_at)) = vocabulary.iter().find(|(word, _)| *word == caps) else {
        continue;
      };
      carried = true;
      problems += 1;
      report.fail(format!(
        "{display}:{}: the verdict `{caps}` is written in a doc comment outside \
         the table that declares it ({declared_at}).\n  \
         That vocabulary is reserved to the declaring table's own rows: written \
         anywhere else it assigns a verdict to a site without being held to the \
         declaration, which is how a comment comes to contradict the row for the \
         same site.\n  \
         Make this a row in that table, or reword it so it is not claiming a \
         verdict.",
        run.line + offset
      ));
    }
    if carried {
      carrying += 1;
    }
  }

  report.checked(format!(
    "table-verdicts: {tables} table(s) checked, {problems} problem(s); {} declared \
     verdict word(s) reserved to them, {} doc run(s) elsewhere scanned, {carrying} \
     carried one; files scanned: {census}",
    vocabulary.len(),
    elsewhere.len()
  ));
  Ok(())
}

/// Every `.rs` file under `dir`, recursively.
///
/// Every io error names the directory it came from. A Rust io error carries no
/// path, so the bare `?` this used to be surfaced `No such file or directory
/// (os error 2)` as the command's ENTIRE output — a message that cannot be
/// acted on, from a check whose whole subject is saying what it could not
/// reach.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), Error> {
  let entries =
    fs::read_dir(dir).map_err(|err| format!("could not read {}: {err}", dir.display()))?;
  for entry in entries {
    let path = entry
      .map_err(|err| format!("could not read an entry of {}: {err}", dir.display()))?
      .path();
    if path.is_dir() {
      collect_rs_files(&path, out)?;
    } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
      out.push(path);
    }
  }
  Ok(())
}

/// The `.rs` files of every crate in [`GATED_CRATES`], sorted, beside the
/// per-crate census its caller prints.
///
/// **The census is the point, not a decoration.** [`verdicts`] and [`callees`]
/// are per-FILE checks over a SET of crates, and a single merged denominator
/// cannot tell a crate that was scanned and held nothing from a crate that was
/// never reached — the one distinction this whole command exists to print.
/// Reverting the loop below to a single hardcoded directory moves a total no
/// reader has memorised and changes nothing else a green run says; naming each
/// crate beside its own count is what makes that edit visible, and
/// `every_gated_crate_is_scanned_and_counted_by_name` is what makes it fail.
///
/// A crate whose `src` is not there is recorded on `report` as a failure and
/// counted `UNREACHED`, rather than returned as an `Err`. [`Report::finish`]
/// prints nothing until every check has run, so an `Err` from here would
/// discard the whole report — including the message [`continuity`] has already
/// recorded about that same misconfigured crate, which is the one that names
/// the crate and says the snapshot could not be read. Losing a good message to
/// a worse one is the opposite of what a `--require-all` run is for. The scan
/// continues over the crates that ARE there, the run still fails (a recorded
/// failure fails [`Report::finish`]), and the census shows the hole rather
/// than silently shrinking the total.
fn gated_files(
  root: &Path,
  check: &str,
  report: &mut Report,
) -> Result<(Vec<PathBuf>, String), Error> {
  let mut files = Vec::new();
  let mut census: Vec<String> = Vec::new();
  for name in GATED_CRATES {
    let dir = root.join(name).join("src");
    if !dir.is_dir() {
      report.fail(format!(
        "{check}: `{name}` is gated but has no `src` directory at {}.\n  \
         A gated crate with no source is a BROKEN gate, not an empty one: every \
         file this check would have read is missing, and a per-crate count is \
         the only thing in a green run that would have said so.\n  \
         Either the crate moved and this path is stale, or it belongs in \
         `GATED_CRATES` no longer.",
        dir.display()
      ));
      census.push(format!("{name} UNREACHED"));
      continue;
    }
    let before = files.len();
    collect_rs_files(&dir, &mut files)?;
    census.push(format!("{name} {}", files.len() - before));
  }
  files.sort();
  Ok((files, census.join(", ")))
}

/// One maximal doc-comment run, and the 1-based file line its first line
/// sits on.
///
/// The line travels with the text because a failure about a doc comment owes
/// its reader a place to open. A run is joined into one string for matching
/// and is CONTIGUOUS by construction, so `line` plus a 0-based offset within
/// the run is that offset's own file line — which is how [`caps_runs`] and
/// [`declarations`] report positions without re-scanning the file.
struct DocRun {
  line: usize,
  text: String,
}

/// Splits `text` into its maximal contiguous doc-comment runs — `///` or
/// `//!` lines with the marker stripped, joined by `\n`, each carrying the
/// file line it starts on. An ordinary `//` comment or a code line ends a
/// run without starting one; the run it ends is kept and a run still open at
/// EOF is kept too, but an empty run never is.
fn doc_runs(text: &str) -> Vec<DocRun> {
  let mut runs = Vec::new();
  let mut current: Vec<&str> = Vec::new();
  let mut line = 0usize;
  for (offset, raw) in text.lines().enumerate() {
    let trimmed = raw.trim_start();
    let stripped = trimmed
      .strip_prefix("///")
      .or_else(|| trimmed.strip_prefix("//!"));
    match stripped {
      Some(rest) => {
        if current.is_empty() {
          line = offset + 1;
        }
        current.push(rest);
      }
      None if !current.is_empty() => {
        runs.push(DocRun {
          line,
          text: current.join("\n"),
        });
        current.clear();
      }
      None => {}
    }
  }
  if !current.is_empty() {
    runs.push(DocRun {
      line,
      text: current.join("\n"),
    });
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
/// `a_bold_bullet_that_is_not_a_definition_is_not_a_declared_verdict`. The
/// rule itself lives in [`declared_verdict`], because [`verdicts`] reserves
/// the same vocabulary and the two must not be able to disagree about what
/// declares it.
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
  let declared: Vec<String> = declarations(doc)
    .into_iter()
    .map(|(_, verdict)| verdict.to_string())
    .collect();
  let mut used: Vec<String> = Vec::new();
  let mut problems = Vec::new();
  let mut in_body = false;
  for line in doc.lines() {
    let trimmed = line.trim();
    if declared_verdict(trimmed).is_some() {
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

/// Every declaration bullet in `doc`, as the 0-based line offset within
/// `doc` it sits on and the verdict it declares.
fn declarations(doc: &str) -> Vec<(usize, &str)> {
  doc
    .lines()
    .enumerate()
    .filter_map(|(offset, line)| declared_verdict(line).map(|verdict| (offset, verdict)))
    .collect()
}

/// The verdict `line` declares, or `None` when `line` is not a declaration
/// bullet — see [`verdict_problems`] for the shape and why the em dash is
/// part of it.
///
/// One matcher, two readers. [`verdict_problems`] collects the vocabulary a
/// governed table declares; [`verdicts`] reserves that vocabulary to the run
/// it was declared in. A second spelling of the rule in either place would
/// let the two disagree about what a declaration IS, and the one that
/// disagreed downward would stop enforcing without ever failing.
fn declared_verdict(line: &str) -> Option<&str> {
  let rest = line.trim().strip_prefix("- **")?;
  let end = rest.find("**")?;
  rest[end + 2..]
    .trim_start()
    .starts_with('—')
    .then_some(&rest[..end])
}

/// Every maximal run of ALL-CAPS words in `doc`, each with the 0-based line
/// offset within `doc` its first word sits on.
///
/// Runs rather than words, because half this vocabulary is multi-word and
/// `GUARDED` is a PREFIX of `GUARDED BY A CALLER`: a caller that searched
/// word by word would report every legitimate long form as a bare `GUARDED`.
/// A run is handed back whole and compared for equality instead — the same
/// answer [`leading_caps`] gives a table cell, reached the same way.
///
/// A word is stripped of surrounding markup before the test, since
/// `` `GUARDED` ``, `**GUARDED**` and `EXCLUDED.` are one word wearing
/// markdown or punctuation. `_` is deliberately NOT stripped and not a caps
/// character, so a screaming-snake constant — `TAKEOVER_STATES_NO_CLOSE` —
/// breaks a run rather than joining it. A line break does not break a run: a
/// wrapped sentence still says what it says.
fn caps_runs(doc: &str) -> Vec<(usize, String)> {
  let mut runs = Vec::new();
  let mut current: Vec<&str> = Vec::new();
  let mut start = 0usize;
  for (offset, line) in doc.lines().enumerate() {
    for word in line.split_whitespace() {
      let word =
        word.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_');
      if is_caps_word(word) {
        if current.is_empty() {
          start = offset;
        }
        current.push(word);
      } else if !current.is_empty() {
        runs.push((start, current.join(" ")));
        current.clear();
      }
    }
  }
  if !current.is_empty() {
    runs.push((start, current.join(" ")));
  }
  runs
}

/// The leading run of ALL-CAPS words in `cell`.
fn leading_caps(cell: &str) -> String {
  cell
    .split_whitespace()
    .take_while(|word| is_caps_word(word))
    .collect::<Vec<_>>()
    .join(" ")
}

/// Whether `word` is a single ALL-CAPS word: at least one upper-case letter,
/// and nothing in it that is not one or a hyphen.
///
/// The one test behind both readings of the vocabulary — a table cell's
/// leading verdict ([`leading_caps`]) and a verdict written loose in prose
/// ([`caps_runs`]) — so a word cannot be a verdict on one side of the
/// reservation and not the other.
fn is_caps_word(word: &str) -> bool {
  word.chars().any(|ch| ch.is_ascii_uppercase())
    && word.chars().all(|ch| ch.is_ascii_uppercase() || ch == '-')
}

/// Fails when a comment in the `src` of any crate in [`GATED_CRATES`]
/// path-qualifies a callee — `` `module::name` `` — ON AN ASSERTIVE SENTENCE,
/// that the item it documents never uses, or that the named module does not
/// hold; see [`callee_problems`].
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
///   [`ASSERTIVE_VERBS`]** (Ruling 13). Most of these crates' cross-referential
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
  let (files, census) = gated_files(root, "path-qualified callee", report)?;
  let modules = module_index(&files)?;

  let mut mentions = 0usize;
  let mut exempt = 0usize;
  let mut unresolved = 0usize;
  for file in &files {
    let text = fs::read_to_string(file)?;
    let display = report::site(file.strip_prefix(root).unwrap_or(file));
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
     {unresolved} whose module half is none of the scanned crates' to resolve; \
     files scanned: {census}"
  ));
  Ok(())
}

/// Every module the scanned crates — the `src` of each of [`GATED_CRATES`] —
/// declare as a FILE, by leaf name, beside that file's text.
///
/// `foo.rs` and `foo/mod.rs` are both module `foo`; `lib.rs` is a crate root
/// and names no module. Two files that land on the same leaf name — every
/// `tests.rs` in the set, and now any leaf two of the scanned crates both
/// spell — are joined, which errs towards a false PASS, the direction every
/// judgement in this check errs. One index across crates rather than one per
/// crate is that same direction taken deliberately: a mention resolves
/// against a module of the same leaf name in a sibling crate, so the widening
/// can only turn a failure into a pass, never the reverse.
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
  /// The module the scanned set declares under that name does name the item.
  Holds,
  /// It exists, and never names the item — the claim is checkable and false.
  Absent,
  /// No module of the scanned set answers to that name, so nothing here can
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

/// Every `mod NAME` the scanned crates declare — the `src` of each of
/// [`GATED_CRATES`] — leaf name only (no path); see
/// [`qualified_final_segment`].
///
/// A fixed list, not a scan: keeping [`qualified_final_segment`] free of
/// filesystem access is what keeps it a pure function a unit test can call on
/// a literal string, the same way [`KNOWN_MODULES`]'s sibling exclusion
/// ([`is_lint_namespace`]) is. The cost of the fixed list is that a crate
/// joining [`GATED_CRATES`] brings modules this list does not know, so
/// regenerate it over the WHOLE set — reviewing, from the workspace root:
/// `grep -rhoE '(^|[[:space:]])mod [a-z_][a-z0-9_]*' http1-proto/src http-semantics/src | awk '{print $NF}' | sort -u`
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
    *pos += 1; // the opening DQUOTE
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
  use super::{NO_LOCATION, Report, unresolved_links};
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

  // A documented re-export is a documented item, and rustdoc does not put its
  // name where every other item's name is: `name` is null and the name it is
  // imported UNDER lives in `inner.use.name`. Guarding the push on `name` alone
  // made `http1-proto`'s `pub use … as SuggestedStatus` and its doc comment
  // invisible here, so that prose could be deleted with nothing failing.
  //
  // The CONTROL is the half that makes this test mean something: a second `use`
  // with an empty `docs` must NOT be collected. Without it a walk that pushed
  // every item it reached would pass, and the assertion would be about the
  // fixture rather than about the rule.
  #[test]
  fn a_documented_re_export_is_collected_under_its_imported_name() {
    use super::{Join, json, walk_item};
    use std::collections::HashSet;

    let value = json::parse(
      r#"{
        "root": 1,
        "index": {
          "1": {"crate_id": 0, "name": "krate", "docs": "",
                "inner": {"module": {"items": [2, 3]}}},
          "2": {"crate_id": 0, "name": null, "docs": "The status vocabulary.",
                "inner": {"use": {"name": "Alias", "id": 9, "is_glob": false}}},
          "3": {"crate_id": 0, "name": null, "docs": "",
                "inner": {"use": {"name": "Undocumented", "id": 9, "is_glob": false}}}
        }
      }"#,
    )
    .expect("a fixture this test supplies");
    let index = value
      .get("index")
      .and_then(json::Value::as_object)
      .expect("the fixture has an index");

    let mut documented = Vec::new();
    walk_item(
      1,
      "",
      Join::Path,
      index,
      &mut HashSet::new(),
      &mut documented,
    );

    let paths: Vec<&str> = documented.iter().map(|(_, path)| path.as_str()).collect();
    assert!(
      paths.contains(&"krate::Alias"),
      "a documented `pub use X as Alias` joins under its alias: {paths:?}"
    );
    assert!(
      !paths.contains(&"krate::Undocumented"),
      "an UNdocumented re-export is not collected, so this cannot pass by \
       collecting everything: {paths:?}"
    );
  }

  // The spine, as a unit: a skip is a printed boundary on a developer's
  // machine and a FAILURE under --require-all, so a check that only ever runs
  // in one CI job cannot disappear the day that job is edited.
  #[test]
  fn a_skip_is_tolerated_alone_and_fatal_under_require_all() {
    let mut report = Report::new("doc-check");
    report.skip("doc-continuity", "requires nightly rustdoc");
    assert!(report.clone().finish(false).is_ok());
    assert!(report.finish(true).is_err());
  }

  // Task 1's contract: `continuity` names the crate and the snapshot it
  // compares, so a second crate is a second call rather than a second copy of
  // the function. Without this the crate list is a comment, and a crate
  // dropped from it is invisible.
  //
  // The name of this test says SNAPSHOT -> GATED, and that is the direction
  // that catches a drop, so it is asserted first and the crate list is not
  // what it iterates. An assertion driven by `GATED_CRATES` cannot see a
  // removal at all: deleting an entry deletes the iteration that would have
  // examined it, so the check gets shorter and stays green while the crate
  // loses continuity, verdicts and callees at once and its snapshot sits in
  // the tree unread. `xtask/snapshots/` is the set an edit to that list cannot
  // shrink, so it is the one to walk.
  //
  // GATED -> SNAPSHOT stays too, below: it is what the constant's own doc
  // promises, and it is the half that catches the opposite edit, a crate named
  // in the list with nothing committed for it to be compared against.
  //
  // `unclaimed_snapshots` now asks the SNAPSHOT -> GATED half inside the
  // binary as well, and the overlap is deliberate rather than a duplicate:
  // this fails in `cargo test -p xtask`, that one fails in `doc-check` itself
  // — the command the docs workflow runs and the one a developer runs by
  // hand. Deleting either leaves the removal audible from one place only.
  #[test]
  fn the_gated_crate_list_names_every_crate_with_a_snapshot() {
    let root = crate::workspace_root().unwrap();
    let dir = root.join("xtask/snapshots");

    let mut orphaned: Vec<String> = Vec::new();
    let mut claimed = 0usize;
    for entry in std::fs::read_dir(&dir).expect("the snapshot directory") {
      let path = entry.expect("a snapshot directory entry").path();
      if path.extension().and_then(std::ffi::OsStr::to_str) != Some("txt") {
        continue;
      }
      let stem = path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .expect("a snapshot file name")
        .to_owned();
      let name = stem.strip_suffix("-documented").unwrap_or_else(|| {
        panic!("{stem}.txt is in xtask/snapshots but is not named `<crate>-documented.txt`")
      });
      if super::GATED_CRATES.contains(&name) {
        claimed += 1;
      } else {
        orphaned.push(name.to_owned());
      }
    }

    assert!(
      orphaned.is_empty(),
      "{orphaned:?} has a committed snapshot in {} that no crate in GATED_CRATES claims — \
       a crate dropped from that list keeps its snapshot, stops being compared against \
       it, and loses table-verdicts and path-qualified callee along with it",
      dir.display()
    );

    for name in super::GATED_CRATES {
      let snapshot = dir.join(format!("{name}-documented.txt"));
      assert!(
        snapshot.exists(),
        "{name} is gated but has no snapshot at {}",
        snapshot.display()
      );
    }

    assert_eq!(
      claimed,
      super::GATED_CRATES.len(),
      "one snapshot per gated crate, and no gated crate reading a snapshot twice"
    );
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

  // #62, as a fixture: `walk_item` gave a field and its accessor one path,
  // and gave one method name declared in two differently-parameterized impls
  // one path, so a doc deleted from either half failed nothing. The two impls
  // below also spell the SAME types two ways — `crate::c::Server` in one and
  // `Server` in the next — and carry a lifetime argument each, because
  // rustdoc really does vary both within a single crate's JSON and a path
  // that varied with it would fail the snapshot for no reason at all.
  #[test]
  fn a_field_its_accessor_and_an_impl_twin_are_three_paths() {
    let value = super::json::parse(
      r#"{
        "root": 0,
        "index": {
          "0": {"crate_id": 0, "name": "c", "docs": "", "inner": {"module": {"items": [1]}}},
          "1": {"crate_id": 0, "name": "S", "docs": "the struct",
                "inner": {"struct": {"kind": {"plain": {"fields": [2]}}, "impls": [3, 5]}}},
          "2": {"crate_id": 0, "name": "limit", "docs": "the field",
                "inner": {"struct_field": {"primitive": "usize"}}},
          "3": {"crate_id": 0, "name": null, "docs": "", "inner": {"impl": {
                  "for": {"resolved_path": {"path": "crate::c::S", "args": {"angle_bracketed": {
                    "args": [{"lifetime": "'a"},
                             {"type": {"resolved_path": {"path": "crate::c::Server", "args": null}}},
                             {"type": {"resolved_path": {"path": "General", "args": null}}}],
                    "constraints": []}}}},
                  "items": [4]}}},
          "4": {"crate_id": 0, "name": "limit", "docs": "the accessor",
                "inner": {"function": {}}},
          "5": {"crate_id": 0, "name": null, "docs": "", "inner": {"impl": {
                  "for": {"resolved_path": {"path": "S", "args": {"angle_bracketed": {
                    "args": [{"lifetime": "'b"},
                             {"type": {"resolved_path": {"path": "Server", "args": null}}},
                             {"type": {"resolved_path": {"path": "crate::c::Tunnel", "args": null}}}],
                    "constraints": []}}}},
                  "items": [6]}}},
          "6": {"crate_id": 0, "name": "limit", "docs": "the tunnel accessor",
                "inner": {"function": {}}}
        }
      }"#,
    )
    .unwrap();
    let index = value
      .get("index")
      .and_then(super::json::Value::as_object)
      .unwrap();
    let mut visited = std::collections::HashSet::new();
    let mut documented = Vec::new();
    super::walk_item(
      0,
      "",
      super::Join::Path,
      index,
      &mut visited,
      &mut documented,
    );
    let mut paths: Vec<String> = documented.into_iter().map(|(_, path)| path).collect();
    paths.sort();
    assert_eq!(
      paths,
      [
        "c::S",
        "c::S.limit",
        "c::S<Server, General>::limit",
        "c::S<Server, Tunnel>::limit",
      ]
    );
  }

  // A lifetime cannot be what separates two impls of one type, and its name is
  // the kind of detail an unrelated edit renames, so an argument list holding
  // nothing else contributes nothing — `Items<'a, 'c>`'s methods stay
  // `Items::…` and are told from its fields by the field join instead.
  #[test]
  fn an_argument_list_of_only_lifetimes_contributes_nothing() {
    let value = super::json::parse(
      r#"{"angle_bracketed": {"args": [{"lifetime": "'a"}, {"lifetime": "'c"}],
          "constraints": []}}"#,
    )
    .unwrap();
    assert_eq!(super::arguments(Some(&value)), "");
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

  // A governed run in the shape `verdicts` discovers one: the declaration
  // bullets and the table they govern inside ONE doc run, which is what makes
  // the bullets exempt from the reservation without a special case for them.
  const GOVERNED: &str = "\
/// - **GUARDED** — it asks the close question itself.
/// - **GUARDED BY A CALLER** — an earlier gate makes the state unreachable.
/// - **STRUCTURALLY EXCLUDED** — the site cannot reach this state at all.
///
/// | corner | site | verdict |
/// |---|---|---|
/// | originate | `open_request` | GUARDED — ok |
/// | receive | `into_tunnel` | GUARDED BY A CALLER — ok |
/// | emit | `send_response` | STRUCTURALLY EXCLUDED — a 101 is refused |
fn switched() {}
";

  // `verdicts` reads the filesystem, so every test of it needs a crate root
  // on disk. Removed before it is written as well as after: a run killed
  // half way through must not leave a file behind that silently joins what
  // the next run scans.
  //
  // EVERY gated crate gets its `src`, not just the ones the fixture writes
  // files into: `verdicts` scans the whole set, and a crate with no `src` is
  // a reported FAILURE (`gated_files`), so a fixture holding only
  // `http1-proto` would fail every test of this check for that reason instead
  // of the one it was written for.
  fn scratch_crates(name: &str, files: &[(&str, &str, &str)]) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("xtask-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    for gated in super::GATED_CRATES {
      std::fs::create_dir_all(root.join(gated).join("src")).expect("a scratch crate root");
    }
    for (crate_name, file, text) in files {
      std::fs::write(root.join(crate_name).join("src").join(file), text).expect("a source file");
    }
    root
  }

  // The single-crate spelling, for the tests whose subject is one file's
  // content rather than the crate set.
  fn scratch_crate(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let spread: Vec<(&str, &str, &str)> = files
      .iter()
      .map(|(file, text)| ("http1-proto", *file, *text))
      .collect();
    scratch_crates(name, &spread)
  }

  fn verdicts_over(root: &std::path::Path) -> Report {
    let mut report = Report::new("doc-check");
    let ran = super::verdicts(root, &mut report);
    std::fs::remove_dir_all(root).ok();
    ran.expect("the check itself runs");
    report
  }

  // Task 1's OTHER contract, and the one no other test in this file bites on:
  // `verdicts` and `callees` scan a SET of crates. Both halves are asserted
  // here, because either alone leaves the same hole in the other:
  //
  // - that a doc run in a crate after the first is REACHED at all — the
  //   `elsewhere` count; and
  // - that each report line SAYS which crate each file came from — the
  //   census. A merged total cannot distinguish a crate that was scanned and
  //   held nothing from a crate that was never reached, so without the census
  //   a reader has nothing to check and this assertion has nothing to read.
  //
  // Written over `GATED_CRATES` rather than over two literal names, so a
  // crate added to that list is scanned by this test too instead of quietly
  // sitting outside it.
  //
  // Generality over that list has a floor, and it is asserted rather than
  // assumed: with ONE gated crate the loop below writes no second crate, the
  // `elsewhere` count reduces to `0` compared against `0`, and both halves
  // above pass while testing nothing. A test that goes quiet when its subject
  // disappears is the failure this file exists to prevent, so the shrunken
  // list is a loud failure here instead — the fixture cannot be built from a
  // one-crate list, and saying so is more use than a green run over it.
  #[test]
  fn every_gated_crate_is_scanned_and_counted_by_name() {
    assert!(
      super::GATED_CRATES.len() >= 2,
      "both halves of this test need a crate AFTER the first and GATED_CRATES holds {}: \
       the fixture loop below would write one crate, `elsewhere scanned` would read 0 \
       against 0, and the whole test would pass with no second crate to reach",
      super::GATED_CRATES.len()
    );

    let mut files: Vec<(&str, &str, &str)> = vec![(super::GATED_CRATES[0], "tunnel.rs", GOVERNED)];
    for name in &super::GATED_CRATES[1..] {
      files.push((
        name,
        "lib.rs",
        "/// A doc run this scan has to reach.\nfn f() {}\n",
      ));
    }
    let root = scratch_crates("gated-set", &files);

    let mut report = Report::new("doc-check");
    let ran = super::verdicts(&root, &mut report).and_then(|()| super::callees(&root, &mut report));
    std::fs::remove_dir_all(&root).ok();
    ran.expect("both checks run");

    assert!(report.failures.is_empty(), "{:?}", report.failures);
    let census = super::GATED_CRATES
      .iter()
      .map(|name| format!("{name} 1"))
      .collect::<Vec<_>>()
      .join(", ");
    for line in &report.lines {
      assert!(
        line.contains(&format!("files scanned: {census}")),
        "every per-file check must name each gated crate beside its own file count: {line}"
      );
    }
    assert!(
      report.lines[0].contains(&format!(
        "{} doc run(s) elsewhere scanned",
        super::GATED_CRATES.len() - 1
      )),
      "a doc run in each crate after the first must be reached: {}",
      report.lines[0]
    );
  }

  // A gated crate with no `src` is a broken gate, and the report has to
  // SURVIVE saying so. `Report::finish` prints nothing until every check has
  // run, so an `Err` out of `verdicts` would discard the whole report —
  // including `continuity`'s own message about the same misconfigured crate,
  // which is the one that names it. The check's own line stays, with the hole
  // in its census, rather than a total that quietly shrank.
  //
  // Its floor is asserted BEFORE the fixture is written, and as a check rather
  // than as an index: `GATED_CRATES[1]` on a one-crate list is a bounds panic
  // whose message names neither this test's subject nor the edit that broke
  // it, and it would leave the scratch tree behind on the way out.
  #[test]
  fn a_gated_crate_with_no_src_is_reported_and_the_rest_of_the_run_survives() {
    let missing = *super::GATED_CRATES.get(1).unwrap_or_else(|| {
      panic!(
        "this test breaks a gated crate OTHER than the one holding its fixture file, \
         and GATED_CRATES holds {} — with one crate there is no other crate to break",
        super::GATED_CRATES.len()
      )
    });

    let root = scratch_crates(
      "gated-missing-src",
      &[(super::GATED_CRATES[0], "tunnel.rs", GOVERNED)],
    );
    std::fs::remove_dir_all(root.join(missing).join("src")).expect("the second crate's src");

    let mut report = Report::new("doc-check");
    let ran = super::verdicts(&root, &mut report);
    std::fs::remove_dir_all(&root).ok();
    ran.expect("the check itself still runs rather than throwing");

    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(
      report.failures[0].contains(&format!("`{missing}` is gated but has no `src` directory")),
      "the failure must name the crate and what is missing: {}",
      report.failures[0]
    );
    assert_eq!(report.lines.len(), 1, "the check's own line must survive");
    assert!(
      report.lines[0].contains(&format!("{missing} UNREACHED")),
      "the census must show the hole rather than a smaller total: {}",
      report.lines[0]
    );
  }

  // The floor under discovery. Renaming one word of the header substring
  // un-governs the crate's only governed table, and every run after that
  // reports zero tables and zero problems and exits 0 — a check governing
  // nothing while still reporting success. `verdicts` reads the filesystem,
  // so this hands it a crate root whose only table is not a governed one.
  #[test]
  fn a_run_that_governs_no_table_fails() {
    let root = scratch_crate(
      "verdicts-floor",
      &[(
        "lib.rs",
        "\
/// | side | verdict |
/// |---|---|
/// | a | GUARDED |
fn f() {}
",
      )],
    );
    let report = verdicts_over(&root);
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
      .filter(|run| run.text.contains(super::GOVERNED_HEADER))
      .map(|run| run.text)
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

    // The LIVE declaration bullets would each be matched by the reservation,
    // and are spared only because they share this run with the table they
    // declare. Read off the real file rather than asserted in the abstract:
    // a declaration reworded into a shape `caps_runs` no longer sees would
    // leave the exemption exempting nothing, with nothing to notice it.
    let caps: Vec<String> = super::caps_runs(&governed[0])
      .into_iter()
      .map(|(_, run)| run)
      .collect();
    for (_, verdict) in super::declarations(&governed[0]) {
      assert!(
        caps.iter().any(|run| run == verdict),
        "the live declaration of `{verdict}` must be a caps run the reservation would match"
      );
    }
  }

  // Rule 3 in the exclusive form, over a crate root: the vocabulary is the
  // table's, so writing one of its words in any other doc run is a failure.
  // The claim sits on the run's THIRD line and the run opens on line 4, so
  // the reported line pins the offset arithmetic and not just the run's own
  // start — a failure naming the wrong line sends its reader to a comment
  // that does not say what it was told.
  #[test]
  fn a_verdict_written_outside_the_governed_table_is_a_failure() {
    let root = scratch_crate(
      "verdicts-reserved",
      &[
        ("tunnel.rs", GOVERNED),
        (
          "outbound.rs",
          "\
// not a doc comment
fn head() {}

/// The 101 branch this mode never takes.
///
/// `send_response` is STRUCTURALLY EXCLUDED — a 101 is refused outright.
fn send_response() {}
",
        ),
      ],
    );
    let report = verdicts_over(&root);
    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    // First, and by name. Both locations in the sentence below — the offending
    // run's and the declaring table's — are IDENTIFIERS a reader greps, pastes
    // into a review, or diffs against another machine's run, so both are
    // `/`-spelled wherever this runs. On Windows they were not, and the
    // literal assertion that follows failed on
    // `http1-proto\src\outbound.rs:6` with a string mismatch naming no rule.
    // Asserted ahead of it so the rule is what a reader is told.
    assert!(
      !report.failures[0].contains('\\'),
      "a finding spells a source location the same on every platform: {}",
      report.failures[0]
    );
    assert!(
      report.failures[0].starts_with(
        "http1-proto/src/outbound.rs:6: the verdict `STRUCTURALLY EXCLUDED` is written"
      ),
      "{}",
      report.failures[0]
    );
    assert!(
      report.failures[0].contains("reword it so it is not claiming a"),
      "the failure must say what to do instead: {}",
      report.failures[0]
    );
    assert!(
      report.failures[0].contains("(http1-proto/src/tunnel.rs:3)"),
      "the failure must name where the verdict was declared: {}",
      report.failures[0]
    );
    assert!(
      report.lines[0].contains(
        "3 declared verdict word(s) reserved to them, 1 doc run(s) elsewhere scanned, 1 carried one"
      ),
      "{}",
      report.lines[0]
    );
  }

  // `GUARDED` is a prefix of `GUARDED BY A CALLER`, and a substring search
  // would report every legitimate long form as a bare `GUARDED` — naming a
  // word the comment does not say and a rule it does not break.
  #[test]
  fn the_long_verdict_is_named_whole_not_as_its_prefix() {
    let root = scratch_crate(
      "verdicts-prefix",
      &[
        ("tunnel.rs", GOVERNED),
        (
          "mod.rs",
          "\
/// `into_tunnel` is GUARDED BY A CALLER — `commit_head` takes it out of `Open`.
fn into_tunnel() {}
",
        ),
      ],
    );
    let report = verdicts_over(&root);
    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(
      report.failures[0].contains("the verdict `GUARDED BY A CALLER` is written"),
      "{}",
      report.failures[0]
    );
    assert!(
      !report.failures[0].contains("the verdict `GUARDED` is written"),
      "the long form must not be reported as its own prefix: {}",
      report.failures[0]
    );
  }

  // The bullets declaring the vocabulary sit in the governed run, so the
  // whole-run exemption covers them and no special case is needed. The
  // printed line is pinned entire here because this is the shape a real run
  // has: zero findings, and a denominator that says so out loud rather than
  // leaving "checked" indistinguishable from "never looked".
  //
  // That includes the per-crate census, and the ZERO in it is the half worth
  // pinning: this fixture writes into the first gated crate only, so every
  // other crate is scanned and holds nothing — which the line has to say in
  // as many words, because it is the exact reading a merged total cannot tell
  // apart from never having looked there.
  #[test]
  fn the_declaration_bullets_are_not_their_own_violation() {
    let root = scratch_crate("verdicts-exempt", &[("tunnel.rs", GOVERNED)]);
    let report = verdicts_over(&root);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    let census = std::iter::once(format!("{} 1", super::GATED_CRATES[0]))
      .chain(
        super::GATED_CRATES[1..]
          .iter()
          .map(|name| format!("{name} 0")),
      )
      .collect::<Vec<_>>()
      .join(", ");
    assert_eq!(
      report.lines[0],
      format!(
        "table-verdicts: 1 table(s) checked, 0 problem(s); 3 declared verdict word(s) \
         reserved to them, 0 doc run(s) elsewhere scanned, 0 carried one; files \
         scanned: {census}"
      )
    );
  }

  // The reserved words are the ones the table declares, not a literal in
  // `xtask`: this crate root declares `FENCED` and never `GUARDED`, so
  // `FENCED` outside the table is the failure and `GUARDED` outside it is
  // not. Hard-coding the live vocabulary here would invert both, and a
  // reworded declaration would stop being enforced without failing anything.
  #[test]
  fn the_reserved_vocabulary_comes_from_the_table_not_a_constant() {
    let root = scratch_crate(
      "verdicts-vocabulary",
      &[
        (
          "tunnel.rs",
          "\
/// - **FENCED** — it asks the close question itself.
///
/// | corner | site | verdict |
/// |---|---|---|
/// | originate | `open_request` | FENCED — ok |
fn switched() {}
",
        ),
        (
          "mod.rs",
          "\
/// `open_request` is FENCED, and its neighbour is GUARDED.
fn open_request() {}
",
        ),
      ],
    );
    let report = verdicts_over(&root);
    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(
      report.failures[0].contains("the verdict `FENCED` is written"),
      "{}",
      report.failures[0]
    );
  }

  // The two decisions inside `caps_runs` a later edit could quietly reverse.
  // Markup and trailing punctuation are not part of a word, so a verdict in
  // backticks or ending a sentence still matches; `_` is, so a
  // screaming-snake constant breaks a run instead of joining the verdict
  // beside it into a run that matches nothing.
  #[test]
  fn caps_runs_strips_markup_and_breaks_on_a_constant() {
    assert_eq!(
      super::caps_runs(
        "a `GUARDED` cell\nand STRUCTURALLY EXCLUDED.\nthen GUARDED TAKEOVER_STATES_NO_CLOSE BY A CALLER"
      ),
      vec![
        (0, "GUARDED".to_string()),
        (1, "STRUCTURALLY EXCLUDED".to_string()),
        (2, "GUARDED".to_string()),
        (2, "BY A CALLER".to_string()),
      ]
    );
    // And a line break is not a word boundary the vocabulary respects: a
    // wrapped verdict is still the verdict it spells.
    assert_eq!(
      super::caps_runs("is GUARDED BY A\nCALLER — the gate is upstream."),
      vec![(0, "GUARDED BY A CALLER".to_string())]
    );
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
    let mut skipped = Report::new("doc-check");
    skipped.skip(
      "doc-continuity",
      "requires nightly rustdoc --output-format json",
    );
    assert!(skipped.finish(false).is_ok());
    let mut failed = Report::new("doc-check");
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

  // `unclaimed_snapshots` reads a directory, so its tests need one — and a
  // list of gated names they control, which is why the function takes that
  // list rather than reading `GATED_CRATES`. Removed before it is written as
  // well as after, matching `scratch_crates`: a run killed half way through
  // must not leave a snapshot behind that silently joins the next run.
  fn scratch_snapshots(name: &str, files: &[&str]) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("xtask-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let dir = root.join("xtask/snapshots");
    std::fs::create_dir_all(&dir).expect("a scratch snapshot directory");
    for file in files {
      std::fs::write(dir.join(file), "# a snapshot\n").expect("a snapshot file");
    }
    root
  }

  fn snapshots_over(root: &std::path::Path, gated: &[&str]) -> Report {
    let mut report = Report::new("doc-check");
    let ran = super::unclaimed_snapshots(root, gated, &mut report);
    std::fs::remove_dir_all(root).ok();
    ran.expect("the check itself runs");
    report
  }

  // The subject: dropping a crate from `GATED_CRATES` costs it three checks
  // and orphans its snapshot, and until this existed the binary exited 0 —
  // `--require-all` included, because nothing was SKIPPED, only shortened.
  // The failure has to name the crate AND what it lost, since the reader is
  // someone who does not yet know the list changed.
  #[test]
  fn a_snapshot_no_gated_crate_claims_fails_the_run() {
    let root = scratch_snapshots(
      "unclaimed-snapshot",
      &["kept-documented.txt", "dropped-documented.txt"],
    );
    let report = snapshots_over(&root, &["kept"]);

    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(
      report.failures[0].contains("`dropped` has a committed snapshot"),
      "{}",
      report.failures[0]
    );
    let lost = "doc-continuity, table-verdicts and path-qualified callee";
    assert!(
      report.failures[0].contains(lost),
      "the message must say what the crate LOST, not only that it is unclaimed: {}",
      report.failures[0]
    );
    assert!(
      report.lines[0].contains("2 committed snapshot(s), 1 claimed by no crate"),
      "{}",
      report.lines[0]
    );
    assert!(
      report.finish(false).is_err(),
      "an orphan fails without --require-all too: it is a defect found, not a check skipped"
    );
  }

  // The clean tree: every snapshot claimed, no failure, and a census line that
  // still states the denominator. Without this half the test above passes on a
  // check that fails on everything.
  #[test]
  fn every_claimed_snapshot_passes_and_is_counted() {
    let root = scratch_snapshots(
      "claimed-snapshot",
      &["kept-documented.txt", "also-documented.txt"],
    );
    let report = snapshots_over(&root, &["kept", "also"]);

    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert!(
      report.lines[0].contains("2 committed snapshot(s), 0 claimed by no crate"),
      "{}",
      report.lines[0]
    );
  }

  // A snapshot spelled any other way is read by nothing, because `continuity`
  // builds its path from a crate name. Same defect, different spelling — and
  // it must not be quietly skipped on the way to counting the orphans.
  #[test]
  fn a_snapshot_not_named_for_a_crate_fails_too() {
    let root = scratch_snapshots("misnamed-snapshot", &["kept-documented.txt", "notes.txt"]);
    let report = snapshots_over(&root, &["kept"]);

    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(
      report.failures[0].contains("is not named `<crate>-documented.txt`"),
      "{}",
      report.failures[0]
    );
  }

  // The opposite edit keeps its OWN message: a crate named in the list with no
  // snapshot committed is `continuity`'s failure, not this one's, and this
  // check must stay silent about it rather than reporting the absence twice
  // under a name that would send the reader to delete the wrong thing.
  #[test]
  fn a_gated_crate_with_no_snapshot_is_not_this_checks_failure() {
    let root = scratch_snapshots("missing-snapshot", &["kept-documented.txt"]);
    let report = snapshots_over(&root, &["kept", "ungated-and-unsnapshotted"]);

    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert!(
      report.lines[0].contains("1 committed snapshot(s), 0 claimed by no crate"),
      "{}",
      report.lines[0]
    );
  }

  // rustdoc's own shape, verbatim from a real `--document-private-items` run:
  // the diagnostic and its location are two lines, and the location is indented
  // and carries a column. `unresolved_links` only DESCRIBES a failure the exit
  // status has already decided, so what these pin is the message, not the
  // verdict.
  #[test]
  fn a_diagnostic_and_its_location_are_read_as_one_finding() {
    let stderr = "\
 Documenting http-semantics v0.1.0 (/w/http-semantics)
error: unresolved link to `RFC2046`
    --> http-semantics/src/media/mod.rs:1299:6
     |
1299 | /// [RFC2046], Section 4.1.2\".
     |      ^^^^^^^ no item named `RFC2046` in scope
";

    assert_eq!(
      unresolved_links(stderr),
      vec![(
        "http-semantics/src/media/mod.rs:1299:6".to_string(),
        "RFC2046".to_string()
      )]
    );
  }

  // The lint at warn level, which no run of this command produces and a hand
  // run easily does. Matching only `error:` would print nothing over a
  // warn-level pass and read exactly like a clean one.
  #[test]
  fn a_warning_level_diagnostic_is_read_too() {
    let stderr = "warning: unresolved link to `advance`\n  --> a/src/lib.rs:1:1\n";

    assert_eq!(
      unresolved_links(stderr),
      vec![("a/src/lib.rs:1:1".to_string(), "advance".to_string())]
    );
  }

  // rustdoc omits the location for a doc comment whose span it cannot map — an
  // outer `///` on a `mod` declaration merged with the file's own `//!` is the
  // case in this workspace. The finding is still reported: dropping it would
  // hand the reader a failure count that does not match the failures printed.
  #[test]
  fn a_diagnostic_with_no_location_is_still_a_finding() {
    let stderr = "\
warning: unresolved link to `FieldValue`
  |
  = note: the link appears in this line:
  = note: no item named `FieldValue` in scope
";

    assert_eq!(
      unresolved_links(stderr),
      vec![(NO_LOCATION.to_string(), "FieldValue".to_string())]
    );
  }

  // The location of the NEXT diagnostic must not be attached to a previous
  // finding that never got one, which is what a plain "fill the last empty
  // site" rule does. Two findings, and the located one is the second.
  #[test]
  fn a_location_attaches_to_its_own_diagnostic_and_not_the_one_before() {
    let stderr = "\
warning: unresolved link to `FieldValue`
  = note: no item named `FieldValue` in scope
warning: unresolved link to `poll_flush`
  --> wren-reactor/src/conn/mod.rs:251:9
";

    assert_eq!(
      unresolved_links(stderr),
      vec![
        (NO_LOCATION.to_string(), "FieldValue".to_string()),
        (
          "wren-reactor/src/conn/mod.rs:251:9".to_string(),
          "poll_flush".to_string()
        ),
      ]
    );
  }

  // A `-->` line belongs to whatever diagnostic printed it, and this command's
  // pass is not the only thing that emits one: any other rustdoc or cargo
  // diagnostic in the same log carries the same arrow. One that follows no
  // unresolved-link line must not become a finding.
  #[test]
  fn a_location_with_no_diagnostic_before_it_is_not_a_finding() {
    let stderr = "warning: redundant explicit link target\n  --> a/src/lib.rs:9:9\n";

    assert!(unresolved_links(stderr).is_empty());
  }
}
