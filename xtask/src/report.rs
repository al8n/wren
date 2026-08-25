//! What one check run examined, could not examine, and found.
//!
//! Shared by [`doc_check`](crate::doc_check) and [`shim_check`](crate::shim_check)
//! rather than written once per command, because it is not a printing
//! convenience: it is this workspace's governing rule about gates made into a
//! type. A green run has to be distinguishable from a run that never looked, so
//! a check records its DENOMINATOR — what it examined — alongside what it
//! found, and records by name anything it could not examine at all.
//!
//! Two hand-copied copies of that rule would be two places for one to be
//! weakened without the other disagreeing, which is the same argument the
//! `no-panic` lie-checks are one CI step for.
//!
//! [`site`] is here for that same argument one step over: how a finding spells
//! the source location it opens with is part of what a finding IS, so every
//! command that prints one — [`doc_check`](crate::doc_check),
//! [`quote_check`](crate::quote_check) — reaches one rule rather than its own
//! copy of it.
use crate::Error;
use std::path::{MAIN_SEPARATOR, Path};

/// A repo-relative source location, spelled the same on every platform.
///
/// **Two kinds of path are printed by this crate and they want opposite
/// spellings. This is for the first kind only.**
///
/// 1. A repo-relative location naming a source site — the `file:line` a
///    finding opens with. That is an IDENTIFIER, not a path to open: a reader
///    greps it, pastes it into a review comment, and diffs one run's output
///    against another run's from another machine. It has to read the same
///    everywhere, so it is always `/`-spelled, and this is what spells it.
///
/// 2. An absolute filesystem path in an io error — `could not read {}`. That
///    is a path the reader hands to their OWN shell, so it keeps the
///    platform's separators. Print those with `.display()` directly; do not
///    reach for this.
///
/// The two are told apart by construction rather than by taste: a path becomes
/// the first kind by having the workspace root stripped off it, so every call
/// here sits on a `strip_prefix(root)`, and a path that still names a
/// filesystem location is the second kind and stays native.
///
/// Both kinds were `.display()` until a Windows CI run printed a finding
/// reading `http1-proto\src\outbound.rs:6` — one platform spelling an
/// identifier its own way, which is the one thing an identifier may not do.
pub fn site(path: &Path) -> String {
  spelled(&path.to_string_lossy(), MAIN_SEPARATOR)
}

/// [`site`]'s whole rule, with the platform's separator passed in.
///
/// Split out for one reason. `MAIN_SEPARATOR` is `/` on the machines this is
/// developed on, so a test that calls [`site`] there exercises an identity
/// function: the rule that matters is reached only on Windows, which is
/// exactly where it cannot be run by hand. Taking the separator as an argument
/// makes the Windows rule executable anywhere, and leaves ONE unexecuted link
/// instead of a whole untested rule — that `MAIN_SEPARATOR` is `\` on Windows,
/// which is std's documented value and not a claim of this crate's.
///
/// It replaces the SEPARATOR, not every backslash. A unix filename may hold a
/// literal `\`; it is a legal character there and not a separator, and a
/// blanket replace would rewrite such a name into a location that does not
/// exist — this same defect with the platforms swapped.
fn spelled(shown: &str, separator: char) -> String {
  shown.replace(separator, "/")
}

/// What one run examined, could not examine, and found.
///
/// `command` is the name the lines are printed under, so one type can serve
/// more than one subcommand without a run's output claiming to be another's.
#[derive(Clone)]
pub struct Report {
  command: &'static str,
  pub(crate) lines: Vec<String>,
  pub(crate) skipped: Vec<String>,
  pub(crate) failures: Vec<String>,
}

impl Report {
  /// An empty report for `command`.
  pub fn new(command: &'static str) -> Self {
    Self {
      command,
      lines: Vec::new(),
      skipped: Vec::new(),
      failures: Vec::new(),
    }
  }

  // `checked`, `skip`, and `fail` are this Report's whole recording surface.
  // `doc-check`'s `continuity` and `verdicts` between them call all three —
  // `checked` and `fail` from either, `skip` only from `continuity`, on a
  // toolchain that lacks nightly rustdoc's JSON output — so none of them needs
  // a dead-code allow.

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
  /// CI passes `require_all`, so a check that needs a toolchain half cannot be
  /// quietly lost by an edit to the workflow that runs it.
  pub fn finish(self, require_all: bool) -> Result<(), Error> {
    for line in &self.lines {
      println!("{}: {line}", self.command);
    }
    for line in &self.skipped {
      println!("{}: {line}", self.command);
    }
    for failure in &self.failures {
      println!("{failure}");
    }
    if !self.failures.is_empty() {
      return Err(format!("{}: {} failures", self.command, self.failures.len()).into());
    }
    if require_all && !self.skipped.is_empty() {
      return Err(
        format!(
          "{}: {} check(s) skipped under --require-all",
          self.command,
          self.skipped.len()
        )
        .into(),
      );
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::{site, spelled};
  use std::path::Path;

  // The Windows rule, run somewhere that is not Windows. `\` is passed in
  // rather than read off the host, so this asserts the same thing on every
  // runner and would still fail on a unix machine if the rule were removed —
  // the regression a `.display()` restored at a finding's call site trips.
  #[test]
  fn a_location_spelled_with_the_windows_separator_is_reported_with_slashes() {
    assert_eq!(
      spelled("http1-proto\\src\\outbound.rs", '\\'),
      "http1-proto/src/outbound.rs"
    );
  }

  // A path built as `root.join("xtask/snapshots")` keeps that `/` verbatim on
  // Windows and picks up a `\` from the join, so the real Windows input is
  // MIXED rather than uniformly backslashed. Normalising only one of the two
  // spellings would leave an identifier that still reads differently there.
  #[test]
  fn a_location_spelled_with_both_separators_is_reported_with_slashes() {
    assert_eq!(
      spelled("http1-proto\\src/outbound.rs", '\\'),
      "http1-proto/src/outbound.rs"
    );
  }

  // The unix half of the same rule: nothing to replace, and nothing replaced.
  #[test]
  fn a_location_already_spelled_with_slashes_is_left_alone() {
    assert_eq!(
      spelled("http1-proto/src/outbound.rs", '/'),
      "http1-proto/src/outbound.rs"
    );
  }

  // `\` is a legal character in a unix filename and is not a separator there,
  // so a file genuinely named `od\d.rs` must be reported under the name it
  // has. This is what makes the rule "replace the separator" rather than
  // "replace every backslash": the blanket form passes every test above and
  // sends a reader to a path that does not exist.
  #[test]
  fn a_backslash_that_is_not_the_separator_is_a_character_and_survives() {
    assert_eq!(
      spelled("http1-proto/src/od\\d.rs", '/'),
      "http1-proto/src/od\\d.rs"
    );
  }

  // The property at the public entrance, stated where a reader will look for
  // it: the same three components produce the same identifier wherever this
  // runs. `join` spells them with `\` on Windows and `/` here, and the
  // assertion does not move — before this helper existed it was false on one
  // of the two.
  #[test]
  fn the_same_components_name_the_same_site_on_every_platform() {
    let path = Path::new("http1-proto").join("src").join("outbound.rs");
    assert_eq!(site(&path), "http1-proto/src/outbound.rs");
  }
}
