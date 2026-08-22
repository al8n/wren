//! Checks over the claims this workspace's documentation makes.
//!
//! `quote-check`'s sibling, and split from it at the toolchain seam rather than
//! by subject: one of these three needs rustdoc's JSON output, which is
//! nightly-only, and the other two are source scanning that any toolchain can
//! do. Running the two it can and SAYING it skipped the third is this crate's
//! rule applied to the command itself — a check that cannot examine something
//! must say so by name.
use crate::Error;

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

  // `checked`, `skip`, and `fail` are this Report's whole recording surface,
  // for the three checks Tasks 5, 6, and 7 add. This task wires the command
  // and the report but calls none of them from `run` yet, so a build with no
  // test code compiled (`--no-default-features`, `cargo doc`, a release
  // build) sees each as dead without the allow below. `skip` is additionally
  // exercised by this file's own test, which is why a `--tests` build only
  // flags `checked` and `fail`.

  /// Records what one check examined — its denominator.
  #[allow(dead_code)]
  pub fn checked(&mut self, line: impl Into<String>) {
    self.lines.push(line.into());
  }

  /// Records a check that did not run, and why.
  #[allow(dead_code)]
  pub fn skip(&mut self, check: &str, why: &str) {
    self.skipped.push(format!("{check}: SKIPPED ({why})"));
  }

  #[allow(dead_code)]
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
  let report = Report::new();
  let root = crate::workspace_root()?;
  let _ = (&root, bless);
  report.finish(require_all)
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
}
