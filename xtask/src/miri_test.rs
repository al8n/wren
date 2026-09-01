//! `cargo run -p xtask -- miri-test <crate> [filter]` — `cargo miri test` with
//! two time budgets on it, which is the whole reason it is not spelled
//! `cargo miri test`.
//!
//! # The rules, and why there are two
//!
//! **No single test** may spend more than [`BUDGET`] seconds inside the
//! interpreter without saying, in its own source, that it meant to. The
//! saying is `#[cfg_attr(miri, ignore = "…")]`, and a test that carries one
//! never runs, so it never has a time for this to read: the exemption is the
//! sanctioned escape and it is invisible here by construction. What this gate
//! exists to make visible is the ABSENCE of one.
//!
//! **No one crate's tests** may spend more than [`CRATE_BUDGET`] seconds in
//! total. The first rule cannot see the harm the job actually dies of: a job
//! has a wall-clock limit and a job dies of the SUM, so five hundred tests of
//! forty seconds each is 20000 s with no single test within an hour of its own
//! ceiling and the job dead anyway. The two rules catch disjoint shapes — one
//! test that ran away, and a crate that grew — and neither implies the other.
//! [`CRATE_BUDGET`] carries what the number is and how the job's own limit
//! divides into it; [`JOB_CRATES`] is held against the workflow rather than
//! trusted, because the claim "these ceilings bound the job" is a
//! multiplication and one of its factors lives in a YAML file.
//!
//! Both are enforced as WATCHDOGS rather than as reports, and that is the
//! difference between naming the harm and stopping it. The harm is the job's
//! budget being spent — three hours in one step, two crates behind it
//! reported as neither passing nor failing — and a run that named the
//! offender at the end would have spent it already. So the per-test budget
//! runs against the test that is running NOW ([`starting_test`]) and the
//! crate's total runs against everything finished plus that test's elapsed;
//! whichever expires first ends the run there. The after-the-fact checks over
//! finished tests are kept beside both as the floor: if a watchdog ever failed
//! to arm, the gate would still fail, just later.
//!
//! # Why a reviewer cannot catch this, and why the numbers are the reason
//!
//! Interpreted cost does not track native cost, so nothing about a test's
//! source says which kind it is. Two brute forces in `http-semantics` measure
//! it: the `date` one is 2.6 s natively — the SLOWER of the pair — and cheap
//! under `miri`, because it is arithmetic; the `auth` one is 1.1 s natively
//! and over two hours interpreted, because it makes roughly 700,000 heap
//! allocations and allocation is what the interpreter charges for.
//!
//! That one test took `cargo miri test -p http-semantics` from a few minutes
//! to 3 h 10 m, 80% of a four-crate job whose hard limit is six hours, with
//! two crates queued behind it that were then reported as neither passing nor
//! failing. With the exemption the same step is 6 m 49 s.
//!
//! A new brute force looks like every other test in review, passes every other
//! gate, and its only symptom is a job that takes longer — until the day it
//! takes six hours. Three tests in `http-semantics` carry the exemption today
//! and **all three were added after the fact**, each after somebody noticed a
//! slow job. That is a defect class this workspace closes with a gate rather
//! than with vigilance.
//!
//! # What the number is, and how it was arrived at
//!
//! Measured, not guessed, and the measurement found the next one before the
//! gate did: the slowest non-exempt test in this job is 1028.1 s and it landed
//! two commits before this did. [`BUDGET`] carries that figure, the command
//! that produced it — which is this command, whose own census is the
//! measurement — the conditions it was taken under, and the two things the
//! headroom above it is for.
//!
//! # Why this wraps the run instead of reading its log
//!
//! Two steps — run `miri`, then check a log — is a gate anyone can drop by
//! editing one of them, and the one worth dropping is always the second. One
//! step cannot be half-run. It also puts the flags the measurement DEPENDS on
//! in the same place as the budget that reads them:
//!
//! - `--report-time` is where the numbers come from at all. It is a libtest
//!   unstable option, so this passes `-Zunstable-options` with it.
//! - `--test-threads=1` is what makes them mean anything, twice over. `miri`
//!   interprets threads rather than running them, so a parallel libtest gains
//!   no parallelism and each test's wall time would instead include however
//!   much of the other threads' work the interpreter interleaved into it. It
//!   is also what makes a RUNNING test visible: on one thread libtest writes
//!   and flushes `test <name> ... ` before it runs the test, and in parallel
//!   it writes the name only once the test is over. One thread costs the job
//!   nothing and is the only way either number is a per-test number.
//!
//! `PROPTEST_CASES` and `MIRIFLAGS` are defaulted here for the same reason,
//! and only when the caller has not already set them: a developer measuring
//! locally has to be measuring what CI measures, or the number they read is
//! not the number the gate holds. They sat on each CI step until this command
//! existed, and their reasons came with them:
//!
//! - `PROPTEST_CASES=8`. proptest under `miri` is orders of magnitude slower
//!   than native, and a handful of cases per property keeps the job in minutes
//!   while still running every test through the interpreter.
//! - `MIRIFLAGS=-Zmiri-disable-isolation`. proptest's failure persistence
//!   reads and writes regression files committed in-tree, which needs `getcwd`
//!   and file IO — host syscalls `miri`'s isolation rejects. Disabling
//!   isolation permits them; UB detection is unaffected.
//!
//! # What this cannot see
//!
//! - **A test just under either budget**, and there is nothing to be done
//!   about that: any threshold has a value one second below it. What stands in
//!   for it is the percentage of its ceiling every run prints beside its
//!   total, pass or fail, so a crate on its way there is visible before it
//!   arrives.
//! - **BUILD time.** Both budgets are on test time, which is what the census
//!   measures. A `miri` build that takes an hour is not counted here and is
//!   not this command's to bound — [`CRATE_BUDGET`]'s reserve out of the job
//!   limit is where builds are accounted for, as a reserve rather than as a
//!   check.
//! - **A hang before the first test.** The per-test watchdog arms only while a
//!   named test is running, so a `miri` build that wedges for an hour is the
//!   job's own timeout to answer, not this. Arming it earlier would mean
//!   timing out a slow COMPILE, which is a failure invented rather than found.
//! - **Whether a crate BELONGS in the job.** [`crates_the_job_names`] holds
//!   the workflow's crate count against [`JOB_CRATES`], so a crate cannot be
//!   added or dropped without the budget arithmetic being re-derived — but
//!   nothing here knows which crates the list SHOULD hold, only how many it
//!   does.
//! - **Whether an exemption was DESERVED.** `#[cfg_attr(miri, ignore = "…")]`
//!   is taken at its word; a test wrongly exempted is a test not run, which
//!   is a different failure from the one this measures.
//!
//! # Seeing them fail
//!
//! `XTASK_MIRI_BUDGET=<seconds>` tightens [`BUDGET`] and
//! `XTASK_MIRI_CRATE_BUDGET=<seconds>` tightens [`CRATE_BUDGET`], each for one
//! run, and a value looser than the ceiling it tightens is refused rather than
//! clamped ([`tighten`]). They exist because a check whose failure nobody has
//! watched is not a check, and these two are an hour and sixty-six minutes
//! away by construction — nobody was ever going to wait for them, so nobody
//! would ever have found out whether the kill reached the interpreter. With
//! the knobs it is seconds:
//!
//! ```text
//! XTASK_MIRI_BUDGET=5 cargo run -p xtask -- miri-test http3-proto \
//!   stream_store::tests::slab_store_dynamic_insert_lookup_remove
//! ```
//!
//! That test is the shape this gate is about, at a small scale: a few
//! milliseconds natively against the 8.7 s the census above records for it, and
//! no exemption on it because at 8.7 s it does not need one. The run ends in 14
//! seconds with a non-zero exit naming the test, and `pgrep -x miri` afterwards
//! is empty — which is the half that cannot be argued from the source, since
//! killing the cargo at the top of the tree leaves the interpreter under it
//! running and only the process group in [`kill_group`] stops that.
//!
//! The SUM has its own, and the shape it demonstrates is the one the per-test
//! budget is blind to — many cheap tests, no single one anywhere near its own
//! ceiling:
//!
//! ```text
//! XTASK_MIRI_CRATE_BUDGET=20 cargo run -p xtask -- miri-test http3-proto
//! ```
//!
//! `http3-proto`'s 420 tests total 83.3 s and its slowest is 8.7 s, so at a
//! 20 s crate ceiling the run is stopped partway through with every test that
//! ran well under the 3600 s per-test budget — which is the whole point: the
//! first rule sees nothing here and the second one stops the run.
//!
//! Refusing the loose direction is what keeps it from being a way to turn the
//! gate off: the only thing a caller can do with it is fail sooner. A CI step
//! that set it high would fail on the value rather than pass on a budget
//! nobody notices was lifted.

use std::{
  env,
  io::Read,
  process::{Child, Command, Stdio},
  sync::mpsc::{self, RecvTimeoutError},
  thread,
  time::{Duration, Instant},
};

type Error = Box<dyn std::error::Error>;

/// The per-test budget under `miri`, in seconds.
///
/// # What was measured
///
/// This command, on each crate the `miri` job runs, one at a time:
///
/// ```text
/// cargo run -p xtask -- miri-test <crate>
/// ```
///
/// which is `cargo +nightly miri test -p <crate> --all-features --
/// -Zunstable-options --report-time --test-threads=1` with the two environment
/// defaults below. The census [`run`] prints at the end IS the measurement, so
/// re-deriving this number is the gate's own output rather than a separate
/// procedure:
///
/// ```text
/// http-semantics — 438 tests timed, 1597.6s in total, 4 ignored
///      1028.1s  grammar::tests::a_joined_refusal_leaves_the_cursor_where_no_member_opens
///       525.7s  date::tests::the_rule_answers_its_own_sentence_for_every_candidate_date
///         4.3s  range::tests::two_message_subtypes_are_seven_bit_only
/// http1-proto    — 508 tests timed, 784.3s in total, 1 ignored
///       126.5s  the_outbound_corpus_keeps_its_vectors
///       117.3s  head::scan::heap_tests::head_cap_enforced_with_414_vs_431_distinction
/// http3-proto    — 420 tests timed, 83.3s in total, 2 ignored
///         8.7s  stream_store::tests::slab_store_dynamic_insert_lookup_remove
/// websocket-proto — 304 tests timed, 1551.8s in total, 1 ignored
///       559.4s  connection::send::deflate_tests::worst_case_len_bounds_actual_output
///       267.3s  negotiation::tests::the_offer_list_is_bounded
/// ```
///
/// 1670 tests, 4017 s, one machine, nothing else running for the first three.
///
/// `http-semantics` is where the shape is clearest: TWO of its 438 tests are
/// 1553.8 s of its 1597.6 s — 97% — and the third slowest is 4.3 s, so the gap
/// between the top two and everything else is two hundredfold. Neither of the
/// two carries an exemption.
///
/// **The slowest non-exempt test in the job is 1028.1 s**, and it landed two
/// commits before this gate did (#78). That is the issue's own prediction
/// arriving: three exemptions in this workspace were all added after somebody
/// noticed a slow job, and here was a fourth test of the same shape with
/// nobody having noticed yet.
///
/// The measurement is a shared aarch64 laptop's. `websocket-proto` carries two
/// caveats the other three do not, and both push its figures UP rather than
/// down: `sha1` takes an aarch64 SHA-2 intrinsic path `miri` cannot interpret,
/// so timing that crate on this host at all needed
/// `RUSTFLAGS='--cfg sha1_backend="soft"'` — a slightly different program, and
/// one CI never builds, since x86_64 never reaches that code — and its run was
/// the only one sharing the machine with other work. Its slowest is 559.4 s
/// either way, well under the floor, so neither caveat moves the answer.
/// Re-measure with the command above before moving this number; the slowest
/// non-exempt test is what decides how low it can go.
///
/// # Why an hour
///
/// The floor is 1028.1 s and this is 3600 s, which is 3.5 times it. It is also
/// one SIXTH of the six-hour limit on the job this protects, and both halves
/// of that are the argument:
///
/// - **Above the floor by enough that the runner cannot move it.** The
///   measurement is not on the machine the gate runs on: CI is a shared
///   GitHub `ubuntu-latest` x86_64 runner. The one calibration available says
///   the two are close — `http3-proto` is 83 s here and was reported at
///   2.6 min there — but "close" measured once is not a budget, and a gate
///   that fails on which runner it drew is a gate that gets switched off.
/// - **Below the harm by enough to matter.** The step this was opened over
///   took 3 h 10 m; one test can now take at most one hour, so it can no
///   longer take the crates queued behind it down with it.
///
/// What that costs is stated rather than left to be discovered: a test at
/// 50 minutes passes. This catches the class that turns a step from minutes
/// into hours, and the census printed by [`run`] every time is what makes a
/// test on its way there visible before it gets there.
const BUDGET: f64 = 3600.0;

/// The environment variable that tightens [`BUDGET`] for one run — see
/// [`tighten`] and the module doc's "Seeing it fail".
const BUDGET_ENV: &str = "XTASK_MIRI_BUDGET";

/// The most one crate's tests may spend inside the interpreter in total, in
/// seconds.
///
/// # Why a second budget at all
///
/// [`BUDGET`] cannot see the harm. What kills the job is the TOTAL, and a
/// per-test ceiling of an hour is blind to five hundred tests of forty seconds
/// each — 20000 s, no single test anywhere near its own limit, and the job
/// dead. The two budgets catch disjoint shapes: one test that ran away, and a
/// crate that grew.
///
/// # Where 4000 comes from
///
/// The same way [`BUDGET`] comes from its floor: the harm, divided, with the
/// headroom stated.
///
/// [`JOB_LIMIT`] is 21600 s. The job runs [`JOB_CRATES`] crate steps, and this
/// ceiling is per crate, so four crates sitting exactly on it spend 16000 s of
/// TEST time — 74% of the limit. The remaining 5600 s is what the rest of the
/// job needs and what a red needs to be REPORTED rather than killed mid-print:
/// `cargo miri setup`, four `cargo miri` builds (roughly 150 s each, from the
/// difference between the issue's reported step times and this command's test
/// totals), checkout and cache restore. That arithmetic is not left to be
/// re-done by a reader — `the_crate_budgets_cannot_reach_the_job_limit` holds
/// it, and [`crates_the_job_names`] holds [`JOB_CRATES`] against the workflow
/// rather than trusting it.
///
/// Measured today, with each crate run alone (see [`BUDGET`] for the full
/// census): `http-semantics` 1597.6 s, `websocket-proto` 1551.8 s,
/// `http1-proto` 784.3 s, `http3-proto` 83.3 s. **4017 s in total, which is
/// 18.6% of the job's limit and 25.1% of the 16000 s these four ceilings
/// allow.** The slowest crate has 2.50 times its own total to grow into, less
/// headroom than [`BUDGET`]'s 3.50 and necessarily so: a total is already the
/// sum of everything a crate does, where a single test is one of hundreds.
///
/// Two of those figures are UPPER bounds, and both are `websocket-proto`'s:
/// its run was the only one sharing the machine, and timing it on an aarch64
/// host at all needed `sha1`'s soft backend. Both inflate rather than deflate,
/// so neither can have hidden a crate that is closer to this ceiling than it
/// looks.
///
/// # What it is a budget ON
///
/// TEST time, which is what the census measures — not the step's wall clock.
/// A `miri` build is not counted here and is not this command's to bound; the
/// 5600 s reserve above is where it lives.
const CRATE_BUDGET: f64 = 4000.0;

/// The environment variable that tightens [`CRATE_BUDGET`] for one run.
const CRATE_BUDGET_ENV: &str = "XTASK_MIRI_CRATE_BUDGET";

/// The hard limit on the `miri` job these budgets protect, in seconds.
///
/// Six hours, which is GitHub Actions' default maximum for a job. It is the
/// number the issue is about: the step that opened it took 3 h 10 m, 80% of
/// this, and the crates queued behind it were reported as neither passing nor
/// failing.
const JOB_LIMIT: f64 = 21600.0;

/// How many crates that job runs `miri-test` on.
///
/// Checked, not trusted: [`run`] reads the workflow and refuses to start when
/// the two disagree ([`crates_the_job_names`]). Everything [`CRATE_BUDGET`]
/// claims about the job is this number times that one, so a fifth crate added
/// to the job without anybody re-deriving the ceiling would make the claim
/// false silently — which is the exact shape of failure this file exists to
/// remove. It also fails the other way, on a crate REMOVED from the job, and
/// that is deliberate: the constant is a mirror, and a mirror that only
/// tracked one direction would let the job quietly stop interpreting a crate.
const JOB_CRATES: usize = 4;

/// The workflow the `miri` job is defined in, relative to the workspace root.
const WORKFLOW: &str = ".github/workflows/ci.yml";

/// How many of the slowest tests to print at the end of a run.
///
/// A census rather than a verdict, printed pass or fail: a green run that
/// says nothing about where the time went is how the last three exemptions
/// came to be added after the fact instead of before.
const SLOWEST: usize = 5;

/// The budget one run holds: `ceiling`, or the tighter one `set` asks for.
///
/// Only tighter. A value above `ceiling` is an ERROR rather than a clamp, and
/// the difference is the whole reason this is safe to ship: a clamp lets a
/// caller believe they raised the budget and quietly not have, so a CI step
/// that set one would go on passing with a limit nobody could read from the
/// workflow. Refusing makes that step fail on the value it wrote.
///
/// What it buys is the only thing that makes these gates demonstrable: the
/// shipped budgets are an hour and sixty-six minutes, so watching either work
/// means waiting that long, which means nobody watches and nobody finds out
/// the kill never reached the interpreter. Seconds, and the same code paths
/// answer.
///
/// One function for both budgets, `name` and `ceiling` being the whole of the
/// difference: two copies of a rule this small is two places for the loose
/// direction to be allowed by accident.
fn tighten(name: &str, ceiling: f64, set: Option<&str>) -> Result<f64, Error> {
  let Some(text) = set else {
    return Ok(ceiling);
  };
  let text = text.trim();
  let seconds: f64 = text
    .parse()
    .map_err(|_| format!("{name} is not a number of seconds: {text}"))?;
  if !seconds.is_finite() || seconds <= 0.0 {
    return Err(format!("{name} must be a positive number of seconds: {text}").into());
  }
  if seconds > ceiling {
    return Err(
      format!(
        "{name}={text} is looser than the {ceiling:.0}s miri budget it tightens, and this \
         only tightens it"
      )
      .into(),
    );
  }
  Ok(seconds)
}

/// The budget `name` asks for in the environment, or `ceiling` when it asks
/// for nothing.
///
/// `var_os` and an explicit decode rather than `env::var().ok()`, because that
/// one folds "not set" and "not UTF-8" into the same `None` — and the second of
/// those would then LOOSEN the budget back to its default without saying so.
fn budget_from_env(name: &str, ceiling: f64) -> Result<f64, Error> {
  match env::var_os(name) {
    None => tighten(name, ceiling, None),
    Some(raw) => tighten(
      name,
      ceiling,
      Some(
        raw
          .to_str()
          .ok_or_else(|| format!("{name} is not valid UTF-8"))?,
      ),
    ),
  }
}

/// How many crates the `miri` job runs this command on, read out of the
/// workflow rather than assumed.
///
/// Only a step's `run:` is read, which is what keeps the job's own prose about
/// `xtask miri-test` — there is a paragraph of it above those steps — from
/// being counted as a step.
fn crates_the_job_names(workflow: &str) -> usize {
  workflow
    .lines()
    .map(str::trim_start)
    .filter_map(|line| {
      line
        .strip_prefix("- run:")
        .or_else(|| line.strip_prefix("run:"))
    })
    .filter(|run| run.contains("miri-test"))
    .count()
}

/// One test the run timed.
struct Timed {
  /// The test's path, as libtest prints it.
  name: String,
  /// Its wall time inside the interpreter, in seconds.
  seconds: f64,
}

/// Runs `cargo miri test` for one crate and holds every test it runs to
/// [`BUDGET`], live.
///
/// Two paths reach the same verdict and both are kept:
///
/// - The WATCHDOG. The stream's unterminated tail names the test now running
///   ([`starting_test`]); when nothing arrives before its budget expires, the
///   child is killed and that test is named. This is the one that bounds what
///   the job spends.
/// - The AFTER-THE-FACT check, over the times of tests that finished. With
///   the watchdog armed nothing should reach it, which is exactly why it is
///   here: it is what the gate degrades to if the tail ever stops being
///   readable, and a gate whose failure mode is "reports later" is a gate
///   whose failure mode is not "reports nothing".
///
/// `filter` is passed to libtest as its test-name filter, for a developer
/// narrowing a local run. It has no effect on the budget: a test that runs is
/// held whether it was reached through a filter or not.
pub fn run(crate_name: &str, filter: Option<&str>) -> Result<(), Error> {
  // Read before the child is spawned: a bad budget should fail the command in a
  // millisecond, not after a `miri` build.
  let budget = budget_from_env(BUDGET_ENV, BUDGET)?;
  let crate_budget = budget_from_env(CRATE_BUDGET_ENV, CRATE_BUDGET)?;
  let root = crate::workspace_root()?;
  // Checked before anything is spent, for the same reason: everything
  // `CRATE_BUDGET` claims about the job is this count times that ceiling, and
  // a claim nobody re-derives when the job changes is the failure this file is
  // about. A workflow that cannot be read is a check that did not happen, and
  // is reported as one rather than passed.
  let workflow = root.join(WORKFLOW);
  let named = crates_the_job_names(
    &std::fs::read_to_string(&workflow)
      .map_err(|err| format!("could not read {}: {err}", workflow.display()))?,
  );
  if named != JOB_CRATES {
    return Err(
      format!(
        "{WORKFLOW} runs miri-test on {named} crate(s) and JOB_CRATES says {JOB_CRATES}; \
         {JOB_CRATES} x the {CRATE_BUDGET:.0}s per-crate budget is what bounds the \
         {JOB_LIMIT:.0}s job, so re-derive it in xtask/src/miri_test.rs before changing the job"
      )
      .into(),
    );
  }

  let mut command = Command::new("cargo");
  command.current_dir(&root).args([
    "+nightly",
    "miri",
    "test",
    "-p",
    crate_name,
    "--all-features",
    "--",
    "-Zunstable-options",
    "--report-time",
    "--test-threads=1",
  ]);
  if let Some(filter) = filter {
    command.arg(filter);
  }
  // Defaulted, never overridden: see the module doc for why a local run has
  // to be the run CI makes, and why a caller who has already chosen is left
  // alone.
  if env::var_os("PROPTEST_CASES").is_none() {
    command.env("PROPTEST_CASES", "8");
  }
  if env::var_os("MIRIFLAGS").is_none() {
    command.env("MIRIFLAGS", "-Zmiri-disable-isolation");
  }

  // Streamed rather than collected: this run is minutes at best, and a job
  // that prints nothing until it ends is a job nobody can tell from a hung
  // one. stderr is inherited for the same reason — cargo's progress belongs
  // in the log as it happens.
  command.stdout(Stdio::piped());
  // Its OWN process group, so the watchdog has something it can actually
  // stop. `cargo miri test` is three processes deep — cargo, `cargo-miri
  // runner`, `miri` — and killing the cargo at the top leaves the interpreter
  // underneath it running: measured, the first time this was written without
  // it. The whole point of the budget is that the job stops spending, so what
  // is killed has to be the group. See `kill_group`.
  #[cfg(unix)]
  {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
  }
  let mut child = command
    .spawn()
    .map_err(|err| format!("could not run cargo miri test: {err}"))?;
  let stdout = child
    .stdout
    .take()
    .ok_or("cargo miri test produced no stdout to read")?;

  // The reader is a thread and not this one, because the budget has to be able
  // to time out ON a read: a test over budget is a test producing no output,
  // and a blocking `read` cannot notice that.
  let (sender, receiver) = mpsc::channel::<Vec<u8>>();
  let reader = thread::spawn(move || {
    let mut stdout = stdout;
    let mut buffer = [0u8; 4096];
    while let Ok(read) = stdout.read(&mut buffer) {
      if read == 0 {
        break;
      }
      let Some(chunk) = buffer.get(..read) else {
        break;
      };
      if sender.send(chunk.to_vec()).is_err() {
        break;
      }
    }
  });

  let mut timed: Vec<Timed> = Vec::new();
  let mut ignored = 0usize;
  // The unterminated tail of the stream: the `test <name> ... ` libtest prints
  // and flushes BEFORE it runs the test, which is what makes a running test
  // visible at all.
  //
  // BYTES rather than a `String`, because a read can land in the middle of a
  // multi-byte character and this workspace's assertion messages are full of
  // `§` and `—`. Decoding per COMPLETE line never splits one; decoding the
  // tail may, and the worst that costs is one `starting_test` answering
  // `None` until the rest of the character arrives.
  let mut pending: Vec<u8> = Vec::new();
  // The test that line named, and when it was seen. `None` between tests, and
  // that is what disarms the watchdog: only a named, running test is on the
  // clock, so a long compile before the first test cannot be timed out.
  let mut running: Option<(String, Instant)> = None;
  // The test the watchdog killed the run over, if it did.
  let mut killed: Option<String> = None;
  // What the crate has spent on tests that FINISHED, in seconds. The crate's
  // budget is held live against this plus however long the running test has
  // been going, for the reason the per-test one is: a total reported after the
  // job has spent it is not a bound on the job.
  let mut spent = 0.0f64;
  // Set when the crate's total ran out, to the total it ran out at.
  let mut overspent: Option<f64> = None;

  loop {
    let message = match &running {
      Some((_, since)) => {
        let elapsed = since.elapsed().as_secs_f64();
        // Whichever budget expires first stops the run, so the wait is the
        // shorter of the two remainders.
        match (left(budget, elapsed), left(crate_budget, spent + elapsed)) {
          (Some(test_left), Some(crate_left)) => receiver.recv_timeout(test_left.min(crate_left)),
          _ => Err(RecvTimeoutError::Timeout),
        }
      }
      // Between tests nothing is on the per-test clock, and a long compile
      // before the first test is deliberately not timed out — but the crate's
      // total is already spent whether or not a test is running.
      None if left(crate_budget, spent).is_none() => Err(RecvTimeoutError::Timeout),
      None => receiver.recv().map_err(|_| RecvTimeoutError::Disconnected),
    };
    match message {
      Ok(chunk) => {
        pending.extend_from_slice(&chunk);
        while let Some(at) = pending.iter().position(|byte| *byte == b'\n') {
          let rest = pending.split_off(at.saturating_add(1));
          let line = String::from_utf8_lossy(&pending).trim_end().to_string();
          pending = rest;
          let line = line.as_str();
          println!("{line}");
          // Any COMPLETE line ends whatever was running: libtest finishes the
          // line it opened with the result, so the test named in the partial
          // is the test named in the line that completes it.
          running = None;
          if let Some((name, seconds)) = timed_test(line) {
            spent += seconds;
            timed.push(Timed {
              name: name.to_string(),
              seconds,
            });
          } else if is_ignored(line) {
            ignored += 1;
          }
        }
        let tail = String::from_utf8_lossy(&pending);
        if let Some(name) = starting_test(&tail)
          && running.as_ref().is_none_or(|(current, _)| current != name)
        {
          running = Some((name.to_string(), Instant::now()));
        }
      }
      Err(RecvTimeoutError::Timeout) => {
        let elapsed = running
          .as_ref()
          .map_or(0.0, |(_, since)| since.elapsed().as_secs_f64());
        // Both are asked, and both may answer: a run that blew its crate total
        // ON a test that also blew its own budget is two things wrong, and a
        // message naming one of them sends the reader to fix half of it.
        if left(budget, elapsed).is_none() {
          killed = running.as_ref().map(|(name, _)| name.clone());
        }
        if left(crate_budget, spent + elapsed).is_none() {
          overspent = Some(spent + elapsed);
        }
        // Killed rather than waited out. The harm this gate exists to stop is
        // the job's budget being spent — a run that reported the offender
        // three hours later would have already spent it, and the crates
        // behind this one would still be unrun.
        kill_group(&mut child);
        break;
      }
      Err(RecvTimeoutError::Disconnected) => break,
    }
  }
  if !pending.is_empty() {
    println!("{}", String::from_utf8_lossy(&pending));
  }
  // The reader is DROPPED, not joined. It is parked in a `read` on a pipe
  // whose write end every process in the group holds, so joining it after a
  // kill waits on whichever of them the kill missed — which is how the first
  // version of this hung for ten minutes on a watchdog that had fired
  // correctly five seconds in.
  drop(receiver);
  drop(reader);
  let status = child.wait()?;

  timed.sort_by(|left, right| right.seconds.total_cmp(&left.seconds));
  // Folded from a literal zero rather than summed: `Sum for f64` folds from
  // -0.0, and an empty run then prints a total of `-0.0s`.
  let total: f64 = timed.iter().fold(0.0, |sum, test| sum + test.seconds);
  // The total carries the fraction of its ceiling it is, every run, pass or
  // fail. That percentage is the only thing that makes a crate ON ITS WAY to
  // the ceiling visible before it arrives — a bare number of seconds says
  // nothing about how much room is left, and this gate exists because nobody
  // was watching the number that mattered.
  println!(
    "miri-test: {crate_name} — {} tests timed, {total:.1}s in total \
     ({:.0}% of the {crate_budget:.0}s a crate's tests may spend), \
     {ignored} ignored (an exemption is not run, so it has no time to hold)",
    timed.len(),
    total / crate_budget * 100.0
  );
  for test in timed.iter().take(SLOWEST) {
    println!("  {:>9.1}s  {}", test.seconds, test.name);
  }

  // The crate's total, the same two ways round: stopped live, or found over
  // once the run ended. `overspent` carries what it was stopped AT, which is
  // not `total` — the run was killed mid-test, so the test that pushed it over
  // never printed a time to be summed.
  let crate_over = overspent.or((total > crate_budget).then_some(total));
  if let Some(at) = crate_over {
    println!(
      "miri-test: {crate_name}'s tests spent {at:.1}s, over the {crate_budget:.0}s a crate's \
       tests may spend under miri; {JOB_CRATES} crates at that ceiling is {:.0}s of the \
       job's {JOB_LIMIT:.0}s limit",
      CRATE_BUDGET * JOB_CRATES as f64
    );
    println!(
      "  No single test need be over its own {budget:.0}s budget for this to happen, and that \
       is what it is for: the job dies of the TOTAL. Make the crate cheaper under the \
       interpreter, or exempt the tests the interpreter is not for."
    );
  }

  // A test the watchdog stopped, and a test that finished over budget, are the
  // same failure reached two ways — see `run`'s doc for why both paths exist.
  let over: Vec<&Timed> = timed.iter().filter(|test| test.seconds > budget).collect();
  if killed.is_some() || !over.is_empty() {
    if let Some(name) = &killed {
      println!(
        "miri-test: {name} was still running after the {budget:.0}s per-test \
         budget under miri; the run was stopped there"
      );
    }
    for test in &over {
      println!(
        "miri-test: {} took {:.1}s, over the {budget:.0}s per-test budget under miri",
        test.name, test.seconds
      );
    }
    println!(
      "  Either make it cheaper under the interpreter — allocation is what \
       miri charges for, and a walk that is pure arithmetic is not — or say so \
       where the test is:"
    );
    println!(
      "  #[cfg_attr(miri, ignore = \"<why the interpreter is not what this test is for>\")]"
    );
  }

  // Both answers are reported, and the budget's is not allowed to hide the
  // suite's: a run whose tests failed AND whose budget was blown is two
  // things wrong, and a message naming one of them sends the reader to fix
  // half of it.
  let mut reasons = Vec::new();
  if !status.success() && killed.is_none() {
    let code = status
      .code()
      .map_or_else(|| "a signal".to_string(), |code| format!("status {code}"));
    reasons.push(format!(
      "cargo miri test -p {crate_name} exited with {code}"
    ));
  }
  if let Some(name) = &killed {
    reasons.push(format!(
      "{name} was still running after the {budget:.0}s per-test miri budget"
    ));
  }
  if !over.is_empty() {
    reasons.push(format!(
      "{} test(s) over the {budget:.0}s per-test miri budget",
      over.len()
    ));
  }
  if let Some(at) = crate_over {
    reasons.push(format!(
      "{crate_name}'s tests spent {at:.1}s, over the {crate_budget:.0}s per-crate miri budget"
    ));
  }
  if reasons.is_empty() {
    return Ok(());
  }
  Err(reasons.join("; ").into())
}

/// How much of `seconds` is left once `spent` of it is gone, or `None` when
/// none is.
///
/// One helper for both budgets, and it answers `None` rather than a zero
/// duration at the boundary: a zero-length `recv_timeout` would come back as a
/// timeout anyway, and going through the same `None` for "expired" and for
/// "expired a while ago" leaves one shape for the caller to read.
fn left(seconds: f64, spent: f64) -> Option<Duration> {
  let remaining = seconds - spent;
  (remaining > 0.0).then(|| Duration::from_secs_f64(remaining))
}

/// Stops `child` and everything it started.
///
/// `Child::kill` is not enough and the difference is the whole gate: `cargo
/// miri test` is cargo over `cargo-miri runner` over `miri`, and killing the
/// cargo at the top leaves the interpreter below it running the very test the
/// budget just refused. On Unix the child is its own process group leader
/// (`process_group(0)` in [`run`]), so the group shares the child's pid and
/// `kill -KILL -<pid>` reaches all of it. The `kill` binary rather than a
/// `libc` dependency: this crate has none, and one signal is not worth the
/// first.
///
/// Elsewhere the group is not available and `Child::kill` is what there is.
/// That leaves a descendant running, which is a worse outcome and a stated
/// one — every machine this job runs on is Unix.
fn kill_group(child: &mut Child) {
  #[cfg(unix)]
  {
    let _ = Command::new("kill")
      .args(["-KILL", &format!("-{}", child.id())])
      .status();
  }
  let _ = child.kill();
}

/// The test named on one libtest result line and the seconds it took, or
/// `None` when the line is not a timed result.
///
/// The shape is libtest's `--report-time` output — `test <path> ... ok
/// <1.234s>` — and the outcome word is deliberately not read. A test that
/// FAILED spent its time all the same, and a budget that only weighed the
/// passing ones would let a slow test hide behind a broken one.
///
/// An ignored test prints no time, so it produces `None` here rather than a
/// zero: see [`is_ignored`] for the half of that this counts instead.
fn timed_test(line: &str) -> Option<(&str, f64)> {
  let rest = line.strip_prefix("test ")?;
  let (name, outcome) = rest.split_once(" ... ")?;
  let open = outcome.find('<')?;
  let close = outcome.rfind("s>")?;
  let seconds = outcome.get(open.checked_add(1)?..close)?.parse().ok()?;
  Some((name.trim(), seconds))
}

/// The test named by an unterminated `test <name> ... ` at the tail of the
/// stream, which is the test now RUNNING.
///
/// This is the watchdog's whole footing, and it rests on two libtest
/// behaviours that `--test-threads=1` and only `--test-threads=1` guarantee:
/// the name is written BEFORE the test runs rather than after it finishes,
/// and libtest flushes explicitly after writing it, so the partial line
/// reaches a pipe instead of sitting in a buffer until the test ends.
///
/// It matches only a tail that ENDS at the ellipsis. A tail carrying part of a
/// result — the run is answering, so nothing is stuck — is not a start, and
/// answering `None` there leaves the clock running on whatever this already
/// named rather than restarting it.
///
/// If this ever stopped matching, the watchdog would simply never arm and the
/// after-the-fact check in [`run`] would be the whole of the gate: a run that
/// took too long would still fail, just after having taken too long. That is
/// the direction a gate is allowed to break in — the other one invents
/// failures.
fn starting_test(partial: &str) -> Option<&str> {
  let rest = partial.strip_prefix("test ")?;
  rest
    .strip_suffix(" ... ")
    .or_else(|| rest.strip_suffix(" ..."))
}

/// Whether one libtest result line reports a test that did not run.
///
/// Counted rather than ignored in turn, because this number IS the
/// exemption's visibility: a crate whose ignored count climbs is a crate
/// whose coverage under the interpreter is being traded away, and the trade
/// should be a number somebody can see in the job's own output rather than a
/// thing to be found by reading attributes.
fn is_ignored(line: &str) -> bool {
  line
    .strip_prefix("test ")
    .and_then(|rest| rest.split_once(" ... "))
    .is_some_and(|(_, outcome)| outcome.starts_with("ignored"))
}

#[cfg(test)]
mod tests {
  use super::{
    BUDGET, BUDGET_ENV, CRATE_BUDGET, JOB_CRATES, JOB_LIMIT, WORKFLOW, crates_the_job_names,
    is_ignored, starting_test, tighten, timed_test,
  };

  // The knobs may only make a gate stricter, and the loose direction is an
  // ERROR rather than a clamp: a clamp would let a CI step write a budget it
  // did not get and pass anyway, which is the same class of silence this whole
  // module exists to remove.
  #[test]
  fn a_budget_knob_tightens_and_refuses_to_loosen() {
    assert_eq!(tighten(BUDGET_ENV, BUDGET, None).ok(), Some(BUDGET));
    assert_eq!(tighten(BUDGET_ENV, BUDGET, Some("20")).ok(), Some(20.0));
    assert_eq!(tighten(BUDGET_ENV, BUDGET, Some(" 20.5 ")).ok(), Some(20.5));
    assert_eq!(
      tighten(BUDGET_ENV, BUDGET, Some("3600")).ok(),
      Some(BUDGET),
      "exactly the budget is not looser than it"
    );

    for refused in ["3601", "0", "-5", "", "an hour", "inf", "NaN"] {
      let Err(err) = tighten(BUDGET_ENV, BUDGET, Some(refused)) else {
        panic!("{refused} was accepted");
      };
      assert!(err.to_string().contains(BUDGET_ENV), "{refused}: {err}");
    }

    // The same rule holds the other budget, because it is the same function —
    // and a value under the per-TEST ceiling can still be over the per-CRATE
    // one, so the two cannot share a ceiling either.
    assert_eq!(
      tighten("X", CRATE_BUDGET, Some("4000")).ok(),
      Some(CRATE_BUDGET)
    );
    assert!(tighten("X", CRATE_BUDGET, Some("4001")).is_err());
    assert!(
      tighten("X", BUDGET, Some("3700")).is_err(),
      "3700 is under the crate ceiling and over the per-test one"
    );
  }

  // The whole of what the per-crate budget claims about the JOB is this
  // multiplication, so it is asserted rather than left in a doc comment for a
  // reader to redo. The reserve is what a red needs in order to be REPORTED:
  // a gate that only reds after the runner has already killed the job says
  // nothing at all.
  #[test]
  fn the_crate_budgets_cannot_reach_the_job_limit() {
    let allotted = CRATE_BUDGET * JOB_CRATES as f64;
    assert_eq!(allotted, 16000.0);
    assert!(
      allotted < JOB_LIMIT,
      "{JOB_CRATES} crates at {CRATE_BUDGET}s is {allotted}s, and the job dies at {JOB_LIMIT}s"
    );
    assert!(
      allotted / JOB_LIMIT <= 0.75,
      "the reserve for `cargo miri setup`, four builds and the margin a red needs \
       is under a quarter of the limit: {allotted}s of {JOB_LIMIT}s"
    );
  }

  // `JOB_CRATES` is a mirror of the workflow, and this is the parsing half of
  // holding it there. Only a step's `run:` counts: the job carries a paragraph
  // of prose about `xtask miri-test` directly above those steps, and counting
  // that would put the constant permanently out of step with the thing it
  // mirrors.
  #[test]
  fn only_a_step_counts_as_a_crate_the_job_names() {
    let workflow = "  # Every step here is `xtask miri-test` rather than a bare
                      # `cargo miri test`, and miri-test is the gate.
                      miri:
    steps:
      - run: cargo miri setup
                          - run: cargo run -p xtask -- miri-test websocket-proto
                          - run: cargo run -p xtask -- miri-test http-semantics
";
    assert_eq!(crates_the_job_names(workflow), 2);
    assert_eq!(crates_the_job_names(""), 0);
  }

  // And the mirror itself, against the real file. `run` refuses to start when
  // these disagree; this is the same check where a developer meets it in a
  // second rather than after a `miri` build.
  #[test]
  fn the_job_runs_the_crates_the_budget_was_divided_among() {
    let root = crate::workspace_root().expect("workspace root");
    let workflow = std::fs::read_to_string(root.join(WORKFLOW)).expect("the workflow");
    assert_eq!(crates_the_job_names(&workflow), JOB_CRATES);
  }

  // Every line shape libtest's `--report-time` actually prints, taken from a
  // real run's log rather than from memory of the format. The FAILED row is
  // the one that matters most: a test that failed still spent its time, and
  // a budget that weighed only the passing ones would let a slow test hide
  // behind a broken one.
  #[test]
  fn a_timed_result_line_gives_up_its_name_and_its_seconds() {
    assert_eq!(
      timed_test("test grammar::tests::a_walk ... ok <16.346s>"),
      Some(("grammar::tests::a_walk", 16.346))
    );
    assert_eq!(
      timed_test("test date::tests::a_rule ... FAILED <0.001s>"),
      Some(("date::tests::a_rule", 0.001))
    );
    assert_eq!(
      timed_test("test x ... ok <665.596s>"),
      Some(("x", 665.596)),
      "the slowest test in the job today"
    );
  }

  // The exemption is invisible to the budget by construction: an ignored test
  // never runs, so libtest prints no time for it and there is nothing for the
  // budget to weigh. This is the assertion that says so, because "it cannot
  // happen" is exactly the kind of claim that stops being true when a format
  // changes.
  #[test]
  fn an_ignored_test_carries_no_time_and_is_counted_instead() {
    let line = "test auth::tests::the_body ... ignored, 181_896 field values, each derived twice";
    assert_eq!(timed_test(line), None);
    assert!(is_ignored(line));

    assert!(is_ignored("test x ... ignored"));
  }

  // The refuting side, and the reason this reads the OUTCOME rather than the
  // line: this workspace has a test whose own name ends in `_is_ignored`, and
  // a substring search for the word would count it as one that never ran.
  #[test]
  fn a_test_named_for_ignoring_something_is_not_an_ignored_test() {
    let line = "test conditional::tests::an_unrecognised_field_is_ignored ... ok <0.001s>";
    assert!(!is_ignored(line));
    assert_eq!(
      timed_test(line),
      Some((
        "conditional::tests::an_unrecognised_field_is_ignored",
        0.001
      ))
    );
  }

  // The watchdog's footing: the tail libtest leaves in the pipe while a test
  // runs. It has to match a tail that ENDS at the ellipsis and nothing else —
  // a tail already carrying part of a result means the run is answering, and
  // restarting the clock on it would keep a stuck test off the clock forever.
  #[test]
  fn an_unterminated_line_names_the_test_now_running() {
    assert_eq!(
      starting_test("test date::tests::a_brute_force ... "),
      Some("date::tests::a_brute_force")
    );
    assert_eq!(
      starting_test("test date::tests::a_brute_force ..."),
      Some("date::tests::a_brute_force"),
      "the trailing space is libtest's, not something to depend on"
    );

    for tail in [
      "test date::tests::a_brute_force ... ok <1.0",
      "test date::tests::a_brute_force",
      "running 519 tests",
      "",
      "   Compiling http-semantics v0.1.0",
    ] {
      assert_eq!(starting_test(tail), None, "{tail}");
    }
  }

  // Everything else in the log is not a result line, and none of it may be
  // read as one — a summary counted as a test would put a number in the
  // census that belongs to no test at all.
  #[test]
  fn nothing_but_a_result_line_is_read_as_one() {
    for line in [
      "running 519 tests",
      "test result: ok. 519 passed; 0 failed; 4 ignored; 0 measured",
      "   Compiling http-semantics v0.1.0",
      "",
      "test malformed ... ok <s>",
      "test no-time-here ... ok",
    ] {
      assert_eq!(timed_test(line), None, "{line}");
      assert!(!is_ignored(line), "{line}");
    }
  }
}
