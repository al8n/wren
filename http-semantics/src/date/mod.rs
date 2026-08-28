//! RFC 9110 §5.6.7 `HTTP-date`, over raw bytes.
//!
//! One grammar serves every field that carries a timestamp — `Date`,
//! `Last-Modified`, `If-Modified-Since` and `If-Unmodified-Since` among them —
//! and no part of it belongs to a wire format, which is why it is here.
//!
//! ```text
//! HTTP-date    = IMF-fixdate / obs-date
//!
//! IMF-fixdate  = day-name "," SP date1 SP time-of-day SP GMT
//! ; fixed length/zone/capitalization subset of the format
//! ; see Section 3.3 of [RFC5322]
//!
//! day-name     = %s"Mon" / %s"Tue" / %s"Wed"
//!              / %s"Thu" / %s"Fri" / %s"Sat" / %s"Sun"
//!
//! date1        = day SP month SP year
//!              ; e.g., 02 Jun 1982
//!
//! day          = 2DIGIT
//! month        = %s"Jan" / %s"Feb" / %s"Mar" / %s"Apr"
//!              / %s"May" / %s"Jun" / %s"Jul" / %s"Aug"
//!              / %s"Sep" / %s"Oct" / %s"Nov" / %s"Dec"
//! year         = 4DIGIT
//!
//! GMT          = %s"GMT"
//!
//! time-of-day  = hour ":" minute ":" second
//!              ; 00:00:00 - 23:59:60 (leap second)
//!
//! hour         = 2DIGIT
//! minute       = 2DIGIT
//! second       = 2DIGIT
//!
//! obs-date     = rfc850-date / asctime-date
//!
//! rfc850-date  = day-name-l "," SP date2 SP time-of-day SP GMT
//! date2        = day "-" month "-" 2DIGIT
//!              ; e.g., 02-Jun-82
//!
//! day-name-l   = %s"Monday" / %s"Tuesday" / %s"Wednesday"
//!              / %s"Thursday" / %s"Friday" / %s"Saturday"
//!              / %s"Sunday"
//!
//! asctime-date = day-name SP date3 SP time-of-day SP year
//! date3        = month SP ( 2DIGIT / ( SP 1DIGIT ))
//!              ; e.g., Jun  2
//! ```
//!
//! # Reading and writing carry different obligations
//!
//! §5.6.7 states them in one breath: "A recipient that parses a timestamp value
//! in an HTTP field MUST accept all three HTTP-date formats.  When a sender
//! generates a field that contains one or more timestamps defined as HTTP-date,
//! the sender MUST generate those timestamps in the IMF-fixdate format."
//! [`parse_http_date`] is the reading half, so it takes all three;
//! [`format_imf_fixdate`] is the writing half, and it writes ONE. The asymmetry
//! is §5.6.7's rather than a gap here: a writer that could also emit an
//! `rfc850-date` would be a way for a caller of this crate to violate that
//! second MUST, so no argument to this module selects an output format and the
//! obsolete two are read and never produced.
//!
//! The `%s` prefixes above are RFC 5234 case-SENSITIVE string notation, and
//! §5.6.7 says it again in prose: "HTTP-date is case sensitive." So `sun` and
//! `SUN` are not `day-name`s here, and nothing in this module compares a name
//! case-insensitively.
//!
//! # The `day-name` a sender writes is not its own to choose
//!
//! §5.6.7 hands five of `IMF-fixdate`'s constituents to another specification:
//! "The semantics of day-name, day, month, year, and time-of-day are the same
//! as those defined for the Internet Message Format constructs with the
//! corresponding name" — RFC 5322, Section 3.3. That section then collects its
//! own requirements into one sentence: "A date-time specification MUST be
//! semantically valid.  That is, the day-of-week (if included) MUST be the day
//! implied by the date, the numeric day-of-month MUST be between 1 and the
//! number of days allowed for the specified month (in the specified year), the
//! time-of-day MUST be in the range 00:00:00 through 23:59:60 …, and the last
//! two digits of the zone MUST be within the range 00 through 59."
//!
//! (The ellipsis drops a parenthetical citing RFC 1305, whose square brackets
//! rustdoc would read as an intra-doc link; `quote-check` grades what remains
//! on either side of it.)
//!
//! `IMF-fixdate`'s `day-name` is what fills RFC 5322's `day-of-week` slot —
//! that specification's `date-time` is `[ day-of-week "," ] date time` and its
//! `day-of-week` is a `day-name` — so a sender's is the day the date implies
//! rather than a column it may fill in freely. [`format_imf_fixdate`] DERIVES
//! it for that reason and not merely for tidiness: echoing back whatever a
//! peer wrote would be a way for a caller of this crate to violate that MUST,
//! exactly as emitting an `rfc850-date` would violate §5.6.7's own.
//!
//! Three of that sentence's four clauses can reach an `IMF-fixdate`, and this
//! module satisfies all three where they bind — at the sender. The `day-name`
//! is the one above; the day-of-month is checked against the length of its own
//! month in its own year; `time-of-day` is checked against `00:00:00` through
//! `23:59:60`. The fourth governs a numeric zone offset, which `IMF-fixdate`
//! cannot spell: its zone is the literal `GMT`.
//!
//! **`year` is the constituent the two halves treat DIFFERENTLY**, and that is
//! a fourth clause rather than an oversight in the first three. RFC 5322 §3.3
//! also says "The year is any numeric year 1900 or later". This module READS a
//! year below 1900 and refuses to WRITE one.
//!
//! It does not bind the reader, for three reasons. The MUST quoted above is
//! where §3.3 collects what a date-time has to satisfy, and `year` is the one
//! constituent it does not name — the range sentence is declarative prose in an
//! earlier paragraph. §5.6.7 re-spells the production itself as
//! `year = 4DIGIT`, narrower at the top than RFC 5322's `4*DIGIT` and open at
//! the bottom, so the two admissible sets already differ in BOTH directions and
//! "the same semantics" cannot mean the same set. And §5.6.7 tells a recipient
//! the opposite of strictness — "Recipients of timestamp values are encouraged
//! to be robust in parsing timestamps unless otherwise restricted by the field
//! definition" — about a year that is a real, unambiguous instant every
//! recipient reads alike. So `Sat, 01 Jan 0000 00:00:00 GMT` parses.
//!
//! It does bind the writer, and robustness is no argument for one: a permissive
//! recipient CARRIES someone else's fault, a permissive sender COMMITS one.
//! Every other clause of §3.3 is discharged here at the sender for that same
//! reason, and so is this one — [`format_imf_fixdate`] refuses a year below
//! 1900 ([`DateError::YearBefore1900`]), as it already refuses one above 9999
//! for `year = 4DIGIT`'s own reason. Two ends, two rules, two variants, so a
//! test names which one refused.
//!
//! What the asymmetry costs is that the round trip is not total: a year this
//! reader accepts is one this writer will not write back. §5.6.7 never asks it
//! to be — the same is already true of an `rfc850-date`, of an `asctime-date`,
//! and of a `day-name` that contradicts its own date.
//!
//! # Which of the three it is, decided once
//!
//! [`parse_http_date`] reads the byte at index 3 — the column where a `day-name`
//! ends — and hands the input to that format's rules and no other's. A `,`
//! there is `IMF-fixdate`, an SP is `asctime-date`, and any other byte is
//! `rfc850-date`, whose `day-name-l` is six letters at its shortest, so the
//! fourth byte of one is always a letter. An input with no byte at index 3 is
//! none of them.
//!
//! Trying all three and keeping the first that succeeds is the obvious
//! alternative, and it is not used here because its failure mode is silent:
//! [`DateError`] names the rule that refused, so a test can assert the REASON
//! rather than the refusal, and a trial-parse reports whatever the LAST attempt
//! happened to break — a malformed `rfc850-date` would be refused for breaking
//! a rule of `asctime-date`, a format its sender never claimed to be writing.
//!
//! # The two-digit year, and the clock this crate does not have
//!
//! §5.6.7: "Recipients of a timestamp value in rfc850-date format, which uses a
//! two-digit year, MUST interpret a timestamp that appears to be more than 50
//! years in the future as representing the most recent year in the past that
//! had the same last two digits."
//!
//! The future is measured against the recipient's clock, and this crate has
//! none — a clock is an I/O capability its caller owns. So the clock arrives as
//! an ARGUMENT, which is what the crate root's membership rule requires of
//! every input that is not the bytes: [`parse_http_date_from`] takes the
//! INSTANT to measure from, as seconds since the POSIX epoch. It is the
//! `now: I` that `websocket-proto`'s connection already takes from its caller,
//! spelled for a parser.
//!
//! **An instant, because a year cannot express the rule.** Both sides of the
//! sentence above are timestamps: the subject is "a timestamp that appears to
//! be more than 50 years in the future", and what it is more than fifty years
//! in the future OF is the recipient's current instant. Measuring the rule in
//! whole years silently rounds one of them, and the two answers then disagree
//! for a whole year at a time. A recipient whose clock reads 2026-01-01 must
//! read `Friday, 31-Dec-76 00:00:00 GMT` as 1976 — its fifty-year anniversary
//! is 2076-01-01, and that timestamp is nearly a year past it — while the same
//! recipient on 2026-12-31 must read it as 2076. Handed only the year 2026,
//! this module could not tell those two recipients apart, and answered 2076 for
//! both.
//!
//! So the comparison here is the sentence's own: the candidate timestamp
//! against the exact fifty-year anniversary of `now_unix_seconds`, to the
//! second. `fifty_year_window` has the arithmetic and the one calendar corner
//! it has to name — named in plain backticks rather than linked, because it is
//! private and this doc is not.
//!
//! **It reaches exactly one of the three formats.** The sentence above scopes
//! itself to `rfc850-date`, and the grammar agrees: `date2` carries the only
//! two-digit YEAR in the section, while `date1` and `asctime-date` both spell
//! `year = 4DIGIT`. (§5.6.7's other `2DIGIT`s are a day of the month, an hour,
//! a minute and a second.) So the argument is handed to the `rfc850-date`
//! reader and to no other, and the code is what says so rather than this
//! paragraph.
//!
//! [`parse_http_date`] supplies a fixed anchor for a caller that has no clock
//! to offer, which is most of them; its own doc names the window that fixes,
//! and what it costs.
//!
//! # What is not checked, and why
//!
//! **The day name against the date, ON THE WAY IN.**
//! `Sun, 07 Nov 1994 08:49:37 GMT` names a Monday and is read as 7 November
//! 1994. The two ARE
//! required to agree — the section above has the requirement and the writer
//! discharges it — but that requirement binds whoever GENERATED the timestamp,
//! and to a recipient §5.6.7 says the opposite of strictness about a fault it
//! did not commit: "Recipients of timestamp values are encouraged to be robust
//! in parsing timestamps unless otherwise restricted by the field definition."
//! So this reader carries the sender's mistake instead of refusing it, and a
//! caller that needs the weekday takes it from the DATE, getting one answer for
//! all three formats. [`format_imf_fixdate`] is such a caller, which is why the
//! input above is written back as `Mon, 07 Nov 1994 08:49:37 GMT` and one
//! instant has exactly one spelling.
//!
//! **A zone in `asctime-date`.** It carries none to check: "The first two
//! formats indicate UTC by the three-letter abbreviation for Greenwich Mean
//! Time, `GMT`, a predecessor of the UTC name; values in the asctime format are
//! assumed to be in UTC."
//!
//! What IS checked beyond the grammar is the day of the month against its own
//! month and year: `day = 2DIGIT` admits `31 Nov`, and admitting it here would
//! answer 1 December — a real instant for a date that does not exist, which is
//! worse than a refusal.
//!
//! # Panic-freedom, and the arithmetic
//!
//! Every read goes through `get` rather than an index, no offset is used
//! before the format's length has been fixed, and the epoch conversion is
//! written so that no operator in it can overflow or divide: `saturating_*`
//! for the sums and products, `div_euclid` for the four divisions Howard
//! Hinnant's `days_from_civil` needs. The lint wall is one reason —
//! `arithmetic_side_effects` and `integer_division` both fire on the operator
//! whatever its operands — and the link-time proof is the other: this is a leaf
//! primitive of the kind `tests/no_panic.rs` covers, where a panic edge the
//! optimizer cannot fold away is a failed link rather than a warning.
//!
//! The writer is held to the same rule from the other side. Its one bounds
//! check is `first_chunk_mut`, which ANSWERS the buffer's size rather than
//! trusting it, and the twenty-nine bytes are then one assignment through the
//! fixed-size reference it hands back — so there is no offset to get wrong and
//! a partial write is not expressible. Its digits are `div_euclid` and
//! `rem_euclid` by constants and a match on the remainder, rather than any
//! formatting machinery, which would want an allocator this crate does not
//! have and a write that can fail.
//!
//! Saturation never actually happens for anything [`parse_http_date`] admits.
//! `year = 4DIGIT` caps the year at 9999, so the largest magnitude any
//! intermediate reaches is under 3.2e11 — seven orders of magnitude short of
//! [`i64::MAX`]. It is spelled saturating so the conversion is a total function
//! with no fallible arm, not because the bound is in doubt.
//!
//! [`parse_http_date_from`] widens that bound without troubling it. Its
//! fifty-year window is measured from an INSTANT the caller names — any
//! [`i64`], including both ends of it — so an `rfc850-date` read against a
//! far-future clock can be answered a year above `4DIGIT`'s ceiling, up to
//! [`u16::MAX`]. `IMF-fixdate` has no column for such a year, and it is one of
//! the two years [`format_imf_fixdate`] refuses.
//!
//! No `i64` the caller can pass makes an intermediate there saturate, and the
//! reason is structural rather than a bound to re-check: the window compares
//! `(days, seconds-of-day)` PAIRS and never forms a seconds-since-the-epoch
//! product at all. The largest quantity it computes is a day count, and a day
//! count is 86400 times smaller than the instant it came from.
//!
//! Where the window's own answer is not a year this module can hold, the PARSE
//! refuses, as [`DateError::FiftyYearWindow`]. It is the one place here where
//! saturating would have been a choice rather than a formality, and the choice
//! is against it: every other saturation above is provably unreachable for the
//! domain its operands come from, so it changes no answer, while clamping a
//! year changes the answer and hands it back as `Ok`. A caller cannot see a
//! clamp; it can see a refusal.

/// Why a byte string is not an RFC 9110 §5.6.7 date.
///
/// One variant per rule that can refuse, so a test can assert the REASON rather
/// than the refusal — a parser that rejects everything passes an `is_err()`
/// test on every one of these.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum DateError {
  /// The input is not one of the three formats' fixed lengths.
  ///
  /// `IMF-fixdate` is 29 bytes and `asctime-date` is 24; `rfc850-date` is its
  /// own `day-name-l` plus 24, which is what makes it the one format whose name
  /// is read before its length can be. An input of fewer than four bytes is
  /// here too: nothing that short can even be told apart from the other two,
  /// let alone be one of them.
  #[error("input is not the length its format fixes")]
  Length,
  /// The day name is not one of the seven, in the case the format requires.
  #[error("day name is not one of the seven")]
  DayName,
  /// The month is not one of the twelve, in the case the format requires.
  #[error("month is not one of the twelve")]
  Month,
  /// The year is not the digits its format spells — `year = 4DIGIT`, or the
  /// `2DIGIT` inside `date2`.
  ///
  /// About the LITERAL, and only about it: every four-digit string the grammar
  /// admits is a year this module converts, so once they are digits there is no
  /// range left for a `date1` or an `asctime-date` to violate. A `date2`'s two
  /// digits are always a year SOMEWHERE; what can fail for them is the fifty-
  /// year rule applied to the caller's reference year, and that is a different
  /// rule refusing —
  /// [`FiftyYearWindow`](Self::FiftyYearWindow).
  #[error("year is not the digits its format spells")]
  Year,
  /// §5.6.7's fifty-year rule chose a year this module cannot represent.
  ///
  /// Reachable only from an `rfc850-date`, the one format with a `2DIGIT` year,
  /// and only from the instant its caller supplied: the rule is measured from
  /// that instant, so the year it names can fall outside `u16` at either end.
  /// A `now_unix_seconds` early enough leaves it asking for a year BEFORE year
  /// 0 — there is no century below it to step back into — and one late enough
  /// puts it above `u16::MAX`.
  ///
  /// Where each band BEGINS is a function of the candidate's own month, day and
  /// time of day as well as of `now_unix_seconds`, because the rule compares
  /// whole timestamps: with a reference instant in year 49, `49` is answered
  /// and `99` steps back to a year before 0, and moving the reference forward
  /// by a day moves which of them does. That is the rule rather than a
  /// looseness — a year-only window could not express it, and used to answer
  /// the wrong century for a year at a time.
  ///
  /// A REFUSAL rather than a clamp, and the distinction is the caller's, not
  /// this module's. A clamped year parses successfully: the caller is handed an
  /// [`HttpDate`] whose [`year`](HttpDate::year) is 65535 or 0, whose
  /// [`unix_seconds`](HttpDate::unix_seconds) describes that instant, and which
  /// carries nothing to say the rule named a different year — a year that does
  /// not even end in the digits the sender wrote. Only a refusal is visible.
  ///
  /// Neither end is reachable from a clock: they sit within a couple of
  /// centuries of year 0 and of year 65535.
  #[error("the fifty-year rule's year is not one this parser can represent")]
  FiftyYearWindow,
  /// A day-of-month, hour, minute or second is out of range, or not a digit.
  ///
  /// The `:` between `hour`, `minute` and `second` is
  /// [`Separator`](Self::Separator) rather than this one: this variant is about
  /// what a field SAYS, that one about the layout it is said in. An hour above
  /// 23, a minute above 59, a second above 60 (`time-of-day`'s own comment
  /// admits the leap second) and a day past the end of its own month are all
  /// this one.
  #[error("day-of-month, hour, minute or second is out of range or not a digit")]
  TimeOfDay,
  /// A byte the format fixes at that column — the SP inside `date1` and
  /// `date3`, the `-` inside `date2`, the `:` inside `time-of-day` — is not the
  /// one §5.6.7 spells there.
  #[error("a separator the format fixes is not there")]
  Separator,
  /// The zone is present but is not `GMT`, which §5.6.7 fixes for two of the
  /// three formats.
  ///
  /// Asked of the whole `SP GMT` tail rather than of its three letters alone,
  /// so an input that loses the space before them is a zone that is not `GMT`
  /// rather than a separate refusal. `asctime-date` carries no zone and never
  /// produces this.
  #[error("zone is not GMT")]
  NotGmt,
  /// The caller's output slice was shorter than [`IMF_FIXDATE_LEN`].
  ///
  /// About writing rather than reading, and it is not [`Length`](Self::Length):
  /// that one is the INPUT not being one of the three formats' fixed lengths,
  /// and this is a different rule refusing, so a test asserting either one
  /// names which. Nothing is written when it is returned — see
  /// [`format_imf_fixdate`].
  #[error("output buffer is shorter than an IMF-fixdate")]
  BufferTooSmall,
  /// The year is before 1900, which a sender may not generate.
  ///
  /// RFC 9110 §5.6.7 gives `year` the semantics of the Internet Message Format
  /// construct of that name, and RFC 5322 §3.3 says "The year is any numeric
  /// year 1900 or later". [`format_imf_fixdate`] is this module's sender, so
  /// that is where the bound is applied; the module doc has why it is not
  /// applied to the reader as well.
  ///
  /// Its own rule, and so its own variant rather than [`Year`](Self::Year).
  /// The two refuse at the two ends of the same field for two DIFFERENT
  /// reasons: above 9999 there is no column in `date1`'s `year = 4DIGIT` to
  /// write the digits in, while 1899 has four digits and a column for each of
  /// them and is refused for what the year MEANS. Folding them together would
  /// leave a test asserting a refusal it cannot attribute — and would let a
  /// writer that had lost the `4DIGIT` ceiling pass the test written for the
  /// 1900 floor.
  ///
  /// Nothing is written when it is returned, on the same terms as
  /// [`BufferTooSmall`](Self::BufferTooSmall).
  #[error("year is before 1900, which a sender may not generate")]
  YearBefore1900,
}

/// One instant, as RFC 9110 §5.6.7 spells it: a civil date and a time of day,
/// always in UTC.
///
/// Holds the fields the grammar names and nothing derived from them.
/// [`unix_seconds`](Self::unix_seconds) computes the epoch offset on demand
/// rather than storing it alongside, so there is one representation of the
/// instant and no pair of fields a later constructor could leave disagreeing.
/// It is also what the two accessors want in opposite directions:
/// [`year`](Self::year) answers with the year the sender wrote — or, for a
/// `2DIGIT` year, the one §5.6.7's fifty-year rule chose — without going
/// through the epoch arithmetic at all.
///
/// Every field is in range by construction: the only thing that builds one is
/// [`parse_http_date`], through the one constructor that range-checks.
///
/// `Ord` and `PartialOrd` compare in **civil order** — year, month, day, hour,
/// minute, then second — not [`unix_seconds`](Self::unix_seconds) order: a
/// leap second (`23:59:60`) sorts strictly before the midnight that follows
/// it, even though the two share a `unix_seconds` value.
// `Ord` is DERIVED, and the field order below is what makes that correct: the
// declaration runs year, month, day, hour, minute, second, so the derived
// lexicographic comparison IS civil order. It must not be written over
// [`unix_seconds`](Self::unix_seconds) instead — a leap second shares that
// value with the midnight that follows it, so an instant-ordering would answer
// `Equal` for two values structural `Eq` calls unequal, which is an unlawful
// `Ord`. Civil order also sorts `23:59:60` strictly before the following
// midnight, which is the true UTC order. Reordering the fields below silently
// breaks the comparison; they are declared coarsest-first for this reason.
//
// Two tests defend this — `ordering_is_civil_and_agrees_with_equality` and
// `the_leap_second_precedes_the_midnight_it_shares_an_instant_with` — but both
// compare through `<`/`>`, which resolve to `PartialOrd`; a hand-written `Ord`
// over `unix_seconds` with `PartialOrd` left derived passes both, silently
// mismatched, and only clippy's deny-by-default `derive_ord_xor_partial_ord`
// catches it. An `#[allow]` on that lint is the tests' blind spot.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct HttpDate {
  year: u16,
  month: u8,
  day: u8,
  hour: u8,
  minute: u8,
  second: u8,
}

impl HttpDate {
  /// The civil year, all four digits.
  ///
  /// For an `rfc850-date` this is the year §5.6.7's fifty-year rule chose for
  /// the `2DIGIT` the sender wrote; the module doc has the window it is chosen
  /// from.
  #[inline]
  pub const fn year(&self) -> u16 {
    self.year
  }

  /// Seconds since the POSIX epoch, 1970-01-01T00:00:00Z. Negative for an
  /// instant before it, which `year = 4DIGIT` admits.
  ///
  /// A leap second (`time-of-day`'s `23:59:60`) lands on the same value as the
  /// `00:00:00` that follows it, POSIX time having no representation of its own
  /// for one. [`year`](Self::year) still answers with the civil year the sender
  /// wrote.
  #[inline]
  pub const fn unix_seconds(&self) -> i64 {
    let days = days_from_civil(self.year as i64, self.month as i64, self.day as i64);
    days
      .saturating_mul(SECONDS_PER_DAY)
      .saturating_add(seconds_since_midnight(self.hour, self.minute, self.second))
  }

  /// The only thing that builds an [`HttpDate`], and so the only place its
  /// in-range invariant has to hold.
  ///
  /// `month` arrives already one of the twelve — [`month_number`] answers
  /// nothing else — which leaves the day against the length of that month in
  /// that year, and the three time-of-day fields against `time-of-day`'s own
  /// comment, `00:00:00 - 23:59:60 (leap second)`.
  fn assemble(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
  ) -> Result<Self, DateError> {
    if !(1..=days_in_month(year, month)).contains(&day) || hour > 23 || minute > 59 || second > 60 {
      return Err(DateError::TimeOfDay);
    }
    Ok(Self {
      year,
      month,
      day,
      hour,
      minute,
      second,
    })
  }
}

/// Reads an RFC 9110 §5.6.7 `HTTP-date` — all three formats, as a recipient
/// must — measuring §5.6.7's fifty-year rule from `now_unix_seconds`.
///
/// `now_unix_seconds` is the recipient's own current instant, in seconds since
/// the POSIX epoch, 1970-01-01T00:00:00Z, negative before it. §5.6.7 has a
/// recipient read a `2DIGIT` year by asking whether the TIMESTAMP it denotes is
/// more than fifty years past that instant, so the rule needs a clock; this
/// crate has none, and the crate root's membership rule is that such an input
/// arrives as an argument rather than as state held here.
///
/// **An instant and not a year**, because the rule cannot be stated in years:
/// on 2026-01-01 a recipient must read `Friday, 31-Dec-76 00:00:00 GMT` as
/// 1976, and on 2026-12-31 the same recipient must read it as 2076. The module
/// doc has the sentence both halves come from.
///
/// **Seconds since the epoch and not an [`HttpDate`]**, because seconds since
/// the epoch is what a clock answers. `SystemTime`'s duration since
/// `UNIX_EPOCH`, a POSIX `time_t` and an embedded RTC's counter are this number
/// already, while an [`HttpDate`] would put the civil-calendar conversion this
/// module already owns on every caller — or make this module publish a second
/// constructor whose only purpose is to feed this argument. It is also what
/// [`unix_seconds`](HttpDate::unix_seconds) answers, so a `Date` field this
/// parser has read is itself a reference instant for the next call.
///
/// Every [`i64`] denotes an instant, so this argument has no malformed value
/// and adds no refusal of its own. What can still refuse is the RULE, when the
/// year it names is one no `u16` holds — see [`DateError::FiftyYearWindow`].
///
/// It reaches ONLY an `rfc850-date`, the one format of the three whose year is
/// two digits. `IMF-fixdate` and `asctime-date` both carry `year = 4DIGIT`, so
/// for them every `now_unix_seconds` gives the same answer — and that is
/// visible rather than promised: the argument is passed to one of the three
/// readers below.
///
/// The value is the field's, already OWS-trimmed
/// ([`grammar::trim_ows`](crate::grammar::trim_ows)): §5.6.7 fixes each
/// format's length exactly, so whitespace the field grammar allows around the
/// value is a length this refuses.
///
/// # Errors
///
/// [`DateError`], naming the rule that refused. The format is chosen from the
/// input's own shape first, and every rule applied after that is one of that
/// format's; see the module doc.
pub fn parse_http_date_from(v: &[u8], now_unix_seconds: i64) -> Result<HttpDate, DateError> {
  // The one column where the three differ before any field has been read:
  // `day-name ","`, `day-name SP`, or a `day-name-l` still spelling itself out.
  match v.get(3).copied() {
    Some(b',') => imf_fixdate(v),
    Some(b' ') => asctime_date(v),
    // `now_unix_seconds` goes to this reader and to no other, because `date2`
    // is the only one of the three that spells its year in two digits.
    Some(_) => rfc850_date(v, now_unix_seconds),
    None => Err(DateError::Length),
  }
}

/// Reads an RFC 9110 §5.6.7 `HTTP-date` with the fifty-year window anchored at
/// a fixed instant, for a caller with no clock of its own to measure from.
///
/// Exactly `parse_http_date_from(v, REFERENCE_INSTANT)`, and `REFERENCE_INSTANT`
/// is 2026-01-01T00:00:00Z. Its fifty-year anniversary is 2076-01-01T00:00:00Z,
/// so `94` reads as 1994, `00` through `75` read as 2000 through 2075, `77`
/// through `99` read as 1977 through 1999, and `76` reads as 1976 for every
/// timestamp of that year except the one that IS the anniversary,
/// `01-Jan-76 00:00:00 GMT`.
///
/// **The anchor is consulted only for an `rfc850-date`**, the obsolete
/// two-digit form — the other two formats spell `year = 4DIGIT`, and
/// `IMF-fixdate` is the only one §5.6.7 permits a sender to generate at all. So
/// what the fixed anchor costs is bounded to that form, and it is exactly the
/// timestamps lying between this anniversary and the recipient's own: a real
/// clock is past 2026-01-01, its anniversary is past 2076-01-01, and every
/// `rfc850-date` in between is read here as a century earlier than that
/// recipient would read it. That set grows by a day for every day the anchor is
/// not moved, and is empty on the day it was chosen.
///
/// A caller that HAS a clock passes its instant to [`parse_http_date_from`] and
/// gets §5.6.7's rule as the section states it.
///
/// # Errors
///
/// [`DateError`], exactly as [`parse_http_date_from`] returns it.
pub fn parse_http_date(v: &[u8]) -> Result<HttpDate, DateError> {
  parse_http_date_from(v, REFERENCE_INSTANT)
}

/// Writes an RFC 9110 §5.6.7 `IMF-fixdate` into `out`, and answers the number
/// of bytes it wrote.
///
/// **One format, because §5.6.7 permits a sender exactly one.** The reading
/// half takes all three; this takes no argument that could select another, so a
/// caller of this crate has no way to generate an obsolete form. The module doc
/// has the section's two sentences.
///
/// Always [`IMF_FIXDATE_LEN`] on success — a fixed size, not a maximum — and
/// bytes past it are the caller's own. On any error `out` is untouched: it is
/// sized BEFORE a byte moves and the twenty-nine then land in one assignment,
/// so a caller that ignores the error cannot ship a truncated date.
///
/// The `day-name` is DERIVED from the date rather than carried across from
/// whatever was read, and a sender is REQUIRED to write it that way rather than
/// merely well advised to. RFC 9110 §5.6.7 gives `day-name` the semantics of
/// the Internet Message Format construct of that name, and RFC 5322 §3.3
/// requires that "the day-of-week (if included) MUST be the day implied by the
/// date". So `Sun, 07 Nov 1994 08:49:37 GMT` is READ as the 7th — a recipient
/// is told to be robust about a fault it did not commit — and WRITTEN back as
/// `Mon, 07 Nov 1994 08:49:37 GMT`. The module doc has both halves.
///
/// **The year is bounded at BOTH ends, and by two different rules.** RFC 9110
/// §5.6.7 hands `year`'s semantics to RFC 5322 §3.3, which says "The year is
/// any numeric year 1900 or later" — a requirement on whoever GENERATES a
/// timestamp, which here is this function. Above, `date1`'s own
/// `year = 4DIGIT` has no column for a fifth digit. [`parse_http_date_from`] is
/// deliberately permissive at both ends, for the reasons the module doc gives,
/// so both refusals are reachable from a date this crate itself produced.
///
/// # Errors
///
/// [`DateError::BufferTooSmall`] when `out` is shorter than
/// [`IMF_FIXDATE_LEN`].
///
/// [`DateError::Year`] for a year past four digits, which is reachable rather
/// than defensive: [`parse_http_date_from`] measures §5.6.7's fifty-year window
/// from an instant its CALLER supplies, and an `rfc850-date` read against a
/// far-future clock can land past 9999 — a year `date1`'s `year = 4DIGIT` has
/// no column for. Refused rather than truncated, since the truncation would be
/// a real date some thousands of years from the one asked for.
///
/// [`DateError::YearBefore1900`] for a year below 1900, equally reachable:
/// `year = 4DIGIT` admits `0000`, and this module reads one.
///
/// Nothing else can refuse. Every other field of an [`HttpDate`] is in range by
/// construction.
pub fn format_imf_fixdate(date: &HttpDate, out: &mut [u8]) -> Result<usize, DateError> {
  // First, and it ANSWERS the buffer's size rather than trusting it: the
  // fixed-size reference it hands back is what makes the write below one
  // assignment with no offset to get wrong and no partial state to leave.
  let Some(out) = out.first_chunk_mut::<IMF_FIXDATE_LEN>() else {
    return Err(DateError::BufferTooSmall);
  };
  // Two rules, two refusals, in the order the field is spelled. Neither is
  // folded into the other: see `DateError::YearBefore1900`.
  if date.year > MAX_FOUR_DIGIT_YEAR {
    return Err(DateError::Year);
  }
  if date.year < MIN_RFC5322_YEAR {
    return Err(DateError::YearBefore1900);
  }
  let [name0, name1, name2] = day_name(days_from_civil(
    i64::from(date.year),
    i64::from(date.month),
    i64::from(date.day),
  ));
  let [month0, month1, month2] = month_name(date.month);
  let [day0, day1] = two_ascii_digits(date.day);
  let [year0, year1, year2, year3] = four_ascii_digits(date.year);
  let [hour0, hour1] = two_ascii_digits(date.hour);
  let [minute0, minute1] = two_ascii_digits(date.minute);
  let [second0, second1] = two_ascii_digits(date.second);
  // The columns `imf_fixdate` reads, in the other direction: its own map of
  // them is on that function.
  *out = [
    name0, name1, name2, b',', b' ', day0, day1, b' ', month0, month1, month2, b' ', year0, year1,
    year2, year3, b' ', hour0, hour1, b':', minute0, minute1, b':', second0, second1, b' ', b'G',
    b'M', b'T',
  ];
  Ok(IMF_FIXDATE_LEN)
}

/// `IMF-fixdate = day-name "," SP date1 SP time-of-day SP GMT`, whose 29 bytes
/// sit at fixed columns:
///
/// ```text
/// Sun, 06 Nov 1994 08:49:37 GMT
/// 0    5  8   12   17    23 26
/// ```
///
/// The `,` at index 3 is what chose this format and is not read again.
fn imf_fixdate(v: &[u8]) -> Result<HttpDate, DateError> {
  if v.len() != IMF_FIXDATE_LEN {
    return Err(DateError::Length);
  }
  if !is_day_name(v.get(..3)) {
    return Err(DateError::DayName);
  }
  separator(v, 4, b' ')?;
  let day = two_digits(v, 5, DateError::TimeOfDay)?;
  separator(v, 7, b' ')?;
  let month = month_number(v.get(8..11))?;
  separator(v, 11, b' ')?;
  let year = four_digits(v, 12)?;
  separator(v, 16, b' ')?;
  let (hour, minute, second) = time_of_day(v, 17)?;
  gmt(v, 25)?;
  HttpDate::assemble(year, month, day, hour, minute, second)
}

/// `rfc850-date = day-name-l "," SP date2 SP time-of-day SP GMT`.
///
/// The one format whose length is not a constant, `day-name-l` running from six
/// letters to nine. So the name is read FIRST and the length rule is applied to
/// what it says: the order is the grammar's here rather than a choice.
fn rfc850_date(v: &[u8], now_unix_seconds: i64) -> Result<HttpDate, DateError> {
  let Some(name_len) = DAY_NAMES_LONG
    .iter()
    .find(|name| v.starts_with(name))
    .map(|name| name.len())
  else {
    return Err(DateError::DayName);
  };
  if v.len() != name_len.saturating_add(RFC850_LEN_AFTER_DAY_NAME) {
    return Err(DateError::Length);
  }
  let at = |offset: usize| name_len.saturating_add(offset);
  separator(v, at(0), b',')?;
  separator(v, at(1), b' ')?;
  let day = two_digits(v, at(2), DateError::TimeOfDay)?;
  separator(v, at(4), b'-')?;
  let month = month_number(v.get(at(5)..at(8)))?;
  separator(v, at(8), b'-')?;
  let two_digit_year = two_digits(v, at(9), DateError::Year)?;
  separator(v, at(11), b' ')?;
  let (hour, minute, second) = time_of_day(v, at(12))?;
  gmt(v, at(20))?;
  // The whole timestamp is read BEFORE the year is resolved, because §5.6.7's
  // rule is about the timestamp and not about the year alone: the month, the
  // day and the time of day are three of the five things that decide which side
  // of the fifty-year anniversary this value falls on. Every refusal the
  // columns can raise still comes first, so a malformed zone is `NotGmt` rather
  // than whatever the window would have said about it.
  let year = fifty_year_window(
    two_digit_year,
    month,
    day,
    seconds_since_midnight(hour, minute, second),
    now_unix_seconds,
  )?;
  HttpDate::assemble(year, month, day, hour, minute, second)
}

/// `asctime-date = day-name SP date3 SP time-of-day SP year`, whose 24 bytes
/// sit at fixed columns:
///
/// ```text
/// Sun Nov  6 08:49:37 1994
/// 0   4   8  11       20
/// ```
///
/// The SP at index 3 is what chose this format and is not read again.
fn asctime_date(v: &[u8]) -> Result<HttpDate, DateError> {
  if v.len() != ASCTIME_LEN {
    return Err(DateError::Length);
  }
  if !is_day_name(v.get(..3)) {
    return Err(DateError::DayName);
  }
  let month = month_number(v.get(4..7))?;
  separator(v, 7, b' ')?;
  // `date3 = month SP ( 2DIGIT / ( SP 1DIGIT ))` — the day is right-aligned in
  // two columns, so a single-digit one is written with a leading SP rather than
  // a leading zero. Both spellings are the grammar's: `06` is a `2DIGIT` too.
  let day = match v.get(8).copied() {
    Some(b' ') => digit(v, 9, DateError::TimeOfDay)?,
    _ => two_digits(v, 8, DateError::TimeOfDay)?,
  };
  separator(v, 10, b' ')?;
  let (hour, minute, second) = time_of_day(v, 11)?;
  separator(v, 19, b' ')?;
  let year = four_digits(v, 20)?;
  HttpDate::assemble(year, month, day, hour, minute, second)
}

/// `IMF-fixdate`'s fixed length: `day-name` (3) `","` SP `date1` (11) SP
/// `time-of-day` (8) SP `GMT` (3).
///
/// A fixed SIZE and not a maximum — the format has no variable-width field — so
/// it is both what [`format_imf_fixdate`] needs and exactly what it writes.
/// Public because a caller sizing a buffer for one has no other way to ask.
pub const IMF_FIXDATE_LEN: usize = 29;

/// `asctime-date`'s fixed length: `day-name` (3) SP `date3` (6) SP
/// `time-of-day` (8) SP `year` (4).
const ASCTIME_LEN: usize = 24;

/// Everything an `rfc850-date` carries after its `day-name-l`: `","` SP `date2`
/// (9) SP `time-of-day` (8) SP `GMT` (3).
const RFC850_LEN_AFTER_DAY_NAME: usize = 24;

/// The anchor [`parse_http_date`] supplies for a caller with no clock, and the
/// only clock reading this module holds. Every other caller passes one to
/// [`parse_http_date_from`].
///
/// 2026-01-01T00:00:00Z, the first instant of the year this parser was written
/// — the anchor a caller would have chosen on the day it shipped. 20454 days
/// from the epoch (fifty-six years of 365 days, plus the fourteen leap days of
/// 1972 through 2024), times [`SECONDS_PER_DAY`]. Its own anniversary, and so
/// the window it fixes, is on [`parse_http_date`].
const REFERENCE_INSTANT: i64 = 1_767_225_600;

/// The fifty years of §5.6.7's rule, as a number of CALENDAR years — the unit
/// the sentence uses, and not a count of seconds, which fifty years is not a
/// fixed number of.
const FIFTY_YEARS: i64 = 50;

/// The largest year `year = 4DIGIT` can spell, and so the largest
/// [`format_imf_fixdate`] can write.
///
/// No parse of a `date1` or an `asctime-date` can exceed it — both read exactly
/// four digits. [`fifty_year_window`] can, out of an `rfc850-date` measured
/// from a clock far enough in the future.
const MAX_FOUR_DIGIT_YEAR: u16 = 9999;

/// The smallest year a sender may generate, and so the smallest
/// [`format_imf_fixdate`] will write: RFC 5322 §3.3's "The year is any numeric
/// year 1900 or later", which RFC 9110 §5.6.7 incorporates along with the rest
/// of `year`'s semantics.
///
/// A bound on the WRITER alone. `year = 4DIGIT` spells `0000` and this module
/// reads it; the module doc has why the two halves differ here.
const MIN_RFC5322_YEAR: u16 = 1900;

/// 1970-01-01's own index into [`DAY_NAMES`]: the epoch was a Thursday, the
/// fourth of the seven, and the day count [`day_name`] takes is measured from
/// it.
const EPOCH_WEEKDAY: i64 = 3;

/// Seconds in a minute.
const SECONDS_PER_MINUTE: i64 = 60;

/// Seconds in an hour.
const SECONDS_PER_HOUR: i64 = 3600;

/// Seconds in a day, every day: a leap second shares the following midnight's
/// value rather than lengthening the day it falls in.
const SECONDS_PER_DAY: i64 = 86_400;

/// `day-name`, in RFC 5234 `%s` case — matched byte for byte, since
/// "HTTP-date is case sensitive."
///
/// The one table BOTH directions use: [`is_day_name`] matches against it and
/// [`day_name`] writes out of it, so a name cannot be read one way and written
/// another. Its three-byte entries are what let the writer take one without an
/// index or a length check.
const DAY_NAMES: [[u8; 3]; 7] = [
  *b"Mon", *b"Tue", *b"Wed", *b"Thu", *b"Fri", *b"Sat", *b"Sun",
];

/// `day-name-l`: the same seven days spelled out, in the same order. No one of
/// them is a prefix of another, so the longest match is the only match.
const DAY_NAMES_LONG: [&[u8]; 7] = [
  b"Monday",
  b"Tuesday",
  b"Wednesday",
  b"Thursday",
  b"Friday",
  b"Saturday",
  b"Sunday",
];

/// `month`, in the order the grammar lists them, so an index here is the month
/// number less one.
///
/// Read by [`month_number`] and written by [`month_name`], for the reason
/// [`DAY_NAMES`] carries.
const MONTH_NAMES: [[u8; 3]; 12] = [
  *b"Jan", *b"Feb", *b"Mar", *b"Apr", *b"May", *b"Jun", *b"Jul", *b"Aug", *b"Sep", *b"Oct",
  *b"Nov", *b"Dec",
];

/// Whether `name` is one of the seven `day-name`s. A slice that was not there
/// is not one.
fn is_day_name(name: Option<&[u8]>) -> bool {
  match name {
    Some(name) => DAY_NAMES.iter().any(|day| day.as_slice() == name),
    None => false,
  }
}

/// The `day-name` of the civil date `days` days after 1970-01-01, out of the
/// same table [`is_day_name`] matches against.
///
/// DERIVED rather than carried across from what was read, because RFC 5322
/// §3.3 — which RFC 9110 §5.6.7 hands `day-name`'s semantics to — requires that
/// "the day-of-week (if included) MUST be the day implied by the date". The
/// module doc has the incorporation clause and the rest of that sentence.
///
/// Fed the CIVIL day count — [`days_from_civil`], and deliberately not
/// [`unix_seconds`](HttpDate::unix_seconds) divided by a day. A leap second
/// shares the following midnight's epoch value, so through the epoch a Sunday's
/// `23:59:60` would be written `Mon` and contradict the date written beside it.
///
/// `rem_euclid` rather than `%`, for the same reason [`days_from_civil`] uses
/// `div_euclid`: a date before the epoch has a NEGATIVE day count, and the
/// remainder wanted is the non-negative one — day -1 is the day before day 0,
/// not the day six after it.
///
/// The table is destructured rather than indexed, so the compiler checks that
/// there are seven of them and no offset can be got wrong here. `rem_euclid(7)`
/// answers 0 through 6 and nothing else, so the last arm is Sunday's own rather
/// than a default standing in for a value that cannot occur.
fn day_name(days: i64) -> [u8; 3] {
  let [mon, tue, wed, thu, fri, sat, sun] = DAY_NAMES;
  match days.saturating_add(EPOCH_WEEKDAY).rem_euclid(7) {
    0 => mon,
    1 => tue,
    2 => wed,
    3 => thu,
    4 => fri,
    5 => sat,
    _ => sun,
  }
}

/// The month number, 1 through 12, of one of the twelve `month` names.
fn month_number(name: Option<&[u8]>) -> Result<u8, DateError> {
  let Some(at) = name.and_then(|name| {
    MONTH_NAMES
      .iter()
      .position(|month| month.as_slice() == name)
  }) else {
    return Err(DateError::Month);
  };
  // `at` is under twelve, so the conversion holds. Written as a fallible
  // conversion rather than a cast so the arithmetic stays total without an arm
  // claiming to be unreachable.
  let number = u8::try_from(at).map_err(|_| DateError::Month)?;
  Ok(number.saturating_add(1))
}

/// The `month` name of a month number, out of the same table [`month_number`]
/// answers from — destructured for the reason [`day_name`] destructures its
/// own.
///
/// December answers the last arm, and the twelve numbers exhaust it. A month
/// outside them cannot reach here: [`assemble`](HttpDate::assemble) is the only
/// thing that builds an [`HttpDate`], and [`days_in_month`] answers zero for
/// such a month, which refuses every day of it.
fn month_name(month: u8) -> [u8; 3] {
  let [jan, feb, mar, apr, may, jun, jul, aug, sep, oct, nov, dec] = MONTH_NAMES;
  match month {
    1 => jan,
    2 => feb,
    3 => mar,
    4 => apr,
    5 => may,
    6 => jun,
    7 => jul,
    8 => aug,
    9 => sep,
    10 => oct,
    11 => nov,
    _ => dec,
  }
}

/// `time-of-day = hour ":" minute ":" second`, the eight bytes from `at`.
fn time_of_day(v: &[u8], at: usize) -> Result<(u8, u8, u8), DateError> {
  let hour = two_digits(v, at, DateError::TimeOfDay)?;
  separator(v, at.saturating_add(2), b':')?;
  let minute = two_digits(v, at.saturating_add(3), DateError::TimeOfDay)?;
  separator(v, at.saturating_add(5), b':')?;
  let second = two_digits(v, at.saturating_add(6), DateError::TimeOfDay)?;
  Ok((hour, minute, second))
}

/// The seconds a `time-of-day` is past its own midnight.
///
/// ONE definition, shared by [`unix_seconds`](HttpDate::unix_seconds) and by
/// [`fifty_year_window`]. The window compares a candidate timestamp against an
/// anniversary, and a second spelling of "how far into the day" is a way for
/// those two to disagree about the same instant — which is precisely what the
/// rule turns on at its boundary.
///
/// A leap second's `23:59:60` answers 86400, one past the last second of a
/// day, and that is deliberate: it is the value that keeps the leap second
/// ordered AFTER `23:59:59` and level with the midnight that follows it, which
/// is where POSIX time puts it.
const fn seconds_since_midnight(hour: u8, minute: u8, second: u8) -> i64 {
  (hour as i64)
    .saturating_mul(SECONDS_PER_HOUR)
    .saturating_add((minute as i64).saturating_mul(SECONDS_PER_MINUTE))
    .saturating_add(second as i64)
}

/// `SP GMT`, the tail two of the three formats end with, read as one — so an
/// input that loses the space is a zone that is not `GMT`.
fn gmt(v: &[u8], at: usize) -> Result<(), DateError> {
  if v.get(at..) == Some(b" GMT".as_slice()) {
    Ok(())
  } else {
    Err(DateError::NotGmt)
  }
}

/// One byte the layout fixes at `at`.
fn separator(v: &[u8], at: usize, byte: u8) -> Result<(), DateError> {
  if v.get(at) == Some(&byte) {
    Ok(())
  } else {
    Err(DateError::Separator)
  }
}

/// One `DIGIT` at `at`, as its value. `fault` is the rule the caller is reading
/// for, so a refusal names that rule rather than this helper.
fn digit(v: &[u8], at: usize, fault: DateError) -> Result<u8, DateError> {
  match v.get(at) {
    Some(&b) if b.is_ascii_digit() => Ok(b.wrapping_sub(b'0')),
    _ => Err(fault),
  }
}

/// `2DIGIT` at `at`, as its value: at most 99, which a `u8` holds.
fn two_digits(v: &[u8], at: usize, fault: DateError) -> Result<u8, DateError> {
  let tens = digit(v, at, fault)?;
  let ones = digit(v, at.saturating_add(1), fault)?;
  Ok(tens.saturating_mul(10).saturating_add(ones))
}

/// `year = 4DIGIT` at `at`, as its value: at most 9999, which a `u16` holds.
fn four_digits(v: &[u8], at: usize) -> Result<u16, DateError> {
  let mut year: u16 = 0;
  for offset in 0..4 {
    let d = digit(v, at.saturating_add(offset), DateError::Year)?;
    year = year.saturating_mul(10).saturating_add(u16::from(d));
  }
  Ok(year)
}

/// One `DIGIT`, as the ASCII byte that spells it — [`digit`] in the other
/// direction.
///
/// The remainder is taken HERE rather than at each call site, so no caller can
/// hand this a value that spells a byte outside `0` through `9`. The last arm
/// is nine's own: `rem_euclid(10)` answers nothing above it.
fn ascii_digit(d: u16) -> u8 {
  match d.rem_euclid(10) {
    0 => b'0',
    1 => b'1',
    2 => b'2',
    3 => b'3',
    4 => b'4',
    5 => b'5',
    6 => b'6',
    7 => b'7',
    8 => b'8',
    _ => b'9',
  }
}

/// `2DIGIT`, zero-padded — [`two_digits`] in the other direction. `day`,
/// `hour`, `minute` and `second` each occupy two fixed columns of an
/// `IMF-fixdate`, so 6 is written `06`.
fn two_ascii_digits(v: u8) -> [u8; 2] {
  let v = u16::from(v);
  [ascii_digit(v.div_euclid(10)), ascii_digit(v)]
}

/// `year = 4DIGIT`, zero-padded — [`four_digits`] in the other direction, and
/// what `date1`'s fixed width requires of a year with fewer than four digits.
///
/// Only a year [`format_imf_fixdate`] has already checked against
/// [`MAX_FOUR_DIGIT_YEAR`] reaches here, so the leading digit is the thousands
/// rather than a truncation of them. It has also been checked against
/// [`MIN_RFC5322_YEAR`], which means the padding is currently unreachable from
/// that caller: every year 1900 through 9999 has four significant digits. It
/// stays because the padding belongs to the FORMAT rather than to the range —
/// `date1` has four columns whatever fills them — and because removing it
/// would make this function's answer depend on a bound enforced two calls
/// away.
fn four_ascii_digits(v: u16) -> [u8; 4] {
  [
    ascii_digit(v.div_euclid(1000)),
    ascii_digit(v.div_euclid(100)),
    ascii_digit(v.div_euclid(10)),
    ascii_digit(v),
  ]
}

/// The four-digit year an `rfc850-date`'s `2DIGIT` denotes, by §5.6.7's rule:
/// the most recent year ending in those two digits whose TIMESTAMP is not more
/// than fifty years past `now_unix_seconds`.
///
/// The month, day and time of day are the candidate's own, and they are
/// arguments because the rule needs them. §5.6.7 asks about "a timestamp that
/// appears to be more than 50 years in the future", not about a year, and the
/// two questions have different answers for a whole year at a time: a
/// recipient at 2026-01-01 reads `31-Dec-76 00:00:00` as 1976, one at
/// 2026-12-31 reads it as 2076, and a rule handed only the year 2026 cannot
/// tell those recipients apart.
///
/// Every year it answers ends in `two_digits`, and that is the whole of what it
/// promises: where the rule names a year this module cannot represent, it
/// REFUSES rather than answering a different one.
///
/// # The comparison
///
/// The horizon is the EXACT fifty-year anniversary of `now_unix_seconds` — the
/// same month, day and time of day, fifty calendar years later. The candidate
/// is the one year ending in `two_digits` that lies in the anniversary's own
/// century. If the candidate's timestamp is past the anniversary the rule steps
/// it back a century, and one step is always enough: the candidate is within 99
/// years above the anniversary's year, so a century below it is a year strictly
/// earlier than the anniversary's and therefore wholly behind it, while a
/// century above it is wholly ahead. So there is exactly one answer and this
/// finds it.
///
/// Both sides are compared as `(day count, seconds within that day)` PAIRS
/// rather than as seconds since the epoch. Lexicographic order on the pair is
/// the order on the instant, and it means no seconds-since-the-epoch product is
/// ever formed: for a `now_unix_seconds` near either end of [`i64`] such a
/// product would saturate, and the rule would be applied to a stand-in instead
/// of to the instant the caller named. That is the shape of a defect this
/// function has already had once, one type narrower.
///
/// **The anniversary of 29 February.** Fifty is not a multiple of four, so the
/// anniversary of a leap day never lands on one: 2024-02-29 plus fifty years is
/// 2074-02-29, a date 2074 does not have. [`days_from_civil`] reads it as the
/// day after 2074-02-28, which is 2074-03-01, and that is the answer this takes
/// — the anniversary falls on the first day the target year actually has after
/// the anniversary month's end. §5.6.7 does not settle this corner; what
/// matters is that the choice is one rule rather than an accident, and it is
/// the same rule [`HttpDate::assemble`] would refuse `29 Feb 2074` under.
///
/// # Why both ends refuse rather than saturate
///
/// The rule's own answer is not always a `u16`. Measured from an instant early
/// enough it names a year BEFORE year 0 — there is no century below it to step
/// back into, and a negative year is not merely unrepresentable here, it is one
/// `year = 4DIGIT` cannot spell at all. Measured from one late enough it names a
/// year above [`u16::MAX`], perfectly real and simply outside what this type
/// holds.
///
/// A clamp at either end is not a narrower answer, it is a wrong one, and it is
/// INVISIBLE: the caller gets `Ok`, an [`HttpDate`] whose
/// [`unix_seconds`](HttpDate::unix_seconds) describes the clamped instant, and
/// nothing that distinguishes it from a year the sender actually wrote — a year
/// that does not even end in the digits the sender wrote. Only a refusal
/// reaches a caller as a refusal.
///
/// Refusing costs nothing a recipient can reach: both bands sit within a couple
/// of centuries of year 0 and of year 65535, and no clock produces an instant
/// in either.
///
/// # Errors
///
/// [`DateError::FiftyYearWindow`], and nothing else. `two_digits` is already
/// two digits — [`two_digits`] answers nothing else — so there is no malformed
/// literal left for this to find.
fn fifty_year_window(
  two_digits: u8,
  month: u8,
  day: u8,
  seconds_of_day: i64,
  now_unix_seconds: i64,
) -> Result<u16, DateError> {
  // `now` as the day it falls on and the second within that day. `div_euclid`
  // and `rem_euclid` rather than `/` and `%` for the reason `days_from_civil`
  // uses them: an instant before the epoch is negative, and the day it falls on
  // is the one below it.
  let now_days = now_unix_seconds.div_euclid(SECONDS_PER_DAY);
  let now_seconds_of_day = now_unix_seconds.rem_euclid(SECONDS_PER_DAY);
  let (now_year, now_month, now_day) = civil_from_days(now_days);

  let horizon_year = now_year.saturating_add(FIFTY_YEARS);
  let horizon_days = days_from_civil(horizon_year, now_month, now_day);

  // The one year ending in `two_digits` inside the anniversary's century.
  // `rem_euclid` again: for an anniversary before year 0 the century wanted is
  // the one BELOW it, which truncating remainder would step past.
  let century = horizon_year.saturating_sub(horizon_year.rem_euclid(100));
  let candidate = century.saturating_add(i64::from(two_digits));
  let candidate_days = days_from_civil(candidate, i64::from(month), i64::from(day));

  let year = if (candidate_days, seconds_of_day) > (horizon_days, now_seconds_of_day) {
    candidate.saturating_sub(100)
  } else {
    candidate
  };
  u16::try_from(year).map_err(|_| DateError::FiftyYearWindow)
}

/// The length of `month` in `year`.
///
/// Zero for a month outside 1 through 12, which nothing here produces:
/// [`assemble`](HttpDate::assemble) then refuses every day, the safe direction
/// for a value that is not supposed to exist and the one an `unreachable!()`
/// the lint wall forbids would have had to pick anyway.
const fn days_in_month(year: u16, month: u8) -> u8 {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
    4 | 6 | 9 | 11 => 30,
    2 if is_leap_year(year) => 29,
    2 => 28,
    _ => 0,
  }
}

/// The proleptic Gregorian leap year rule, that being the calendar an RFC 9110
/// §5.6.7 date is read in.
const fn is_leap_year(year: u16) -> bool {
  year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// Days from 1970-01-01 to the civil date `(year, month, day)`, by Howard
/// Hinnant's `days_from_civil` — the standard proleptic Gregorian conversion,
/// exact for every year this grammar admits.
///
/// It counts in eras of 400 years that begin on 1 March, which is why the year
/// is shifted back for January and February and the month re-indexed from
/// March: the leap day then lands at the end of an era's year rather than
/// inside it. `div_euclid` rather than `/` for the four divisions: the crate's
/// lint wall denies the operator, and floor division is what the algorithm
/// wants for the era of a year before 0, which truncating division would have
/// to correct for afterwards.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
  let shifted_year = if month <= 2 {
    year.saturating_sub(1)
  } else {
    year
  };
  let era = shifted_year.div_euclid(400);
  let year_of_era = shifted_year.saturating_sub(era.saturating_mul(400));
  let month_of_era = if month > 2 {
    month.saturating_sub(3)
  } else {
    month.saturating_add(9)
  };
  let day_of_year = month_of_era
    .saturating_mul(153)
    .saturating_add(2)
    .div_euclid(5)
    .saturating_add(day)
    .saturating_sub(1);
  let day_of_era = year_of_era
    .saturating_mul(365)
    .saturating_add(year_of_era.div_euclid(4))
    .saturating_sub(year_of_era.div_euclid(100))
    .saturating_add(day_of_year);
  era
    .saturating_mul(146_097)
    .saturating_add(day_of_era)
    .saturating_sub(719_468)
}

/// The civil date `(year, month, day)` of the day `days` days after
/// 1970-01-01: Howard Hinnant's `civil_from_days`, and the exact inverse of
/// [`days_from_civil`] over every day either can name.
///
/// Reached from one place, [`fifty_year_window`], and for one reason: §5.6.7's
/// anniversary is fifty CALENDAR years after the caller's instant, so the month
/// and day that instant falls on have to be recovered before fifty can be added
/// to its year. Seconds since the epoch does not carry them.
///
/// The same eras of 400 years that begin on 1 March, run backwards: the shifted
/// origin is why `day_of_era` reaches 146096 rather than a multiple of 365, why
/// the month comes out indexed from March, and why January and February are
/// pulled back into the year that precedes them at the last line.
///
/// `div_euclid` for every division, and `saturating_*` for every sum and
/// product, on the same two grounds as [`days_from_civil`]: the crate's lint
/// wall denies the bare operators, and floor division is what the era of a day
/// before the shifted origin needs. Saturation is a formality here — the
/// largest quantity is a day count, at most about 1.1e14 for an [`i64`] of
/// seconds, six orders short of what could overflow.
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
  let shifted = days.saturating_add(719_468);
  let era = shifted.div_euclid(146_097);
  let day_of_era = shifted.saturating_sub(era.saturating_mul(146_097));
  let year_of_era = day_of_era
    .saturating_sub(day_of_era.div_euclid(1460))
    .saturating_add(day_of_era.div_euclid(36_524))
    .saturating_sub(day_of_era.div_euclid(146_096))
    .div_euclid(365);
  let year = year_of_era.saturating_add(era.saturating_mul(400));
  let day_of_year = day_of_era.saturating_sub(
    year_of_era
      .saturating_mul(365)
      .saturating_add(year_of_era.div_euclid(4))
      .saturating_sub(year_of_era.div_euclid(100)),
  );
  let month_of_era = day_of_year
    .saturating_mul(5)
    .saturating_add(2)
    .div_euclid(153);
  let day = day_of_year
    .saturating_sub(
      month_of_era
        .saturating_mul(153)
        .saturating_add(2)
        .div_euclid(5),
    )
    .saturating_add(1);
  // March is `month_of_era` 0, so the first ten run to December and the last
  // two are the January and February that belong to the NEXT civil year.
  let month = if month_of_era < 10 {
    month_of_era.saturating_add(3)
  } else {
    month_of_era.saturating_sub(9)
  };
  let year = if month <= 2 {
    year.saturating_add(1)
  } else {
    year
  };
  (year, month, day)
}

#[cfg(test)]
mod tests;
