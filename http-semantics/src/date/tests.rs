use super::*;

// RFC 9110 §5.6.7's own worked example: the three formats below all denote the
// same instant, and the section presents them together for exactly that reason.
// Pinning all three against one expected value is what makes this a test of the
// EQUIVALENCE the section states, rather than three unrelated parses.
// Verified against `.rfc-cache/rfc9110.txt` (the section presents these three
// strings itself, labelled `IMF-fixdate`, `obsolete RFC 850 format` and
// `ANSI C's asctime() format`) and against a `datetime` computation of the
// instant. Their lengths are 29, 30 and 24 bytes.
const SUNDAY_1994_11_06_08_49_37: i64 = 784_111_777;

#[test]
fn the_three_formats_denote_one_instant() {
  for input in [
    b"Sun, 06 Nov 1994 08:49:37 GMT".as_slice(),
    b"Sunday, 06-Nov-94 08:49:37 GMT".as_slice(),
    b"Sun Nov  6 08:49:37 1994".as_slice(),
  ] {
    assert_eq!(
      parse_http_date(input).map(|d| d.unix_seconds()),
      Ok(SUNDAY_1994_11_06_08_49_37),
      "{:?}",
      core::str::from_utf8(input),
    );
  }
}

// §5.6.7 requires a sender to generate only IMF-fixdate, and this parser to
// accept all three — so a rejection has to name WHICH rule refused, not merely
// that something did. A test asserting `is_err()` would pass on the wrong
// reason.
#[test]
fn a_malformed_date_names_the_rule_that_refused_it() {
  assert_eq!(
    parse_http_date(b"Sun, 06 Nov 1994 08:49:37 UTC"),
    Err(DateError::NotGmt)
  );
  assert_eq!(
    parse_http_date(b"Xxx, 06 Nov 1994 08:49:37 GMT"),
    Err(DateError::DayName)
  );
  assert_eq!(
    parse_http_date(b"Sun, 06 Nov 1994 08:49:99 GMT"),
    Err(DateError::TimeOfDay)
  );
  assert_eq!(parse_http_date(b"Sun, 06 Nov 1994"), Err(DateError::Length));
}

// The two-digit year is the obs-date form's own hazard: §5.6.7 says a recipient
// that parses one MUST interpret a timestamp that appears to be more than 50
// years in the future as the most recent year in the past with the same last
// two digits. Pinned here because it is a rule with an answer, not a
// convention.
#[test]
fn a_two_digit_year_follows_the_fifty_year_rule() {
  let parsed = parse_http_date(b"Sunday, 06-Nov-94 08:49:37 GMT").unwrap();
  assert_eq!(parsed.year(), 1994);
}

// Every byte offset in a fixed-layout parse is an opportunity to read the wrong
// column, and a length check that passes does not prove the columns are right.
#[test]
fn every_truncation_of_a_valid_date_is_refused_not_misread() {
  const VALID: &[u8] = b"Sun, 06 Nov 1994 08:49:37 GMT";
  for cut in 0..VALID.len() {
    assert!(
      parse_http_date(&VALID[..cut]).is_err(),
      "prefix of length {cut} was accepted"
    );
  }
}

// Everything below pins a decision §5.6.7 leaves to the parser, at the place it
// is decided. The four tests above are the section's own worked example and its
// stated rules; these are the answers this module had to choose.

// `DateError::Separator` is not `TimeOfDay` and not `Length`: the input below
// is 29 bytes with every field in range, and what is wrong is a byte the layout
// fixes. A parser that folded the two together would answer `TimeOfDay` for a
// time of day that is perfectly in range.
#[test]
fn a_separator_the_layout_fixes_is_its_own_refusal() {
  assert_eq!(
    parse_http_date(b"Sun, 06 Nov 1994 08.49:37 GMT"),
    Err(DateError::Separator)
  );
  assert_eq!(
    parse_http_date(b"Sun, 06-Nov 1994 08:49:37 GMT"),
    Err(DateError::Separator)
  );
  assert_eq!(
    parse_http_date(b"Sunday, 06 Nov-94 08:49:37 GMT"),
    Err(DateError::Separator)
  );
  assert_eq!(
    parse_http_date(b"Sun Nov  6-08:49:37 1994"),
    Err(DateError::Separator)
  );
  // The SP before the zone belongs to the zone, which is read as one `SP GMT`
  // tail — so losing it is a zone that is not GMT rather than a fourth kind of
  // refusal.
  assert_eq!(
    parse_http_date(b"Sun, 06 Nov 1994 08:49:37GMT."),
    Err(DateError::NotGmt)
  );
}

// `year = 4DIGIT` and `date2`'s `2DIGIT` are the year's own rule, so a year
// that is not digits names the year and not the field beside it.
#[test]
fn a_year_that_is_not_digits_names_the_year() {
  assert_eq!(
    parse_http_date(b"Sun, 06 Nov 19x4 08:49:37 GMT"),
    Err(DateError::Year)
  );
  assert_eq!(
    parse_http_date(b"Sunday, 06-Nov-9x 08:49:37 GMT"),
    Err(DateError::Year)
  );
  assert_eq!(
    parse_http_date(b"Sun Nov  6 08:49:37 19x4"),
    Err(DateError::Year)
  );
  assert_eq!(
    parse_http_date(b"Sun, 06 Xxx 1994 08:49:37 GMT"),
    Err(DateError::Month)
  );
}

// RFC 9110 §5.6.7: "HTTP-date is case sensitive." The `%s` prefix on every
// terminal in the section's grammar says the same thing in RFC 5234's notation,
// so each of these differs from a valid date by case alone and none of them is
// a date.
#[test]
fn the_grammar_is_case_sensitive() {
  assert_eq!(
    parse_http_date(b"SUN, 06 Nov 1994 08:49:37 GMT"),
    Err(DateError::DayName)
  );
  assert_eq!(
    parse_http_date(b"Sun, 06 NOV 1994 08:49:37 GMT"),
    Err(DateError::Month)
  );
  assert_eq!(
    parse_http_date(b"Sun, 06 Nov 1994 08:49:37 gmt"),
    Err(DateError::NotGmt)
  );
  assert_eq!(
    parse_http_date(b"SUNDAY, 06-Nov-94 08:49:37 GMT"),
    Err(DateError::DayName)
  );
}

// `day = 2DIGIT` admits `31 Nov`, and the calendar does not. Accepting it would
// answer with 1 December — a real instant for a date that never happened, which
// is the one outcome worse than a refusal.
#[test]
fn a_day_past_the_end_of_its_own_month_is_refused() {
  assert_eq!(
    parse_http_date(b"Wed, 31 Nov 1994 08:49:37 GMT"),
    Err(DateError::TimeOfDay)
  );
  assert_eq!(
    parse_http_date(b"Tue, 00 Nov 1994 08:49:37 GMT"),
    Err(DateError::TimeOfDay)
  );
  // February, and the century rule underneath it: 2000 is a leap year because
  // 400 divides it, 1900 is not because 100 does and 400 does not.
  assert_eq!(
    parse_http_date(b"Tue, 29 Feb 2000 12:00:00 GMT").map(|d| d.unix_seconds()),
    Ok(951_825_600)
  );
  assert!(parse_http_date(b"Thu, 29 Feb 1996 12:00:00 GMT").is_ok());
  assert_eq!(
    parse_http_date(b"Thu, 29 Feb 1900 12:00:00 GMT"),
    Err(DateError::TimeOfDay)
  );
}

// `time-of-day`'s own comment is `00:00:00 - 23:59:60 (leap second)`, so `:60`
// is in the grammar; POSIX time has no value of its own for a leap second, so
// it shares the following midnight's. The civil year is still the one the
// sender wrote.
#[test]
fn a_leap_second_is_admitted_and_lands_on_the_following_midnight() {
  let leap = parse_http_date(b"Sun, 31 Dec 1995 23:59:60 GMT").unwrap();
  assert_eq!(leap.unix_seconds(), 820_454_400);
  assert_eq!(leap.year(), 1995);
  for out_of_range in [
    b"Sun, 31 Dec 1995 23:59:61 GMT".as_slice(),
    b"Sun, 31 Dec 1995 23:60:00 GMT",
    b"Sun, 31 Dec 1995 24:00:00 GMT",
  ] {
    assert_eq!(
      parse_http_date(out_of_range),
      Err(DateError::TimeOfDay),
      "{:?}",
      core::str::from_utf8(out_of_range),
    );
  }
}

// `date3 = month SP ( 2DIGIT / ( SP 1DIGIT ))` spells a single-digit day two
// ways, and both are the grammar's. Each puts the digit in a different column,
// which is the whole reason this alternative exists in a fixed-width format.
#[test]
fn asctime_reads_both_spellings_of_a_single_digit_day() {
  assert_eq!(
    parse_http_date(b"Sun Nov  6 08:49:37 1994").map(|d| d.unix_seconds()),
    Ok(SUNDAY_1994_11_06_08_49_37)
  );
  assert_eq!(
    parse_http_date(b"Sun Nov 06 08:49:37 1994").map(|d| d.unix_seconds()),
    Ok(SUNDAY_1994_11_06_08_49_37)
  );
  assert_eq!(
    parse_http_date(b"Sun Nov x6 08:49:37 1994"),
    Err(DateError::TimeOfDay)
  );
  assert_eq!(
    parse_http_date(b"Sun Nov  x 08:49:37 1994"),
    Err(DateError::TimeOfDay)
  );
}

// ── §5.6.7's fifty-year rule, and an oracle written from its sentence ────────
//
// RFC 9110 §5.6.7: "Recipients of a timestamp value in rfc850-date format,
// which uses a two-digit year, MUST interpret a timestamp that appears to be
// more than 50 years in the future as representing the most recent year in the
// past that had the same last two digits."
//
// Everything below measures this module against THAT sentence rather than
// against the shape of the code implementing it, and the distinction is the
// reason this section was rewritten. The version of it that shipped with the
// first implementation computed its expected value as `horizon =
// reference_year + 50`, `want = horizon - horizon % 100 + two_digits` — the
// implementation's own model, spelled a second time. It ran over all 6_553_600
// argument pairs and every one agreed, because a wrong model checked against
// itself agrees everywhere. What neither could express is that §5.6.7 asks
// about a TIMESTAMP and that model asks about a YEAR: a recipient at
// 2026-01-01 must read `31-Dec-76 00:00:00` as 1976, one at 2026-12-31 must
// read it as 2076, and a rule handed only the year 2026 answers both the same.
//
// So the oracle here is built the other way round, on two rules:
//
// * its calendar is DIFFERENT arithmetic, not `days_from_civil` under another
//   name — a day-of-year table plus a leap-year count, where the module runs
//   Howard Hinnant's 400-year eras shifted to begin in March. The two are
//   pinned against each other by `the_two_calendars_agree_and_invert_each_other`,
//   so a fault in either is a failure here rather than a shared assumption.
// * it applies the sentence by SEARCH: it enumerates the years ending in the
//   given two digits and keeps the most recent whose timestamp is not past the
//   fifty-year anniversary. The module computes one candidate from a century
//   and conditionally steps it back a hundred. Neither derivation is the
//   other's, so agreeing is evidence.

/// Days from 0000-01-01 to 1970-01-01: 1970 years of 365 days, plus the 478
/// leap days of 0000 through 1969.
///
/// The one constant this oracle shares with anything, and
/// `a_date_before_the_epoch_counts_backwards` derives it independently below.
const ORACLE_EPOCH_FROM_YEAR_ZERO: i64 = 719_528;

/// Days elapsed in a COMMON year before the first of each month.
const ORACLE_DAYS_BEFORE_MONTH: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

/// The proleptic Gregorian leap rule, stated again so the oracle depends on
/// nothing under test.
fn oracle_is_leap_year(year: i64) -> bool {
  year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// The leap years in `0..year`, counting the other way for a year before 0.
///
/// `year - 1` and the floor divisions are what make it hold in both
/// directions: the multiples of 4, of 100 and of 400 at or below `year - 1`,
/// plus year 0 itself, which every one of the three divisions misses.
fn oracle_leap_days_before(year: i64) -> i64 {
  let last = year - 1;
  last.div_euclid(4) - last.div_euclid(100) + last.div_euclid(400) + 1
}

/// Days from 1970-01-01 to `year-month-day`, by a day-of-year table — the same
/// answer `days_from_civil` gives by a different route.
///
/// 29 February of a year that has no such day lands on 1 March, because the
/// table's February is 28 days and the extra day runs over into it. That is
/// the same convention `days_from_civil` reaches from its March-based eras,
/// and it is the convention the fifty-year anniversary of a leap day needs.
fn oracle_days(year: i64, month: i64, day: i64) -> i64 {
  let index = usize::try_from(month - 1).expect("a month of the twelve");
  let leap_day = i64::from(oracle_is_leap_year(year) && month > 2);
  365 * year + oracle_leap_days_before(year) + ORACLE_DAYS_BEFORE_MONTH[index] + leap_day + day
    - 1
    - ORACLE_EPOCH_FROM_YEAR_ZERO
}

/// One instant as a civil calendar spells it, so a test names the clock it
/// measures from in the units a reader can check rather than as a bare number.
#[derive(Copy, Clone, Debug)]
struct Civil {
  year: i64,
  month: i64,
  day: i64,
  hour: i64,
  minute: i64,
  second: i64,
}

impl Civil {
  const fn new(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> Self {
    Self {
      year,
      month,
      day,
      hour,
      minute,
      second,
    }
  }

  /// Seconds past this instant's own midnight.
  fn seconds_of_day(self) -> i64 {
    self.hour * 3600 + self.minute * 60 + self.second
  }

  /// Seconds since the POSIX epoch — what `parse_http_date_from` takes.
  fn unix(self) -> i64 {
    oracle_days(self.year, self.month, self.day) * 86_400 + self.seconds_of_day()
  }
}

/// §5.6.7's sentence, applied by search: the most recent year ending in
/// `two_digits` whose timestamp is not more than fifty years past `now`.
///
/// The anniversary is `now`'s own month, day and time of day, fifty calendar
/// years on — which is what "more than 50 years in the future" is measured
/// against. Candidates are ENUMERATED rather than computed from a century, so
/// this shares no step with the code it grades.
///
/// Answers over the integers, including years no `u16` holds: that is what
/// lets a caller check a refusal was owed as well as that an answer was right.
fn oracle_fifty_year_rule(
  two_digits: i64,
  month: i64,
  day: i64,
  seconds_of_day: i64,
  now: Civil,
) -> i64 {
  let anniversary = (
    oracle_days(now.year + 50, now.month, now.day),
    now.seconds_of_day(),
  );
  // Two centuries either side of the anniversary's own year: the answer is
  // within one of it, since a year above it is wholly ahead of the anniversary
  // and a year a century below is wholly behind.
  let base = now.year + 50;
  let mut year = base - 200 + (two_digits - (base - 200)).rem_euclid(100);
  let mut answer = None;
  while year <= base + 200 {
    if (oracle_days(year, month, day), seconds_of_day) <= anniversary {
      // Ascending, so the last to qualify is the most recent.
      answer = Some(year);
    }
    year += 100;
  }
  answer.expect("the search starts two centuries below the anniversary")
}

// The oracle's calendar and the module's are two derivations of one function,
// and this is what says they are the same one. Without it every assertion below
// rests on the two sharing a mistake — which is the failure this whole section
// was rewritten to stop.
//
// `civil_from_days` is pinned here too, in both directions. It is the only
// consumer of a caller's raw instant, so a fault in it would misplace the
// anniversary for every reference instant at once, and there is no other test
// in this file whose subject it is.
#[test]
#[cfg_attr(
  miri,
  ignore = "1.5 million calendar conversions; no unsafe to interpret"
)]
fn the_two_calendars_agree_and_invert_each_other() {
  for year in 0..=i64::from(u16::MAX) {
    for month in 1..=12i64 {
      let index = usize::try_from(month - 1).expect("a month of the twelve");
      let last = ORACLE_DAYS_BEFORE_MONTH
        .get(index + 1)
        .copied()
        .unwrap_or(365)
        - ORACLE_DAYS_BEFORE_MONTH[index]
        + i64::from(oracle_is_leap_year(year) && month == 2);
      for day in [1, last] {
        let days = oracle_days(year, month, day);
        assert_eq!(
          days,
          days_from_civil(year, month, day),
          "{year}-{month}-{day}"
        );
        assert_eq!(civil_from_days(days), (year, month, day), "day {days}");
      }
    }
  }
  // Both ends of what a caller's `i64` of seconds can reach, where an
  // implementation that had let an intermediate saturate would stop inverting.
  for days in [
    i64::MIN.div_euclid(86_400),
    i64::MAX.div_euclid(86_400),
    -719_528,
    -1,
    0,
    1,
    -1_000_000_000,
    1_000_000_000,
  ] {
    let (year, month, day) = civil_from_days(days);
    assert_eq!(days_from_civil(year, month, day), days, "day {days}");
    assert_eq!(oracle_days(year, month, day), days, "day {days}");
  }
}

// THE finding this section was rewritten for, as its own test. Both assertions
// are the same thirty bytes and the same two-digit year; what differs is the
// clock, by less than a year — and a rule measured in whole years answers them
// alike, which is what the implementation and its old oracle both did.
#[test]
fn the_rule_is_measured_against_the_whole_instant_and_not_the_year() {
  let candidate = b"Friday, 31-Dec-76 00:00:00 GMT".as_slice();
  let year_at = |now: Civil| parse_http_date_from(candidate, now.unix()).map(|d| d.year());
  // Anniversary 2076-01-01T00:00:00Z; 2076-12-31 is most of a year past it.
  assert_eq!(year_at(Civil::new(2026, 1, 1, 0, 0, 0)), Ok(1976));
  // Anniversary 2076-12-31T00:00:00Z; the same timestamp now sits ON it.
  assert_eq!(year_at(Civil::new(2026, 12, 31, 0, 0, 0)), Ok(2076));
  // And one second either side of that second anniversary.
  assert_eq!(year_at(Civil::new(2026, 12, 30, 23, 59, 59)), Ok(1976));
  assert_eq!(year_at(Civil::new(2026, 12, 31, 0, 0, 1)), Ok(2076));
}

// The anniversary is an instant, so every field of it separates two answers.
// One step up in each of month, day, hour, minute and second crosses it and
// one step down does not — five boundaries, none of which a year-wide horizon
// has at all.
#[test]
fn the_anniversary_is_exact_in_every_field() {
  let now = Civil::new(2026, 6, 15, 12, 30, 45);
  let year_of = |v: &[u8]| parse_http_date_from(v, now.unix()).map(|d| d.year());
  // ON the anniversary is not PAST it: "more than 50 years in the future".
  assert_eq!(year_of(b"Monday, 15-Jun-76 12:30:45 GMT"), Ok(2076));
  for past in [
    b"Monday, 15-Jun-76 12:30:46 GMT".as_slice(),
    b"Monday, 15-Jun-76 12:31:45 GMT",
    b"Monday, 15-Jun-76 13:30:45 GMT",
    b"Monday, 16-Jun-76 12:30:45 GMT",
    b"Monday, 15-Jul-76 12:30:45 GMT",
  ] {
    assert_eq!(year_of(past), Ok(1976), "{:?}", core::str::from_utf8(past));
  }
  for inside in [
    b"Monday, 15-Jun-76 12:30:44 GMT".as_slice(),
    b"Monday, 15-Jun-76 12:29:45 GMT",
    b"Monday, 15-Jun-76 11:30:45 GMT",
    b"Monday, 14-Jun-76 12:30:45 GMT",
    b"Monday, 15-May-76 12:30:45 GMT",
  ] {
    assert_eq!(
      year_of(inside),
      Ok(2076),
      "{:?}",
      core::str::from_utf8(inside)
    );
  }
}

// Fifty is not a multiple of four, so a leap day's fiftieth anniversary never
// lands on one. The module reads 29 February of a year that has no such day as
// 1 March — `days_from_civil`'s own answer for it — and that is the rule the
// anniversary of a leap-day clock falls under. Stated here because §5.6.7 does
// not settle the corner and a reader is owed the answer this module chose.
#[test]
fn the_anniversary_of_a_leap_day_falls_on_the_first_of_march() {
  assert!(is_leap_year(2024) && !is_leap_year(2074));
  assert_eq!(days_from_civil(2074, 2, 29), days_from_civil(2074, 3, 1));

  let now = Civil::new(2024, 2, 29, 6, 0, 0);
  let year_of = |v: &[u8]| parse_http_date_from(v, now.unix()).map(|d| d.year());
  assert_eq!(year_of(b"Wednesday, 28-Feb-74 06:00:00 GMT"), Ok(2074));
  assert_eq!(year_of(b"Wednesday, 01-Mar-74 06:00:00 GMT"), Ok(2074));
  assert_eq!(year_of(b"Wednesday, 01-Mar-74 06:00:01 GMT"), Ok(1974));

  // The candidate side of the same corner, and the case where the century the
  // rule picks is what decides whether 29 February exists at all: `00` read as
  // 2000 is a date, read as 1900 it is not, and the refusal is the CALENDAR's
  // rather than the window's.
  let in_2000 = Civil::new(1975, 1, 1, 0, 0, 0);
  assert_eq!(
    parse_http_date_from(b"Tuesday, 29-Feb-00 12:00:00 GMT", in_2000.unix()).map(|d| d.year()),
    Ok(2000)
  );
  let in_1900 = Civil::new(1925, 1, 1, 0, 0, 0);
  assert_eq!(
    parse_http_date_from(b"Thursday, 29-Feb-00 12:00:00 GMT", in_1900.unix()),
    Err(DateError::TimeOfDay)
  );
}

// A refusal that reaches the CALLER, through the parser and by name, at both
// ends — and each end is shown to move with the candidate's own date, which is
// what a year-wide window could not express. The two digits here are digits, so
// `DateError::Year` would be the wrong answer to give for any of them.
#[test]
fn a_window_year_the_parser_cannot_represent_is_refused_by_name() {
  // Below year 0. The anniversary is 0050-01-01T00:00:00Z, so `50` is answered
  // for the one timestamp that IS the anniversary and refused for the next
  // second — the rule stepping back a century to a year before 0.
  let year_zero = Civil::new(0, 1, 1, 0, 0, 0).unix();
  let low = |v: &[u8]| parse_http_date_from(v, year_zero).map(|d| d.year());
  assert_eq!(low(b"Sunday, 01-Jan-50 00:00:00 GMT"), Ok(50));
  assert_eq!(
    low(b"Sunday, 01-Jan-50 00:00:01 GMT"),
    Err(DateError::FiftyYearWindow)
  );
  assert_eq!(low(b"Sunday, 06-Nov-49 08:49:37 GMT"), Ok(49));
  assert_eq!(
    low(b"Sunday, 06-Nov-94 08:49:37 GMT"),
    Err(DateError::FiftyYearWindow)
  );

  // Above u16::MAX. The anniversary is 65536-06-01T00:00:00Z, a year `u16`
  // cannot hold: `36` before that date is answered by the rule and refused by
  // the type, `36` after it steps back to 65436, and `35` is the last year this
  // parser can represent.
  let far = Civil::new(65_486, 6, 1, 0, 0, 0).unix();
  let high = |v: &[u8]| parse_http_date_from(v, far).map(|d| d.year());
  assert_eq!(
    high(b"Sunday, 01-Jan-36 00:00:00 GMT"),
    Err(DateError::FiftyYearWindow)
  );
  assert_eq!(high(b"Sunday, 01-Dec-36 00:00:00 GMT"), Ok(65_436));
  assert_eq!(high(b"Sunday, 01-Jan-35 00:00:00 GMT"), Ok(65_535));

  // The malformed literal is still the OTHER rule, and still names it.
  assert_eq!(
    parse_http_date_from(b"Sunday, 06-Nov-9x 08:49:37 GMT", year_zero),
    Err(DateError::Year)
  );
}

// The whole reference-year domain, against the oracle above. Exhaustive over
// the dimension the old test was exhaustive over, so nothing it covered is
// lost, but graded by the sentence rather than by the model: an `Ok` has to
// equal the searched answer and end in the digits it was given, and an `Err`
// has to be a case whose searched answer no `u16` holds. It fails both on a
// wrong answer and on a refusal that was not owed.
//
// The reference instant is deliberately mid-year and mid-day, and the
// candidate's date deliberately later in the year than it — so a rule that
// still compared years would answer a century high for one two-digit value at
// every single reference year, rather than for none.
#[test]
#[cfg_attr(
  miri,
  ignore = "6_553_600 applications of the rule; no unsafe to interpret"
)]
fn the_rule_answers_its_own_sentence_from_every_reference_year() {
  const CANDIDATE_MONTH: i64 = 11;
  const CANDIDATE_DAY: i64 = 6;
  let candidate_seconds = 8 * 3600 + 49 * 60 + 37;
  let mut answered = 0u32;
  let mut refused_low = 0u32;
  let mut refused_high = 0u32;

  for reference_year in 0..=i64::from(u16::MAX) {
    let now = Civil::new(reference_year, 5, 17, 13, 45, 6);
    let now_unix = now.unix();
    for two_digits in 0..100u8 {
      let want = oracle_fifty_year_rule(
        i64::from(two_digits),
        CANDIDATE_MONTH,
        CANDIDATE_DAY,
        candidate_seconds,
        now,
      );
      let representable = (0..=i64::from(u16::MAX)).contains(&want);
      match fifty_year_window(two_digits, 11, 6, candidate_seconds, now_unix) {
        Ok(year) => {
          assert!(
            representable,
            "({two_digits}, {reference_year}) -> {year}, but the sentence names \
             {want}, which no u16 holds"
          );
          assert_eq!(i64::from(year), want, "({two_digits}, {reference_year})");
          assert_eq!(
            year.rem_euclid(100),
            u16::from(two_digits),
            "({two_digits}, {reference_year}) -> {year}, which does not end in \
             the digits given"
          );
          answered += 1;
        }
        Err(err) => {
          assert_eq!(err, DateError::FiftyYearWindow);
          assert!(
            !representable,
            "({two_digits}, {reference_year}) was refused, but the sentence \
             names {want}, which a u16 holds"
          );
          if want < 0 {
            refused_low += 1;
          } else {
            refused_high += 1;
          }
        }
      }
    }
  }

  // The denominator, so a green run is distinguishable from one where the loop
  // never reached either refusing end. Both bands are the oracle's own count.
  assert_eq!((refused_low, refused_high), (1275, 1225));
  assert_eq!(answered + refused_low + refused_high, 6_553_600);
}

// And the dimension the old test could not reach at all: the candidate's own
// month, day and time of day, which are three of the five things deciding
// which side of the anniversary a timestamp falls on. Every month, every day
// column the grammar admits — `31 Nov` included, since the window is asked
// before the calendar refuses it — and five times of day around the
// anniversary's own, including the leap second `time-of-day` admits.
#[test]
fn the_rule_answers_its_own_sentence_for_every_candidate_date() {
  let now = Civil::new(2026, 6, 15, 12, 30, 45);
  let now_unix = now.unix();
  let anniversary_seconds = now.seconds_of_day();
  let mut checked = 0u32;
  for month in 1..=12i64 {
    for day in 1..=31i64 {
      for seconds in [
        0,
        anniversary_seconds - 1,
        anniversary_seconds,
        anniversary_seconds + 1,
        86_400,
      ] {
        for two_digits in 0..100u8 {
          let want = oracle_fifty_year_rule(i64::from(two_digits), month, day, seconds, now);
          let month_u8 = u8::try_from(month).expect("a month of the twelve");
          let day_u8 = u8::try_from(day).expect("a day column of the two");
          assert_eq!(
            fifty_year_window(two_digits, month_u8, day_u8, seconds, now_unix).map(i64::from),
            Ok(want),
            "({two_digits}, {month}-{day} {seconds}s)"
          );
          checked += 1;
        }
      }
    }
  }
  assert_eq!(checked, 12 * 31 * 5 * 100);
}

// §5.6.7 scopes the fifty-year rule to `rfc850-date`, and the grammar agrees:
// `date2` holds the only two-digit YEAR: `date1` and `asctime-date` both spell
// `year = 4DIGIT`. So no clock, however wrong, can move what those two say —
// and the one that does move is the obsolete form the rule names.
#[test]
fn the_reference_instant_reaches_only_the_two_digit_format() {
  for input in [
    b"Sun, 06 Nov 1994 08:49:37 GMT".as_slice(),
    b"Sun Nov  6 08:49:37 1994",
  ] {
    for reference in [
      i64::MIN,
      Civil::new(0, 1, 1, 0, 0, 0).unix(),
      REFERENCE_INSTANT,
      Civil::new(9999, 12, 31, 23, 59, 59).unix(),
      i64::MAX,
    ] {
      assert_eq!(
        parse_http_date_from(input, reference).map(|d| d.unix_seconds()),
        Ok(SUNDAY_1994_11_06_08_49_37),
        "{:?} moved under reference instant {reference}",
        core::str::from_utf8(input),
      );
    }
  }
  let rfc850 = b"Sunday, 06-Nov-94 08:49:37 GMT".as_slice();
  assert_ne!(
    parse_http_date_from(rfc850, REFERENCE_INSTANT).map(|d| d.year()),
    parse_http_date_from(rfc850, Civil::new(2050, 1, 1, 0, 0, 0).unix()).map(|d| d.year()),
  );
}

// `parse_http_date` is `parse_http_date_from` with the crate's own anchor and
// nothing else. Without this, a wrapper that grew a second rule of its own —
// a different refusal, a shifted window — would pass every other test in this
// file, since they all reach one entry point or the other and never compare
// the two.
//
// The anchor's own value is checked against the calendar date its doc names,
// rather than being taken on trust: a constant nothing derives is a constant
// that can be a year out with no test to say so.
#[test]
fn the_wrapper_delegates_with_the_crates_own_anchor() {
  assert_eq!(REFERENCE_INSTANT, Civil::new(2026, 1, 1, 0, 0, 0).unix());
  for input in [
    b"Sun, 06 Nov 1994 08:49:37 GMT".as_slice(),
    b"Sunday, 06-Nov-94 08:49:37 GMT",
    b"Sun Nov  6 08:49:37 1994",
    b"Sunday, 06-Nov-76 08:49:37 GMT",
    b"Sunday, 06-Nov-77 08:49:37 GMT",
    b"Xxx, 06 Nov 1994 08:49:37 GMT",
    b"Sun, 06 Nov 1994",
    b"",
  ] {
    assert_eq!(
      parse_http_date(input),
      parse_http_date_from(input, REFERENCE_INSTANT),
      "{:?}",
      core::str::from_utf8(input),
    );
  }
}

// The window that fixed anchor actually fixes, spelled out, because its doc
// spells it out and a doc nothing checks drifts. 2076 is reachable from this
// anchor for exactly one timestamp — the anniversary itself — which is the
// visible difference between a rule measured in instants and one measured in
// years, stated at the crate's own default.
#[test]
fn the_fixed_anchor_admits_2076_for_one_instant_only() {
  let year_of = |v: &[u8]| parse_http_date(v).map(|d| d.year());
  assert_eq!(year_of(b"Wednesday, 01-Jan-76 00:00:00 GMT"), Ok(2076));
  assert_eq!(year_of(b"Wednesday, 01-Jan-76 00:00:01 GMT"), Ok(1976));
  assert_eq!(year_of(b"Sunday, 06-Nov-76 08:49:37 GMT"), Ok(1976));
  assert_eq!(year_of(b"Sunday, 06-Nov-75 08:49:37 GMT"), Ok(2075));
  assert_eq!(year_of(b"Sunday, 06-Nov-77 08:49:37 GMT"), Ok(1977));
  assert_eq!(year_of(b"Sunday, 06-Nov-00 08:49:37 GMT"), Ok(2000));
  assert_eq!(year_of(b"Sunday, 06-Nov-99 08:49:37 GMT"), Ok(1999));
  assert_eq!(year_of(b"Sunday, 06-Nov-94 08:49:37 GMT"), Ok(1994));
}

// `year = 4DIGIT` reaches back past the epoch and past year 1, where the era
// arithmetic has to FLOOR rather than truncate toward zero. 0000-01-01 is the
// case that tells the two apart: its January puts the era's year at -1, and a
// truncating division would put it in era 0 rather than era -1.
#[test]
fn a_date_before_the_epoch_counts_backwards() {
  let seconds_of = |v: &[u8]| parse_http_date(v).map(|d| d.unix_seconds());
  assert_eq!(seconds_of(b"Thu, 01 Jan 1970 00:00:00 GMT"), Ok(0));
  assert_eq!(seconds_of(b"Wed, 31 Dec 1969 23:59:59 GMT"), Ok(-1));
  // 719_528 days from 0000-01-01 to 1970-01-01: 1970 years of 365 days plus the
  // 478 leap days in 0000..=1969, which is also Hinnant's 719_468-day offset
  // from 0000-03-01 plus the 60 days of that leap year's January and February.
  assert_eq!(
    seconds_of(b"Sat, 01 Jan 0000 00:00:00 GMT"),
    Ok(-62_167_219_200)
  );
}

// The two ARE required to agree, but the requirement is the SENDER's — RFC
// 5322 §3.3, which RFC 9110 §5.6.7 hands `day-name`'s semantics to, says "the
// day-of-week (if included) MUST be the day implied by the date". To a
// recipient §5.6.7 says the opposite, asking it to be robust in what it parses.
// So a Monday spelled `Sun` is read, and it is read as the 7th — the date
// decides, never the name.
#[test]
fn a_day_name_that_contradicts_its_date_is_still_read() {
  let parsed = parse_http_date(b"Sun, 07 Nov 1994 08:49:37 GMT").unwrap();
  assert_eq!(
    parsed.unix_seconds(),
    SUNDAY_1994_11_06_08_49_37 + 24 * 60 * 60
  );
}

// Each format's length is exact rather than a minimum, so a trailing byte — the
// OWS a field value may carry around its content, for one — makes the value a
// length that is none of the three.
#[test]
fn a_trailing_byte_is_a_length_no_format_has() {
  for trailed in [
    b"Sun, 06 Nov 1994 08:49:37 GMT ".as_slice(),
    b"Sunday, 06-Nov-94 08:49:37 GMT ",
    b"Sun Nov  6 08:49:37 1994 ",
  ] {
    assert_eq!(
      parse_http_date(trailed),
      Err(DateError::Length),
      "{:?}",
      core::str::from_utf8(trailed),
    );
  }
}

// What `every_truncation_of_a_valid_date_is_refused_not_misread` does for
// IMF-fixdate, for the two obsolete formats: a fixed-column parse that reads
// one column too far is a misread rather than a refusal, and only every prefix
// says so.
#[test]
fn every_truncation_of_the_obsolete_formats_is_refused_too() {
  for valid in [
    b"Sunday, 06-Nov-94 08:49:37 GMT".as_slice(),
    b"Sun Nov  6 08:49:37 1994",
  ] {
    for cut in 0..valid.len() {
      assert!(
        parse_http_date(&valid[..cut]).is_err(),
        "prefix of length {cut} of {:?} was accepted",
        core::str::from_utf8(valid),
      );
    }
  }
}

// §5.6.7's two obligations are not symmetric — a recipient MUST accept all
// three formats, a sender MUST generate only `IMF-fixdate` — and the round trip
// is that asymmetry stated as a test rather than as a sentence: three inputs,
// one output format.
#[test]
fn every_accepted_format_formats_back_as_imf_fixdate() {
  let mut out = [0u8; IMF_FIXDATE_LEN];
  for input in [
    b"Sun, 06 Nov 1994 08:49:37 GMT".as_slice(),
    b"Sunday, 06-Nov-94 08:49:37 GMT".as_slice(),
    b"Sun Nov  6 08:49:37 1994".as_slice(),
  ] {
    let parsed = parse_http_date(input).unwrap();
    let written = format_imf_fixdate(&parsed, &mut out).unwrap();
    assert_eq!(written, IMF_FIXDATE_LEN);
    assert_eq!(&out[..written], b"Sun, 06 Nov 1994 08:49:37 GMT");
  }
}

// Matching `head::encode`'s contract: a buffer too small is refused and NOTHING
// is written, so a caller that ignores the error cannot ship a truncated date.
//
// `BufferTooSmall` and not `Length`: `Length` is the INPUT not being one of the
// three formats' fixed lengths, and an output buffer with no room is a
// different rule refusing. One variant per rule, so the assertion below names
// the reason rather than the refusal.
#[test]
fn a_short_buffer_is_refused_and_writes_nothing() {
  const SENTINEL: u8 = 0xAB;
  let parsed = parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
  for len in 0..IMF_FIXDATE_LEN {
    let mut out = [SENTINEL; IMF_FIXDATE_LEN];
    assert_eq!(
      format_imf_fixdate(&parsed, &mut out[..len]),
      Err(DateError::BufferTooSmall)
    );
    assert!(
      out.iter().all(|&b| b == SENTINEL),
      "a {len}-byte buffer was refused and still written to"
    );
  }
}

// The length is a fixed SIZE and not a maximum, so room to spare is room left
// alone: a caller that hands over a larger buffer keeps every byte past the
// twenty-ninth.
#[test]
fn a_longer_buffer_keeps_every_byte_past_the_twenty_ninth() {
  const SENTINEL: u8 = 0xAB;
  let parsed = parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
  let mut out = [SENTINEL; IMF_FIXDATE_LEN * 2];
  assert_eq!(format_imf_fixdate(&parsed, &mut out), Ok(IMF_FIXDATE_LEN));
  assert_eq!(&out[..IMF_FIXDATE_LEN], b"Sun, 06 Nov 1994 08:49:37 GMT");
  assert!(out[IMF_FIXDATE_LEN..].iter().all(|&b| b == SENTINEL));
}

// The `day-name` written is DERIVED from the date, never echoed from the input,
// and that is a sender's OBLIGATION: RFC 5322 §3.3, which RFC 9110 §5.6.7 hands
// `day-name`'s semantics to, says "the day-of-week (if included) MUST be the
// day implied by the date". The parser reads a Monday spelled `Sun` as the 7th
// because a recipient is told to be robust; echoing that spelling back out
// would put a caller of this crate in breach.
#[test]
fn the_day_name_is_derived_from_the_date_not_echoed_from_the_input() {
  let mut out = [0u8; IMF_FIXDATE_LEN];
  let parsed = parse_http_date(b"Sun, 07 Nov 1994 08:49:37 GMT").unwrap();
  assert_eq!(format_imf_fixdate(&parsed, &mut out), Ok(IMF_FIXDATE_LEN));
  assert_eq!(&out, b"Mon, 07 Nov 1994 08:49:37 GMT");
}

// All seven names over seven consecutive days, so the derivation is pinned at
// every offset of the week rather than at the one a single fixture happens to
// land on. An off-by-one in the epoch's own weekday would pass a test that
// checked one day and fail all seven here.
#[test]
fn a_full_week_runs_through_all_seven_day_names() {
  let mut out = [0u8; IMF_FIXDATE_LEN];
  // 6 November 1994 is §5.6.7's own Sunday, so the week beginning there runs
  // Sun, Mon, … Sat.
  //
  // The seven names are spelled HERE rather than read out of `DAY_NAMES`. They
  // used to be `DAY_NAMES.iter().cycle().skip(6)`, which made every assertion
  // in this loop hold for any CONTENT of that table: `day_name` destructures
  // the same array in the same order, so a rotated or transposed table moved
  // both sides together and the week still "ran through all seven" while every
  // date written carried the wrong name. Tue, Fri and Sat appear nowhere else
  // in this file, so nothing else would have caught it either.
  for (day, expected) in (6u8..=12).zip([
    b"Sun".as_slice(),
    b"Mon",
    b"Tue",
    b"Wed",
    b"Thu",
    b"Fri",
    b"Sat",
  ]) {
    let mut input = *b"Mon, 06 Nov 1994 08:49:37 GMT";
    // Spelled here rather than through the module's own digit writer, so a
    // fault in that writer cannot supply the input that hides it.
    input[5..7].copy_from_slice(&[b'0' + day / 10, b'0' + day % 10]);
    let parsed = parse_http_date(input.as_slice()).unwrap();
    assert_eq!(format_imf_fixdate(&parsed, &mut out), Ok(IMF_FIXDATE_LEN));
    assert_eq!(
      &out[..3],
      expected,
      "{day} Nov 1994 was written with the wrong day name",
    );
  }
}

// Day 0 of the epoch is a Thursday and the day before it is a Wednesday, which
// is the whole reason the derivation takes a EUCLIDEAN remainder: a date before
// the epoch has a NEGATIVE day count, and `%` would put day -1 six places after
// day 0 rather than one place before it. `year = 4DIGIT` reaches back that far,
// so this is a date the grammar admits and not a hypothetical.
#[test]
fn the_day_name_is_derived_across_the_epoch_in_both_directions() {
  let mut out = [0u8; IMF_FIXDATE_LEN];
  for (input, expected) in [
    (
      b"Mon, 01 Jan 1970 00:00:00 GMT".as_slice(),
      b"Thu, 01 Jan 1970 00:00:00 GMT".as_slice(),
    ),
    (
      b"Mon, 31 Dec 1969 23:59:59 GMT".as_slice(),
      b"Wed, 31 Dec 1969 23:59:59 GMT".as_slice(),
    ),
    // The lowest year this writer will spell at all. Year 0000 used to stand
    // here, for `days_from_civil`'s era floor and for `four_ascii_digits`'
    // leading zeros; RFC 5322 §3.3's "The year is any numeric year 1900 or
    // later" now refuses it on the way out, so the reader keeps that case
    // (`a_date_before_the_epoch_counts_backwards`) and the writer takes its
    // own boundary instead.
    (
      b"Sun, 01 Jan 1900 00:00:00 GMT".as_slice(),
      b"Mon, 01 Jan 1900 00:00:00 GMT".as_slice(),
    ),
  ] {
    let parsed = parse_http_date(input).unwrap();
    assert_eq!(format_imf_fixdate(&parsed, &mut out), Ok(IMF_FIXDATE_LEN));
    assert_eq!(
      out.as_slice(),
      expected,
      "{:?}",
      core::str::from_utf8(input)
    );
  }
}

// The day count fed to the derivation is the CIVIL one, and this is the test
// that says so. A leap second shares the FOLLOWING midnight's epoch second, so
// a writer deriving the weekday from `unix_seconds` divided by a day would name
// the next day beside a date that says otherwise — `Mon, 31 Dec 1995`, exactly
// the self-contradiction RFC 5322 §3.3's "the day-of-week (if included) MUST be
// the day implied by the date" forbids. Nothing else in this file formats a
// leap second, so without this the substitution is invisible: every other test
// stays green under it.
#[test]
fn a_leap_second_is_written_with_the_day_name_of_its_own_civil_date() {
  let mut out = [0u8; IMF_FIXDATE_LEN];
  let leap = parse_http_date(b"Sun, 31 Dec 1995 23:59:60 GMT").unwrap();
  // The two instants a derivation through the epoch cannot tell apart: the
  // Sunday leap second and the Monday midnight after it are one POSIX second.
  assert_eq!(leap.unix_seconds(), 820_454_400);
  assert_eq!(
    parse_http_date(b"Mon, 01 Jan 1996 00:00:00 GMT").map(|d| d.unix_seconds()),
    Ok(820_454_400)
  );
  assert_eq!(format_imf_fixdate(&leap, &mut out), Ok(IMF_FIXDATE_LEN));
  // Read back as text rather than as bytes: what this test catches differs in
  // three bytes out of twenty-nine, and a reader of the failure should not have
  // to decode it.
  assert_eq!(
    core::str::from_utf8(&out),
    Ok("Sun, 31 Dec 1995 23:59:60 GMT")
  );
}

// One table serves both directions, and this is what says the reader and the
// writer agree at every one of its twelve entries rather than at the November
// the other fixtures all use. A writer with its own second spelling of the
// months would pass every test above.
//
// The names are spelled HERE, and each is pinned to the INSTANT it denotes by
// the oracle's own calendar. Both halves used to come from `MONTH_NAMES`:
// `month_number` finds a name's position in that table and `month_name` reads
// the same position back, so `parsed.month == index + 1` and
// `out[8..11] == name` held for any content and any ORDER of it. Transpose two
// entries and every date bearing either name moves a month — wrong
// `unix_seconds`, wrong day-of-month bound — with this test still green. Only
// Jan, Feb, Nov and Dec are pinned to a verified instant anywhere else in this
// file; the other eight were pinned nowhere at all.
#[test]
fn every_month_round_trips_through_the_one_table() {
  let mut out = [0u8; IMF_FIXDATE_LEN];
  for (name, number) in [
    (b"Jan".as_slice(), 1i64),
    (b"Feb", 2),
    (b"Mar", 3),
    (b"Apr", 4),
    (b"May", 5),
    (b"Jun", 6),
    (b"Jul", 7),
    (b"Aug", 8),
    (b"Sep", 9),
    (b"Oct", 10),
    (b"Nov", 11),
    (b"Dec", 12),
  ] {
    let mut input = *b"Sun, 15 Jan 1994 08:49:37 GMT";
    input[8..11].copy_from_slice(name);
    let parsed = parse_http_date(input.as_slice()).unwrap();
    assert_eq!(i64::from(parsed.month), number, "{:?}", name);
    assert_eq!(
      parsed.unix_seconds(),
      Civil::new(1994, number, 15, 8, 49, 37).unix(),
      "15 {:?} 1994 is not the instant the oracle's calendar puts it at",
      name
    );
    assert_eq!(format_imf_fixdate(&parsed, &mut out), Ok(IMF_FIXDATE_LEN));
    assert_eq!(&out[8..11], name, "month {number} was not written back");
    assert_eq!(
      parse_http_date(out.as_slice()).map(|d| d.unix_seconds()),
      Ok(parsed.unix_seconds()),
    );
  }
}

// `year = 4DIGIT` is a CEILING on the way out as much as a shape on the way in,
// and a year past it is reachable rather than hypothetical: the fifty-year
// window is measured from a year the CALLER supplies, so a caller that names
// one past 9949 gets a five-digit year out of an `rfc850-date`. `IMF-fixdate`
// has no column to write it in, so it is refused — and refused with the YEAR's
// own rule, not with the buffer's, which has room.
#[test]
fn a_year_imf_fixdate_cannot_spell_is_refused_rather_than_truncated() {
  const SENTINEL: u8 = 0xAB;
  let mut out = [SENTINEL; IMF_FIXDATE_LEN];
  let past_four_digits = parse_http_date_from(
    b"Sunday, 06-Nov-40 08:49:37 GMT",
    Civil::new(9990, 11, 6, 8, 49, 37).unix(),
  )
  .unwrap();
  assert_eq!(past_four_digits.year(), 10_040);
  assert_eq!(
    format_imf_fixdate(&past_four_digits, &mut out),
    Err(DateError::Year)
  );
  assert!(
    out.iter().all(|&b| b == SENTINEL),
    "a refused encode wrote to the buffer"
  );
  // The other side of the same boundary: 9999 is four digits and is written.
  let last_four_digit_year = parse_http_date(b"Sun, 06 Nov 9999 08:49:37 GMT").unwrap();
  assert_eq!(
    format_imf_fixdate(&last_four_digit_year, &mut out),
    Ok(IMF_FIXDATE_LEN)
  );
  assert_eq!(&out[12..16], b"9999");
}

// The OTHER end of the same field, and the other rule. RFC 9110 §5.6.7 gives
// `year` the semantics of the Internet Message Format construct of that name,
// and RFC 5322 §3.3 says "The year is any numeric year 1900 or later". That
// binds the sender — a permissive recipient carries someone else's fault, a
// permissive sender commits one — so the asymmetry is deliberate: these dates
// PARSE and will not be written back.
//
// The refusal names its own rule and not `DateError::Year`. Sharing that
// variant with the four-digit ceiling would leave this assertion unable to say
// which end refused, and would let a writer that had lost the ceiling pass the
// test written for the floor.
#[test]
fn a_year_before_1900_is_read_and_then_refused_on_the_way_out() {
  const SENTINEL: u8 = 0xAB;
  let mut out = [SENTINEL; IMF_FIXDATE_LEN];
  // The third is the fifty-year window's own way of reaching a year below 1900:
  // measured from an 1860 clock, `99` is 1899. So this refusal is reachable
  // from an `rfc850-date` a peer sent, not only from a date a caller built.
  let early_clock = Civil::new(1860, 1, 1, 0, 0, 0).unix();
  for early in [
    (
      b"Sat, 01 Jan 0000 00:00:00 GMT".as_slice(),
      REFERENCE_INSTANT,
    ),
    (b"Sun, 31 Dec 1899 23:59:59 GMT", REFERENCE_INSTANT),
    (b"Sunday, 06-Nov-99 08:49:37 GMT", early_clock),
  ] {
    let (early, now) = early;
    let parsed = parse_http_date_from(early, now).unwrap_or_else(|err| {
      panic!(
        "{:?} was refused by the reader: {err}",
        core::str::from_utf8(early)
      )
    });
    assert!(parsed.year() < 1900, "{:?}", core::str::from_utf8(early));
    assert_eq!(
      format_imf_fixdate(&parsed, &mut out),
      Err(DateError::YearBefore1900),
      "{:?}",
      core::str::from_utf8(early),
    );
    assert!(
      out.iter().all(|&b| b == SENTINEL),
      "a refused encode wrote to the buffer"
    );
  }

  // "1900 or later" includes 1900 itself, and the year below it is the first
  // refusal — the exact edge, so a bound off by one fails here.
  let floor = parse_http_date(b"Sun, 01 Jan 1900 00:00:00 GMT").unwrap();
  assert_eq!(floor.year(), 1900);
  assert_eq!(format_imf_fixdate(&floor, &mut out), Ok(IMF_FIXDATE_LEN));
  assert_eq!(
    core::str::from_utf8(&out),
    Ok("Mon, 01 Jan 1900 00:00:00 GMT")
  );
  let below = parse_http_date(b"Sun, 31 Dec 1899 00:00:00 GMT").unwrap();
  assert_eq!(below.year(), 1899);
  assert_eq!(
    format_imf_fixdate(&below, &mut out),
    Err(DateError::YearBefore1900)
  );

  // Both ends of the field refuse, and they refuse with DIFFERENT variants.
  // Without this the two are indistinguishable to a reader of either test.
  let past_four_digits = parse_http_date_from(
    b"Sunday, 06-Nov-40 08:49:37 GMT",
    Civil::new(9990, 11, 6, 8, 49, 37).unix(),
  )
  .unwrap();
  assert_ne!(
    format_imf_fixdate(&past_four_digits, &mut out),
    format_imf_fixdate(&below, &mut out)
  );
  assert_eq!(
    format_imf_fixdate(&past_four_digits, &mut out),
    Err(DateError::Year)
  );
}

// The buffer is sized BEFORE either year rule is applied, so a caller that is
// wrong about both gets the buffer's refusal. Stated because the order is a
// choice: `first_chunk_mut` is what makes the write one assignment, and moving
// a year check above it would make a short buffer report a year fault.
#[test]
fn a_short_buffer_outranks_both_year_rules() {
  let below = parse_http_date(b"Sun, 31 Dec 1899 00:00:00 GMT").unwrap();
  let mut out = [0u8; IMF_FIXDATE_LEN - 1];
  assert_eq!(
    format_imf_fixdate(&below, &mut out),
    Err(DateError::BufferTooSmall)
  );
}
