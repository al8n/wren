//! The QPACK static table (RFC 9204 Appendix A), 99 entries, index 0..=98.

mod generated;

/// The static index whose `(name, value)` both match, if any.
///
/// Exposed only for the QPACK static-lookup benchmark; not a stable public API.
#[doc(hidden)]
#[inline]
pub fn find_name_value(name: &str, value: &str) -> Option<usize> {
  generated::find_name_value(name, value)
}

/// The first static index whose name matches, if any (for literal-with-name-ref).
///
/// Exposed only for the QPACK static-lookup benchmark; not a stable public API.
#[doc(hidden)]
#[inline]
pub fn find_name(name: &str) -> Option<usize> {
  generated::find_name(name)
}

/// Number of entries in the QPACK static table.
#[cfg(test)]
pub(crate) const STATIC_TABLE_LEN: usize = generated::STATIC_TABLE_LEN;

/// Returns the static-table `(name, value)` entry at `index`.
#[inline]
pub(crate) fn entry(index: usize) -> Option<(&'static str, &'static str)> {
  generated::entry(index)
}

#[cfg(test)]
mod tests {
  use super::{STATIC_TABLE_LEN, entry, find_name, find_name_value};

  #[test]
  fn name_value_lookup_matches_static_table() {
    for index in 0..STATIC_TABLE_LEN {
      let (name, value) = entry(index).expect("static table entry");
      assert_eq!(find_name_value(name, value), Some(index));
    }
  }

  #[test]
  fn name_lookup_returns_first_static_index() {
    for index in 0..STATIC_TABLE_LEN {
      let (name, _) = entry(index).expect("static table entry");
      let expected = (0..STATIC_TABLE_LEN)
        .position(|candidate| entry(candidate).is_some_and(|(n, _)| n == name));
      if expected == Some(index) {
        assert_eq!(find_name(name), Some(index));
      }
    }
  }
}
