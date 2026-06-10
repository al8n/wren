//! Incremental, fail-fast UTF-8 validation for streaming text payloads.
//!
//! RFC 6455 §8.1 requires text messages to be valid UTF-8, and §5.4 lets a
//! message arrive as arbitrarily-split fragments and frames; Autobahn
//! section 6 additionally requires *fail-fast* behaviour — the connection
//! fails (1007) as soon as a byte makes the text invalid, without waiting
//! for the message to end.
//!
//! State is the explicit well-formed byte-range table from the Unicode
//! standard (TUS Table 3-7), not a DFA lookup table, so the code can be
//! checked against the standard by eye:
//!
//! | lead       | continuation bounds                  |
//! |------------|--------------------------------------|
//! | 00..=7F    | —                                    |
//! | C2..=DF    | 80..=BF                              |
//! | E0         | A0..=BF, then 80..=BF                |
//! | E1..=EC    | 80..=BF ×2                           |
//! | ED         | 80..=9F, then 80..=BF (no surrogates)|
//! | EE..=EF    | 80..=BF ×2                           |
//! | F0         | 90..=BF, then 80..=BF ×2             |
//! | F1..=F3    | 80..=BF ×3                           |
//! | F4         | 80..=8F, then 80..=BF ×2 (≤ U+10FFFF)|
//!
//! C0, C1, F5..=FF, and a continuation byte in lead position are invalid.

/// A byte made the text invalid; `at` is the byte's index within the input
/// slice passed to the [`Utf8Validator::feed`] call that detected it.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct InvalidUtf8 {
  pub(crate) at: usize,
}

/// Streaming UTF-8 validator. Feed payload chunks in arrival order; the
/// validator carries in-flight character state across feeds.
#[derive(Debug, Clone)]
pub(crate) struct Utf8Validator {
  /// Continuation bytes still expected for the in-flight character
  /// (0 = at a character boundary).
  need: u8,
  /// Inclusive bounds for the *next* continuation byte. After the
  /// (possibly constrained) second byte is consumed these reset to 80..=BF.
  lower: u8,
  upper: u8,
}

impl Utf8Validator {
  /// A fresh validator, at a character boundary.
  pub(crate) const fn new() -> Self {
    Self {
      need: 0,
      lower: 0x80,
      upper: 0xBF,
    }
  }

  /// True when no character is in flight — a text message may legally end
  /// here (RFC 6455 §8.1: a message truncated mid-character is invalid).
  pub(crate) const fn is_boundary(&self) -> bool {
    self.need == 0
  }

  /// Continuation bytes still required to finish the in-flight character.
  pub(crate) const fn pending_needed(&self) -> u8 {
    self.need
  }

  /// Forgets any in-flight character (for reuse across messages).
  pub(crate) fn reset(&mut self) {
    *self = Self::new();
  }

  /// Validates `input`, advancing the streaming state across all of it.
  ///
  /// Returns the length of the longest prefix of `input` that ends at a
  /// character boundary (the `&str`-sliceable part once any carried prefix
  /// is accounted for). Bytes past that boundary belong to an in-flight
  /// character continued on the next feed.
  pub(crate) fn feed(&mut self, input: &[u8]) -> Result<usize, InvalidUtf8> {
    let mut complete = 0;
    for (i, &b) in input.iter().enumerate() {
      if self.need == 0 {
        match b {
          0x00..=0x7F => complete = i.saturating_add(1),
          0xC2..=0xDF => self.start(1, 0x80, 0xBF),
          0xE0 => self.start(2, 0xA0, 0xBF),
          0xE1..=0xEC | 0xEE..=0xEF => self.start(2, 0x80, 0xBF),
          0xED => self.start(2, 0x80, 0x9F),
          0xF0 => self.start(3, 0x90, 0xBF),
          0xF1..=0xF3 => self.start(3, 0x80, 0xBF),
          0xF4 => self.start(3, 0x80, 0x8F),
          _ => return Err(InvalidUtf8 { at: i }),
        }
      } else {
        if b < self.lower || b > self.upper {
          return Err(InvalidUtf8 { at: i });
        }
        self.need = self.need.saturating_sub(1);
        self.lower = 0x80;
        self.upper = 0xBF;
        if self.need == 0 {
          complete = i.saturating_add(1);
        }
      }
    }
    Ok(complete)
  }

  #[inline]
  fn start(&mut self, need: u8, lower: u8, upper: u8) {
    self.need = need;
    self.lower = lower;
    self.upper = upper;
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  fn feed_all(chunks: &[&[u8]]) -> Result<(), usize> {
    let mut v = Utf8Validator::new();
    for chunk in chunks {
      v.feed(chunk).map_err(|e| e.at)?;
    }
    if v.is_boundary() {
      Ok(())
    } else {
      Err(usize::MAX)
    }
  }

  #[test]
  fn ascii_and_multibyte_whole() {
    assert_eq!(feed_all(&[b"hello"]), Ok(()));
    assert_eq!(feed_all(&["héllo wörld".as_bytes()]), Ok(()));
    assert_eq!(feed_all(&["日本語 𐍈".as_bytes()]), Ok(()));
  }

  #[test]
  fn split_at_every_position_is_accepted() {
    let s = "aé日𐍈z".as_bytes(); // 1-, 2-, 3-, 4-byte chars
    for cut in 0..=s.len() {
      let (l, r) = s.split_at(cut);
      assert_eq!(feed_all(&[l, r]), Ok(()), "cut at {cut}");
    }
  }

  #[test]
  fn complete_boundary_tracks_last_char_end() {
    let mut v = Utf8Validator::new();
    // "é" = C3 A9. Feed "aéb" split mid-é.
    assert_eq!(v.feed(b"a\xC3").unwrap(), 1); // boundary after 'a'
    assert!(!v.is_boundary());
    assert_eq!(v.pending_needed(), 1);
    assert_eq!(v.feed(b"\xA9b").unwrap(), 2); // é completes at 1, 'b' at 2
    assert!(v.is_boundary());
  }

  #[test]
  fn invalid_sequences_fail_fast_at_the_offending_byte() {
    // Overlong "/" (C0 AF): C0 is never a valid lead.
    let mut v = Utf8Validator::new();
    assert_eq!(v.feed(b"\xC0\xAF").unwrap_err().at, 0);

    // Overlong NUL (E0 80 80): second byte must be A0..=BF.
    let mut v = Utf8Validator::new();
    assert_eq!(v.feed(b"\xE0\x80\x80").unwrap_err().at, 1);

    // CESU-8 surrogate (ED A0 80): second byte must be 80..=9F.
    let mut v = Utf8Validator::new();
    assert_eq!(v.feed(b"\xED\xA0\x80").unwrap_err().at, 1);

    // Above U+10FFFF (F4 90 80 80): second byte must be 80..=8F.
    let mut v = Utf8Validator::new();
    assert_eq!(v.feed(b"\xF4\x90\x80\x80").unwrap_err().at, 1);

    // F5..FF are never valid leads.
    let mut v = Utf8Validator::new();
    assert_eq!(v.feed(b"a\xF5").unwrap_err().at, 1);

    // A bare continuation byte is never a valid lead.
    let mut v = Utf8Validator::new();
    assert_eq!(v.feed(b"\x80").unwrap_err().at, 0);

    // A lead followed by a non-continuation fails at the second byte —
    // including when the split hides it across feeds.
    let mut v = Utf8Validator::new();
    v.feed(b"\xC2").unwrap();
    assert_eq!(v.feed(b"A").unwrap_err().at, 0);
  }

  #[test]
  fn truncated_message_is_not_a_boundary() {
    let mut v = Utf8Validator::new();
    v.feed(b"\xF0\x9F").unwrap(); // first half of a 4-byte char
    assert!(!v.is_boundary());
    assert_eq!(v.pending_needed(), 2);
    v.reset();
    assert!(v.is_boundary());
  }

  mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
      /// Any valid string, chunked arbitrarily, validates with boundaries
      /// that line up with `char` boundaries.
      ///
      /// `complete == 0` means "no char boundary inside THIS chunk" (the
      /// chunk may sit wholly inside one multi-byte char), so the absolute
      /// last-known boundary is tracked across feeds, and the validator's
      /// `is_boundary()` must agree with it after every feed.
      #[test]
      fn valid_strings_chunked_anywhere(s in ".*", cuts in proptest::collection::vec(any::<u16>(), 0..8)) {
        let bytes = s.as_bytes();
        let mut points: Vec<usize> =
          cuts.iter().map(|&c| usize::from(c) % (bytes.len() + 1)).collect();
        points.sort_unstable();
        points.dedup();

        let mut v = Utf8Validator::new();
        let mut start = 0;
        let mut last_boundary = 0;
        for &p in points.iter().chain(core::iter::once(&bytes.len())) {
          let complete = v.feed(&bytes[start..p]).unwrap();
          if complete > 0 {
            last_boundary = start + complete;
          }
          // Every reported boundary is a real char boundary in the original.
          prop_assert!(s.is_char_boundary(last_boundary));
          // The validator is at a boundary exactly when the last boundary
          // coincides with the total bytes fed so far.
          prop_assert_eq!(v.is_boundary(), last_boundary == p);
          start = p;
        }
        prop_assert!(v.is_boundary());
        prop_assert_eq!(last_boundary, bytes.len());
      }

      /// Single-shot verdict agrees with `core::str::from_utf8`:
      /// Ok ⇔ (no error AND ends at a boundary); a trailing incomplete char
      /// (from_utf8 `error_len() == None`) is pending, not an error.
      #[test]
      fn verdict_matches_core(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let mut v = Utf8Validator::new();
        let ours = v.feed(&bytes);
        match core::str::from_utf8(&bytes) {
          Ok(_) => {
            prop_assert!(ours.is_ok());
            prop_assert!(v.is_boundary());
            prop_assert_eq!(ours.unwrap(), bytes.len());
          }
          Err(e) => match e.error_len() {
            None => {
              // Truncated final char: accepted so far, pending continuation.
              prop_assert!(ours.is_ok());
              prop_assert!(!v.is_boundary());
              prop_assert_eq!(ours.unwrap(), e.valid_up_to());
            }
            Some(_) => {
              let at = ours.unwrap_err().at;
              // Fail-fast detection happens within the invalid sequence:
              // at or just after `valid_up_to`, never beyond 3 bytes in.
              prop_assert!(at >= e.valid_up_to());
              prop_assert!(at <= e.valid_up_to() + 3);
            }
          },
        }
      }
    }
  }
}
