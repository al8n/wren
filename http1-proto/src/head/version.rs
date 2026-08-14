//! RFC 9112 §2.3 `HTTP-version`, shared by both start-line codecs: a
//! request-line ends with it (§3), a status-line opens with it (§4).

use super::malformed;
use crate::error::H1Error;

/// HTTP version of a parsed start line.
///
/// Only 1.x reaches callers. RFC 9110 §6.2 makes a higher minor version
/// backwards compatible, so `HTTP/1.2`…`HTTP/1.9` normalize to `Http11`
/// semantics; `HTTP/0.9` and every other major version are rejected instead.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Version {
  /// `HTTP/1.0` (RFC 1945).
  Http10,
  /// `HTTP/1.1` (RFC 9112), or a higher 1.x minor processed as 1.1.
  Http11,
}

/// RFC 9112 §2.3 `HTTP-version = HTTP-name "/" DIGIT "." DIGIT`, where
/// `HTTP-name = %s"HTTP"` — the `%s` prefix (RFC 8174) makes the name
/// case-SENSITIVE, so `http/1.1` is malformed grammar rather than an
/// unsupported version.
///
/// A well-formed version outside 1.x is `VersionNotSupported` instead: the
/// sender spoke correct HTTP grammar, just a protocol this core does not
/// implement, and RFC 9110 §15.6.6 answers that with 505 rather than 400.
///
/// RFC 9110 §6.2 (Control Data) makes a higher minor version backwards
/// compatible — "a recipient … SHOULD process the message as if it were in the
/// highest minor version within that major version to which the recipient is
/// conformant" — so `HTTP/1.2` … `HTTP/1.9` are processed as 1.1. The pinpoint
/// is §6.2 and not the section either specification points at first: §2.3 above
/// carries only the grammar and defers "the semantics of HTTP version numbers"
/// to RFC 9110 §2.5, which defines what the two digits MEAN without stating any
/// rule about what a recipient does with a higher minor.
///
/// `bytes` is the version field alone and `at` is where that field starts
/// within the caller's line, so every offset the error carries is already
/// rebased onto the line: a status-line passes 0, a request-line passes the
/// offset past its method and target.
pub(crate) fn parse_version(bytes: &[u8], at: usize) -> Result<Version, H1Error> {
  const NAME: &[u8; 5] = b"HTTP/";

  let Some(digits) = bytes.strip_prefix(NAME) else {
    // The first byte that deviates from the literal, or the end of a version
    // that stopped short of it.
    let offset = bytes
      .iter()
      .zip(NAME)
      .position(|(got, want)| got != want)
      .unwrap_or(bytes.len());
    return Err(malformed(
      at.saturating_add(offset),
      "expected HTTP-version",
    ));
  };
  let major_at = at.saturating_add(NAME.len());
  let Some((&major, rest)) = digits.split_first() else {
    return Err(malformed(major_at, "HTTP-version has no major digit"));
  };
  if !major.is_ascii_digit() {
    return Err(malformed(major_at, "HTTP-version major is not a digit"));
  }
  let dot_at = major_at.saturating_add(1);
  let Some((&dot, rest)) = rest.split_first() else {
    return Err(malformed(dot_at, "HTTP-version has no `.` separator"));
  };
  if dot != b'.' {
    return Err(malformed(dot_at, "HTTP-version separator is not `.`"));
  }
  let minor_at = dot_at.saturating_add(1);
  let Some((&minor, rest)) = rest.split_first() else {
    return Err(malformed(minor_at, "HTTP-version has no minor digit"));
  };
  if !minor.is_ascii_digit() {
    return Err(malformed(minor_at, "HTTP-version minor is not a digit"));
  }
  if !rest.is_empty() {
    return Err(malformed(
      minor_at.saturating_add(1),
      "trailing bytes after the HTTP-version",
    ));
  }

  match (major, minor) {
    (b'1', b'0') => Ok(Version::Http10),
    (b'1', _) => Ok(Version::Http11),
    _ => Err(H1Error::VersionNotSupported),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // RFC 9112 §2.3 (`HTTP-name "/" DIGIT "." DIGIT`, case-sensitive name), RFC
  // 9110 §6.2 (a higher minor is processed as the highest minor of that major
  // the recipient implements) and RFC 9110 §15.6.6 (505): correct grammar for a
  // protocol this core does not speak is NOT the same fault as broken grammar,
  // and only the latter is `Malformed`.
  #[test]
  fn unsupported_versions_are_not_malformed_ones() {
    assert_eq!(parse_version(b"HTTP/1.0", 0).unwrap(), Version::Http10);
    assert_eq!(parse_version(b"HTTP/1.9", 0).unwrap(), Version::Http11);
    assert_eq!(
      parse_version(b"HTTP/2.0", 0),
      Err(H1Error::VersionNotSupported)
    );
    assert_eq!(
      parse_version(b"HTTP/0.9", 0),
      Err(H1Error::VersionNotSupported)
    );
    assert!(matches!(
      parse_version(b"http/1.1", 0),
      Err(H1Error::Malformed(_))
    ));
    assert!(matches!(
      parse_version(b"HTTP/11.1", 0),
      Err(H1Error::Malformed(_))
    ));
  }

  // RFC 9112 §2.3: the offset names the byte that broke the grammar, rebased
  // onto the caller's line by `at` — §4 puts the version at the start of a
  // status-line, §3 puts it after the method and target of a request-line.
  #[test]
  fn offsets_are_rebased_onto_the_callers_line() {
    let H1Error::Malformed(d) = parse_version(b"XTTP/1.1", 0).unwrap_err() else {
      panic!()
    };
    assert_eq!(d.at(), 0);
    // 6 + 7: the `x` sitting where the minor DIGIT belongs.
    let H1Error::Malformed(d) = parse_version(b"HTTP/1.x", 6).unwrap_err() else {
      panic!()
    };
    assert_eq!(d.at(), 13);
  }
}
