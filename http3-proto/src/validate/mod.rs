//! Role-aware HTTP/3 message semantic validation (RFC 9114 §4.1–§4.5, §5;
//! RFC 8441 / RFC 9220 for Extended CONNECT). Validates message *control-data*
//! structure only — presence/ordering/duplication/placement of pseudo-headers,
//! connection-specific field rejection, status/method consistency. Application
//! semantics (routing, auth, value meaning) stay with the driver.
//!
//! Boundary: this module enforces the protocol-layer message structure (which
//! pseudo-headers are present, that they precede regular fields, that none are
//! duplicated or misplaced, that connection-specific fields are absent, and that
//! `:status`/`:method` are mutually consistent). It does **not** interpret what a
//! field value *means* — e.g. whether a WebSocket `:status` is 2xx or a
//! `:protocol` is `websocket` stays a driver-level concern. The driver's checks
//! are additive on top of this layer, not replaced by it.

use crate::{HeaderSet, error::H3Error};

/// The message context being validated.
///
/// Selects which RFC 9114 §4.3 rule set applies: a request leading section, a
/// final-response leading section, an interim (1xx) response section, or a
/// trailing section. The connection layer picks the variant from the stream role
/// and the section's placement (leading vs trailing) and, for client leading
/// sections, the `:status` class (see [`response_is_interim`]).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MessageKind {
  /// A request leading field section (server-received).
  Request,
  /// A final response leading field section (client-received).
  Response,
  /// An interim (1xx) response leading field section.
  Interim,
  /// A trailers field section (either direction).
  Trailers,
}

/// The pseudo-header facts a single decode pass records, without retaining any
/// borrow into the (lending) [`HeaderSet`]. Presence/value of each pseudo-header
/// the rule sets care about, plus the structural flags needed to enforce
/// ordering and duplication.
#[derive(Default)]
struct Scan {
  /// A regular (non-pseudo) field has been seen; any pseudo-header after this
  /// point violates the "pseudo-headers precede regular fields" rule.
  saw_regular: bool,
  /// A pseudo-header name not in the known request/response set was seen.
  unknown_pseudo: bool,
  /// A known single-valued pseudo-header appeared more than once.
  dup_pseudo: bool,
  /// A pseudo-header (`:`-prefixed name) was present at all.
  any_pseudo: bool,
  /// `:method` value, if present.
  method: Option<bool>,
  /// `:scheme` was present.
  scheme: bool,
  /// `:path` was present.
  path: bool,
  /// `:authority` was present.
  authority: bool,
  /// `:status` class, if a `:status` was present.
  status: Option<StatusClass>,
  /// `:protocol` was present (Extended CONNECT, RFC 8441/9220).
  protocol: bool,
}

/// The class of a `:status` pseudo-header value, used to enforce the response
/// rules without retaining a borrow into the section.
#[derive(Clone, Copy, Eq, PartialEq)]
enum StatusClass {
  /// An interim informational status (`100..=199`, RFC 9110 §15.2).
  Interim,
  /// A final status (`>= 200`).
  Final,
  /// A value that is non-numeric or outside the valid status range.
  Invalid,
}

/// Validates a decoded field section for `kind`, draining `headers`. Returns
/// `Ok(())` if the message control-data is well-formed, else
/// [`H3Error::MessageError`] (a stream error per RFC 9114 §4.1.2).
///
/// Enforced (RFC 9114 §4.3 unless noted):
/// - pseudo-headers precede regular fields; no unknown/misplaced pseudo-headers;
///   no duplicate single-valued pseudo-headers;
/// - **Request:** `:method` required; non-CONNECT methods require `:scheme` +
///   `:path` (`:authority` optional); **CONNECT** = only `:method` + `:authority`
///   (no `:scheme`/`:path`); **Extended CONNECT** (`:method`=CONNECT +
///   `:protocol`) = `:protocol` + `:scheme`/`:path`/`:authority` (RFC 8441/9220);
/// - **Response/Interim:** `:status` required; an interim status is `1xx`; a final
///   status is `>= 200`;
/// - **Field rules (§4.2):** reject `Connection`/`Keep-Alive`/`Proxy-Connection`/
///   `Transfer-Encoding`/`Upgrade`; `TE` may only be `trailers`; field names must
///   be lowercase;
/// - **Trailers:** no pseudo-headers; no connection-specific fields.
pub fn validate(kind: MessageKind, headers: &mut HeaderSet<'_>) -> Result<(), H3Error> {
  let mut scan = Scan::default();
  while let Some(pair) = headers.next().map_err(|e| e.to_h3())? {
    let name = pair.name();
    if let Some(pseudo) = name.strip_prefix(':') {
      // A pseudo-header. It must precede every regular field, and (for the names
      // this layer tracks) be single-valued. An unknown or context-wrong pseudo
      // name is rejected by the per-kind rules below via `unknown_pseudo`.
      if scan.saw_regular {
        return Err(H3Error::MessageError);
      }
      scan.any_pseudo = true;
      record_pseudo(&mut scan, pseudo, pair.value());
    } else {
      // A regular field: enforce the §4.2 field rules inline.
      check_field(name, pair.value())?;
      scan.saw_regular = true;
    }
  }
  if scan.dup_pseudo {
    return Err(H3Error::MessageError);
  }
  match kind {
    MessageKind::Request => check_request(&scan),
    MessageKind::Response => check_response(&scan, false),
    MessageKind::Interim => check_response(&scan, true),
    MessageKind::Trailers => check_trailers(&scan),
  }
}

/// Records one pseudo-header (`name` is the part after the leading `:`) into the
/// scan: known single-valued names flip a duplicate flag if seen twice; an
/// unrecognized name sets `unknown_pseudo` (rejected by the per-kind rules). The
/// `:method`/`:status` *values* are stored as their CONNECT / interim
/// classification so no borrow into the section is retained.
fn record_pseudo(scan: &mut Scan, name: &str, value: &str) {
  match name {
    "method" => set_once_value(&mut scan.method, value == "CONNECT", &mut scan.dup_pseudo),
    "scheme" => set_once(&mut scan.scheme, &mut scan.dup_pseudo),
    "path" => set_once(&mut scan.path, &mut scan.dup_pseudo),
    "authority" => set_once(&mut scan.authority, &mut scan.dup_pseudo),
    "status" => set_once_value(
      &mut scan.status,
      classify_status(value),
      &mut scan.dup_pseudo,
    ),
    "protocol" => set_once(&mut scan.protocol, &mut scan.dup_pseudo),
    _ => scan.unknown_pseudo = true,
  }
}

/// Marks a boolean presence flag, flagging a duplicate if it was already set.
fn set_once(flag: &mut bool, dup: &mut bool) {
  if *flag {
    *dup = true;
  }
  *flag = true;
}

/// Stores a derived value for an at-most-once pseudo-header (`:method` CONNECT
/// flag, `:status` class), flagging a duplicate if a value was already recorded.
fn set_once_value<T>(slot: &mut Option<T>, derived: T, dup: &mut bool) {
  if slot.is_some() {
    *dup = true;
  } else {
    *slot = Some(derived);
  }
}

/// Classifies a `:status` value as interim (`100..=199`, RFC 9110 §15.2), final
/// (`>= 200`), or invalid (non-numeric or below 100).
fn classify_status(value: &str) -> StatusClass {
  match value.parse::<u16>() {
    Ok(100..=199) => StatusClass::Interim,
    Ok(200..) => StatusClass::Final,
    _ => StatusClass::Invalid,
  }
}

/// Enforces the §4.2 field rules on one regular (non-pseudo) field: a lowercase
/// name, no connection-specific field, and `TE` (which cannot appear here as a
/// regular field name unless lowercase) restricted to `trailers`.
fn check_field(name: &str, value: &str) -> Result<(), H3Error> {
  // RFC 9114 §4.2: field names MUST be lowercase.
  if name.bytes().any(|b| b.is_ascii_uppercase()) {
    return Err(H3Error::MessageError);
  }
  // RFC 9114 §4.2: connection-specific fields are forbidden.
  if matches!(
    name,
    "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
  ) {
    return Err(H3Error::MessageError);
  }
  // RFC 9114 §4.2: the only permitted `TE` value is `trailers`.
  if name == "te" && value != "trailers" {
    return Err(H3Error::MessageError);
  }
  Ok(())
}

/// Applies the request rule set (RFC 9114 §4.3.1, RFC 8441/9220): `:method`
/// required; no unknown/response pseudo-headers; CONNECT, Extended CONNECT, and
/// normal-method shapes.
fn check_request(scan: &Scan) -> Result<(), H3Error> {
  // No response pseudo-header and no unrecognized pseudo-header in a request.
  if scan.status.is_some() || scan.unknown_pseudo {
    return Err(H3Error::MessageError);
  }
  let Some(is_connect) = scan.method else {
    // `:method` is mandatory for every request.
    return Err(H3Error::MessageError);
  };
  if is_connect {
    if scan.protocol {
      // Extended CONNECT (RFC 8441/9220): :method=CONNECT + :protocol, and the
      // request takes the normal-method origin form (:scheme + :path +
      // :authority).
      if scan.scheme && scan.path && scan.authority {
        Ok(())
      } else {
        Err(H3Error::MessageError)
      }
    } else {
      // Plain CONNECT (RFC 9114 §4.3.1): exactly :method + :authority — no
      // :scheme, no :path.
      if scan.authority && !scan.scheme && !scan.path {
        Ok(())
      } else {
        Err(H3Error::MessageError)
      }
    }
  } else {
    // A normal method: :scheme + :path required; :authority is optional; a stray
    // :protocol (only valid with CONNECT) is rejected.
    if scan.scheme && scan.path && !scan.protocol {
      Ok(())
    } else {
      Err(H3Error::MessageError)
    }
  }
}

/// Applies the response rule set (RFC 9114 §4.3.2): exactly a `:status`
/// pseudo-header whose class matches `interim`; no request pseudo-headers and no
/// unrecognized pseudo-header.
fn check_response(scan: &Scan, interim: bool) -> Result<(), H3Error> {
  // No request pseudo-header and no unrecognized pseudo-header in a response.
  if scan.method.is_some()
    || scan.scheme
    || scan.path
    || scan.authority
    || scan.protocol
    || scan.unknown_pseudo
  {
    return Err(H3Error::MessageError);
  }
  let want = if interim {
    StatusClass::Interim
  } else {
    StatusClass::Final
  };
  match scan.status {
    Some(class) if class == want => Ok(()),
    _ => Err(H3Error::MessageError),
  }
}

/// Applies the trailers rule set (RFC 9114 §4.1): no pseudo-headers at all and no
/// connection-specific fields (the latter enforced inline during the scan via
/// [`check_field`]).
fn check_trailers(scan: &Scan) -> Result<(), H3Error> {
  if scan.any_pseudo {
    return Err(H3Error::MessageError);
  }
  Ok(())
}

/// Whether a decoded response section's `:status` is interim (`100..=199`).
/// `Ok(None)` if there is no `:status` (the caller treats that as a validation
/// error in response context). Drains `headers`.
///
/// This is the focused `:status`-class scan the connection layer uses to tag a
/// client leading section as interim before choosing the [`MessageKind`] for the
/// full [`validate`] pass; the full pseudo-header validation lives in [`validate`].
pub fn response_is_interim(headers: &mut HeaderSet<'_>) -> Result<Option<bool>, H3Error> {
  while let Some(pair) = headers.next().map_err(|e| e.to_h3())? {
    if pair.name() == ":status" {
      return Ok(Some(classify_status(pair.value()) == StatusClass::Interim));
    }
  }
  Ok(None)
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod tests;
