//! Minimal `ws://` / `wss://` URL splitting. Validation of the parts is
//! delegated to websocket-proto's handshake builders — this only carves
//! scheme, authority, and path?query, and computes the default port.

use crate::error::ConnectError;

/// A parsed WebSocket URL, borrowed from the input string.
#[derive(Debug, Copy, Clone)]
pub(crate) struct WsUrl<'a> {
  pub(crate) tls: bool,
  /// Host (incl. brackets for IPv6) without the port.
  pub(crate) host: &'a str,
  pub(crate) port: u16,
  /// `host[:port]` exactly as written — the `Host:` header value.
  pub(crate) authority: &'a str,
  /// Always `/`-leading (`/` substituted for an empty path).
  pub(crate) path_and_query: &'a str,
}

impl<'a> WsUrl<'a> {
  pub(crate) fn parse(url: &'a str) -> Result<Self, ConnectError> {
    // Schemes are case-insensitive (RFC 3986 §3.1).
    let (tls, rest) = if let Some(r) = strip_scheme(url, "ws://") {
      (false, r)
    } else if let Some(r) = strip_scheme(url, "wss://") {
      (true, r)
    } else {
      return Err(ConnectError::UnsupportedScheme);
    };
    // Checked on the whole remainder: a `#` with no path would otherwise
    // land in the authority and corrupt the Host header.
    if rest.contains('#') {
      return Err(ConnectError::InvalidUrl("fragments are not allowed"));
    }
    let (authority, path_and_query) = match rest.find(['/', '?']) {
      // A query with no path has no `/` to split on; the request target
      // would need an allocation (`/?query`), so ask for the explicit form.
      Some(i) if rest.as_bytes().get(i) == Some(&b'?') => {
        return Err(ConnectError::InvalidUrl(
          "query without a path; write /?query",
        ));
      }
      Some(i) => rest.split_at(i),
      None => (rest, "/"),
    };
    if authority.is_empty() {
      return Err(ConnectError::InvalidUrl("empty authority"));
    }
    if authority.contains('@') {
      return Err(ConnectError::InvalidUrl("userinfo is not allowed"));
    }
    // Split host vs port; IPv6 brackets keep their interior colons.
    let (host, port) = if authority.starts_with('[') {
      let Some(end) = authority.find(']') else {
        return Err(ConnectError::InvalidUrl("unterminated IPv6 bracket"));
      };
      let host = authority.get(..=end).unwrap_or(authority);
      match authority.get(end + 1..) {
        Some("") => (host, None),
        Some(rest) => match rest.strip_prefix(':') {
          Some(p) => (host, Some(p)),
          None => return Err(ConnectError::InvalidUrl("malformed IPv6 authority")),
        },
        None => (host, None),
      }
    } else {
      match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
      }
    };
    let port = match port {
      Some(p) => match p.parse::<u16>() {
        Ok(0) | Err(_) => return Err(ConnectError::InvalidUrl("invalid port")),
        Ok(p) => p,
      },
      None if tls => 443,
      None => 80,
    };
    if host.is_empty() {
      return Err(ConnectError::InvalidUrl("empty host"));
    }
    Ok(Self {
      tls,
      host,
      port,
      authority,
      path_and_query,
    })
  }

  /// The host as a dialable name: IPv6 brackets stripped for the socket
  /// address lookup (and for TLS SNI).
  pub(crate) fn host_for_dial(&self) -> &'a str {
    self
      .host
      .strip_prefix('[')
      .and_then(|h| h.strip_suffix(']'))
      .unwrap_or(self.host)
  }
}

/// Case-insensitive scheme strip (the scheme is always ASCII; a non-ASCII
/// or short head simply fails to match).
fn strip_scheme<'a>(url: &'a str, scheme: &str) -> Option<&'a str> {
  let head = url.get(..scheme.len())?;
  head
    .eq_ignore_ascii_case(scheme)
    .then(|| url.get(scheme.len()..).unwrap_or(""))
}

#[cfg(test)]
mod tests;
