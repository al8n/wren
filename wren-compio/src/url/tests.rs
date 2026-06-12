use super::*;

#[test]
fn parses_ws_and_wss() {
  let u = WsUrl::parse("ws://example.com/chat?x=1").unwrap();
  assert!(!u.tls);
  assert_eq!(u.authority, "example.com");
  assert_eq!(u.host, "example.com");
  assert_eq!(u.port, 80);
  assert_eq!(u.path_and_query, "/chat?x=1");

  let u = WsUrl::parse("wss://example.com:8443").unwrap();
  assert!(u.tls);
  assert_eq!(u.port, 8443);
  assert_eq!(u.path_and_query, "/");
  assert_eq!(u.authority, "example.com:8443");

  let u = WsUrl::parse("ws://[::1]:9001/p").unwrap();
  assert_eq!(u.host, "[::1]");
  assert_eq!(u.host_for_dial(), "::1");
  assert_eq!(u.port, 9001);

  let u = WsUrl::parse("ws://[::1]/p").unwrap();
  assert_eq!(u.host, "[::1]");
  assert_eq!(u.port, 80);
}

#[test]
fn scheme_is_case_insensitive() {
  let u = WsUrl::parse("WS://example.com/chat").unwrap();
  assert!(!u.tls);
  assert_eq!(u.host, "example.com");

  let u = WsUrl::parse("Wss://example.com/").unwrap();
  assert!(u.tls);
  assert_eq!(u.port, 443);
}

#[test]
fn keeps_explicit_default_ports_in_the_authority() {
  let u = WsUrl::parse("ws://example.com:80/p").unwrap();
  assert_eq!(u.port, 80);
  assert_eq!(u.authority, "example.com:80");

  let u = WsUrl::parse("wss://example.com:443/p").unwrap();
  assert_eq!(u.port, 443);
  assert_eq!(u.authority, "example.com:443");
}

#[test]
fn rejects_bad_urls() {
  for bad in [
    "http://h/",
    "ws://",
    "ws://h/p#frag",
    "ws://h#frag",
    "ws://h?q=1",
    "example.com/x",
    "wss://user@h/",
    "ws://[::1/p",
    "ws://[::1]x/p",
    "ws://h:70000/",
    "ws://h:0/",
    "ws://h:/",
  ] {
    assert!(WsUrl::parse(bad).is_err(), "{bad}");
  }
}
