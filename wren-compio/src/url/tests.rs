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
fn rejects_bad_urls() {
  for bad in [
    "http://h/",
    "ws://",
    "ws://h/p#frag",
    "example.com/x",
    "wss://user@h/",
    "ws://[::1/p",
    "ws://[::1]x/p",
    "ws://h:70000/",
  ] {
    assert!(WsUrl::parse(bad).is_err(), "{bad}");
  }
}
