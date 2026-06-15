use super::*;

#[test]
fn slice_headers_visits_pairs_in_order() {
  let pairs = [(":method", "CONNECT"), (":path", "/")];
  let expected: [(&str, &str); 2] = [(":method", "CONNECT"), (":path", "/")];
  let mut i = 0usize;
  Headers::for_each(&pairs[..], &mut |n, v| {
    assert_eq!((n, v), expected[i]);
    i += 1;
  })
  .unwrap();
  assert_eq!(i, 2);
}
