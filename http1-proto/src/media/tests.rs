use super::*;

#[test]
fn qvalue_accepts_exactly_what_the_abnf_spells() {
  // `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`
  assert_eq!(parse_qvalue(b"0"), Some(Weight::ZERO));
  assert_eq!(parse_qvalue(b"1"), Some(Weight::ONE));
  assert_eq!(parse_qvalue(b"0.5"), Some(Weight(500)));
  assert_eq!(parse_qvalue(b"0.05"), Some(Weight(50)));
  assert_eq!(parse_qvalue(b"0.005"), Some(Weight(5)));
  assert_eq!(parse_qvalue(b"0.001"), Some(Weight(1)));
  assert_eq!(parse_qvalue(b"1.000"), Some(Weight::ONE));
  // `[ "." 0*3DIGIT ]` admits ZERO digits after the dot.
  assert_eq!(parse_qvalue(b"0."), Some(Weight::ZERO));
  assert_eq!(parse_qvalue(b"1."), Some(Weight::ONE));
}

#[test]
fn qvalue_refuses_what_the_abnf_does_not_spell() {
  for bad in [
    b"1.001".as_slice(), // 1 admits only zeros after the dot
    b"1.5",
    b"0.5000", // 0*3DIGIT is at most three
    b".5",     // no leading digit
    b"00.5",
    b"2",
    b"",
    b"blah",
    b"0,5",
    b"-0.5",
    b"0.5 ",
  ] {
    assert_eq!(parse_qvalue(bad), None, "{:?} is not a qvalue", bad);
  }
}

#[test]
fn weight_orders_as_the_rfc_says_it_does() {
  // RFC 9110 section 12.4.2: "0.001 is the least preferred and 1 is the most
  // preferred".
  assert!(Weight::ZERO < Weight(1));
  assert!(Weight(1) < Weight(500));
  assert!(Weight(500) < Weight::ONE);
  assert_eq!(Weight::ONE.thousandths(), 1000);
  assert_eq!(Weight::ZERO.thousandths(), 0);
}
