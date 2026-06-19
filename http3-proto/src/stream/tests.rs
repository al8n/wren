use super::*;
use crate::{
  frame::{FrameType, encode_header},
  qpack::encode_field_section,
};

fn headers_frame(headers: &[(&str, &str)]) -> std::vec::Vec<u8> {
  let mut payload = [0u8; 256];
  let plen = encode_field_section(headers.iter().copied(), &mut payload).unwrap();
  let mut out = std::vec::Vec::new();
  let mut hdr = [0u8; 16];
  let hn = encode_header(FrameType::Headers, plen as u64, &mut hdr).unwrap();
  out.extend_from_slice(&hdr[..hn]);
  out.extend_from_slice(&payload[..plen]);
  out
}

fn data_frame(payload: &[u8]) -> std::vec::Vec<u8> {
  let mut out = std::vec::Vec::new();
  let mut hdr = [0u8; 16];
  let hn = encode_header(FrameType::Data, payload.len() as u64, &mut hdr).unwrap();
  out.extend_from_slice(&hdr[..hn]);
  out.extend_from_slice(payload);
  out
}

#[test]
fn reads_headers_then_data() {
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT"), (":protocol", "websocket")]);
  {
    let mut items = s.handle(&req, &mut scratch);
    match items.next().unwrap().unwrap() {
      StreamItem::Headers {
        headers: mut hs, ..
      } => {
        let p = hs.next().unwrap().unwrap();
        assert_eq!((p.name(), p.value()), (":method", "CONNECT"));
        let p = hs.next().unwrap().unwrap();
        assert_eq!((p.name(), p.value()), (":protocol", "websocket"));
        assert!(hs.next().unwrap().is_none());
      }
      _ => panic!("expected Headers"),
    }
    assert!(items.next().unwrap().is_none());
  }
  let data = data_frame(b"hi");
  let mut items = s.handle(&data, &mut scratch);
  match items.next().unwrap().unwrap() {
    StreamItem::Data(chunk) => assert_eq!(chunk, b"hi"),
    _ => panic!("expected Data"),
  }
  assert!(items.next().unwrap().is_none());
}

#[test]
fn split_reads_reassemble() {
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT")]);
  let mut saw = false;
  for b in &req {
    let mut items = s.handle(core::slice::from_ref(b), &mut scratch);
    while let Some(item) = items.next().unwrap() {
      if let StreamItem::Headers {
        headers: mut hs, ..
      } = item
      {
        assert_eq!(hs.next().unwrap().unwrap().name(), ":method");
        saw = true;
      }
    }
  }
  assert!(saw);
}

#[test]
fn fragmented_headers_decode_with_fresh_scratch_each_call() {
  // A HEADERS field section that arrives fragmented across many `handle` calls must
  // decode correctly even when the caller passes a DIFFERENT, freshly-zeroed scratch
  // on every call. The in-progress field section is owned by the FSM, so the caller's
  // scratch is only transient Huffman-output space and need not be preserved across
  // calls: accumulating the partial section into the caller scratch instead would
  // make a fresh buffer on the next call decode stale/zeroed bytes → corruption /
  // QPACK error.
  let expected: [(&str, &str); 5] = [
    (":method", "CONNECT"),
    (":scheme", "https"),
    (":path", "/chat"),
    (":authority", "example.com"),
    (":protocol", "websocket"),
  ];
  let req = headers_frame(&expected);
  let mut s = RequestStream::new();
  // Each decoded (name, value) pair must match `expected` in order. We compare
  // borrowed `&str`s directly (no owned String) so this works on the alloc tier
  // too. Collect into a fixed-size record of "did pair i match" flags.
  let mut idx = 0usize;
  // Feed one byte at a time, each time with a brand-new zeroed scratch buffer.
  for b in &req {
    let mut scratch = [0u8; 512]; // fresh, distinct buffer per call
    let mut items = s.handle(core::slice::from_ref(b), &mut scratch);
    while let Some(item) = items.next().unwrap() {
      if let StreamItem::Headers {
        headers: mut hs, ..
      } = item
      {
        while let Some(p) = hs.next().unwrap() {
          let want = expected.get(idx).expect("more pairs than expected");
          assert_eq!((p.name(), p.value()), *want, "pair {idx} mismatch");
          idx = idx.saturating_add(1);
        }
      }
    }
  }
  assert_eq!(idx, expected.len(), "not all header pairs were decoded");
}

#[test]
fn fragmented_huffman_headers_decode_with_fresh_scratch_each_call() {
  // Huffman variant: the same fresh-scratch fragmentation, but with a Huffman-coded
  // value (:authority + Huffman("www.example.com")).
  // This exercises the completion path's use of the caller scratch as
  // Huffman-output space while the encoded section comes from FSM-owned storage.
  let fs: [u8; 16] = [
    0x00, 0x00, 0x50, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
  ];
  let mut frame = std::vec::Vec::new();
  let mut hdr = [0u8; 16];
  let hn = crate::frame::encode_header(crate::frame::FrameType::Headers, fs.len() as u64, &mut hdr)
    .unwrap();
  frame.extend_from_slice(&hdr[..hn]);
  frame.extend_from_slice(&fs);
  let mut s = RequestStream::new();
  let mut saw = false;
  for b in &frame {
    let mut scratch = [0u8; 512]; // fresh per call
    let mut items = s.handle(core::slice::from_ref(b), &mut scratch);
    while let Some(item) = items.next().unwrap() {
      if let StreamItem::Headers {
        headers: mut hs, ..
      } = item
      {
        let p = hs.next().unwrap().unwrap();
        assert_eq!((p.name(), p.value()), (":authority", "www.example.com"));
        saw = true;
      }
    }
  }
  assert!(saw);
}

#[test]
fn oversize_field_section_is_frame_error_not_panic() {
  // A HEADERS frame whose field section exceeds HDR_CAP must be a graceful frame
  // error, never a panic or an out-of-bounds copy. We claim a length larger than
  // HDR_CAP in the frame header; the FSM rejects it once accumulation overflows.
  let mut s = RequestStream::new();
  let mut scratch = [0u8; 512];
  let mut hdr = [0u8; 16];
  let claim = (super::HDR_CAP + 1) as u64;
  let hn = encode_header(FrameType::Headers, claim, &mut hdr).unwrap();
  // Feed the header plus a chunk of payload large enough to drive accumulation
  // past HDR_CAP (more than HDR_CAP bytes of "payload").
  let mut buf = std::vec::Vec::new();
  buf.extend_from_slice(&hdr[..hn]);
  buf.resize(buf.len() + super::HDR_CAP + 1, 0u8);
  let mut items = s.handle(&buf, &mut scratch);
  assert!(matches!(
    items.next(),
    Err(crate::error::H3Error::FrameError)
  ));
}

#[test]
fn malformed_later_field_line_errors_without_draining_headers() {
  // A HEADERS frame whose field section has a VALID first field line (`:status 200`,
  // indexed static) followed by an INVALID one (an
  // indexed line with T=0 = a dynamic-table reference, which this static-only
  // decoder rejects) must make `handle`'s item iterator return the QPACK-mapped
  // error EAGERLY — before the caller pulls a single header out of the yielded
  // set. The FSM validates the whole section up front, so the error surfaces even
  // though the driver never drains the `HeaderSet`.
  //
  // Field section: prefix 0x00 0x00 (RIC=0, base=0); 0xd9 = indexed static line
  // for index 25 (`:status 200`); 0x80 = indexed line with the T (static) bit
  // clear, i.e. a dynamic-table reference -> DynamicReference -> QPACK error.
  let fs = [0x00u8, 0x00, 0xd9, 0x80];
  let mut frame = std::vec::Vec::new();
  let mut hdr = [0u8; 16];
  let hn = encode_header(FrameType::Headers, fs.len() as u64, &mut hdr).unwrap();
  frame.extend_from_slice(&hdr[..hn]);
  frame.extend_from_slice(&fs);
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let mut items = s.handle(&frame, &mut scratch);
  // The very first `next()` must be the error — NOT a `Headers` item the caller
  // would then have to drain to discover the fault.
  assert!(matches!(
    items.next(),
    Err(crate::error::H3Error::QpackDecompressionFailed)
  ));
}

#[test]
fn data_before_headers_is_unexpected() {
  let mut scratch = [0u8; 64];
  let mut s = RequestStream::new();
  let data = data_frame(b"");
  let mut items = s.handle(&data, &mut scratch);
  assert!(matches!(
    items.next(),
    Err(crate::error::H3Error::FrameUnexpected)
  ));
}

#[test]
fn second_leading_headers_is_a_second_initial_section() {
  // A second HEADERS section with no intervening DATA is no longer an FSM-level
  // placement error (it is an interim-1xx repeat candidate): the FSM stays in the
  // leading-HEADERS phase and tags it `Initial` again, leaving the
  // "only one final response" decision to the connection/validator (decided by
  // `:status`). Compare the OLD single-stream FSM, which rejected any second
  // HEADERS outright.
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT")]);
  {
    let mut items = s.handle(&req, &mut scratch);
    while items.next().unwrap().is_some() {}
  }
  let second = headers_frame(&[(":status", "200")]);
  let mut items = s.handle(&second, &mut scratch);
  assert!(matches!(
    items.next().unwrap().unwrap(),
    StreamItem::Headers {
      kind: HeadersKind::Initial,
      ..
    }
  ));
}

#[test]
fn settings_on_request_stream_is_unexpected() {
  let mut scratch = [0u8; 64];
  let mut s = RequestStream::new();
  let mut hdr = [0u8; 16];
  let hn = encode_header(FrameType::Settings, 0, &mut hdr).unwrap();
  let mut items = s.handle(&hdr[..hn], &mut scratch);
  assert!(matches!(
    items.next(),
    Err(crate::error::H3Error::FrameUnexpected)
  ));
}

#[test]
fn reserved_frame_on_request_stream_is_unexpected() {
  // An HTTP/2-reserved frame type (0x02, length 0) is forbidden on HTTP/3
  // (RFC 9114 §7.2.8): H3_FRAME_UNEXPECTED, not silently skipped.
  let mut scratch = [0u8; 64];
  let mut s = RequestStream::new();
  let mut items = s.handle(&[0x02, 0x00], &mut scratch);
  assert!(matches!(
    items.next(),
    Err(crate::error::H3Error::FrameUnexpected)
  ));
}

#[test]
fn goaway_frame_on_request_stream_is_unexpected() {
  // GOAWAY (0x07) is a control-stream frame; on the request stream it is
  // misplaced (RFC 9114 §7.2.6): H3_FRAME_UNEXPECTED.
  let mut scratch = [0u8; 64];
  let mut s = RequestStream::new();
  let mut items = s.handle(&[0x07, 0x00], &mut scratch);
  assert!(matches!(
    items.next(),
    Err(crate::error::H3Error::FrameUnexpected)
  ));
}

#[test]
fn push_promise_on_request_stream_is_id_error() {
  // PUSH_PROMISE (0x05) on the request stream carries a push id, but this crate
  // never enables server push (it never sends MAX_PUSH_ID, so the max push id
  // stays 0). The push id was never granted, so this is H3_ID_ERROR (RFC 9114
  // §7.2.5 / §8.1) — distinct from the FrameUnexpected placement errors.
  let mut scratch = [0u8; 64];
  let mut s = RequestStream::new();
  let mut items = s.handle(&[0x05, 0x00], &mut scratch);
  assert!(matches!(items.next(), Err(crate::error::H3Error::IdError)));
}

#[test]
fn unknown_frame_is_skipped() {
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let mut buf = std::vec::Vec::new();
  buf.extend_from_slice(&[0x21, 0x02, 0xaa, 0xbb]); // GREASE type 0x21, len 2, payload
  buf.extend_from_slice(&headers_frame(&[(":method", "CONNECT")]));
  let mut items = s.handle(&buf, &mut scratch);
  match items.next().unwrap().unwrap() {
    StreamItem::Headers {
      headers: mut hs, ..
    } => {
      assert_eq!(hs.next().unwrap().unwrap().name(), ":method")
    }
    _ => panic!("expected Headers after skipping GREASE"),
  }
}

#[test]
fn fin_after_leading_headers_without_complete_signal_is_request_incomplete() {
  // A completed leading HEADERS section alone does NOT make a FIN clean: the FSM stays in
  // `Phase::Headers` until the connection signals the leading message complete
  // (`complete_leading`, fired only on the final response / request, never on an interim
  // 1xx). A FIN here — the shape of `[interim 1xx] FIN`, where no `complete_leading` ran —
  // is `RequestIncomplete`, NOT a clean half-close. (Pre-fix `fin` returned `Ok` for any
  // `headers_seen`, so a `103`-then-FIN read as a clean pre-establishment half-close — the
  // silent forever-deferred half-close of Finding #2. The clean case requires the signal;
  // see `complete_leading_then_fin_is_clean_half_close`.)
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT")]);
  {
    let mut items = s.handle(&req, &mut scratch);
    while items.next().unwrap().is_some() {}
  }
  assert_eq!(
    s.fin(),
    Err(H3Error::RequestIncomplete),
    "a leading HEADERS without complete_leading (only interims seen) is incomplete on FIN"
  );
}

#[test]
fn fin_mid_frame_is_error() {
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT")]);
  {
    let mut items = s.handle(&req[..1], &mut scratch);
    while items.next().unwrap().is_some() {}
  }
  assert_eq!(s.fin(), Err(H3Error::FrameError));
}

#[test]
fn fin_before_headers_is_request_incomplete() {
  // A clean frame-boundary FIN that arrives BEFORE the mandatory CONNECT HEADERS
  // (the FSM never left AwaitingHeaders) is an incomplete request, not a graceful
  // half-close: the field section never arrived (RFC 9114 §8.1).
  let s = RequestStream::new();
  assert_eq!(s.fin(), Err(H3Error::RequestIncomplete));
}

#[test]
fn zero_length_data_frame_yields_one_empty_occurrence() {
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT")]);
  {
    let mut items = s.handle(&req, &mut scratch);
    while items.next().unwrap().is_some() {}
  }
  // A zero-length DATA frame (header only, no payload) is a real DATA occurrence: it
  // yields exactly ONE empty `StreamItem::Data` rather than being silently skipped,
  // so the connection's establishment gate sees every DATA frame. The next call
  // resumes at a clean frame boundary (no stuck `Cur::Data`).
  let empty = data_frame(b"");
  {
    let mut items = s.handle(&empty, &mut scratch);
    match items.next().unwrap() {
      Some(StreamItem::Data(chunk)) => assert!(chunk.is_empty(), "one empty DATA occurrence"),
      other => panic!(
        "expected one empty Data occurrence, got {:?}",
        other.is_some()
      ),
    }
    assert!(
      items.next().unwrap().is_none(),
      "exactly one occurrence, then the boundary"
    );
  }
  // ... and the stream is left at a clean boundary.
  assert!(s.fin().is_ok());
}

#[test]
fn zero_length_then_nonempty_data_yields_both_occurrences() {
  // The empty DATA occurrence must not stall the FSM: a length-0 DATA frame followed by
  // a non-empty one yields the empty occurrence first, then the non-empty chunk — so a
  // connection skipping the empty still reaches the next real frame.
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT")]);
  {
    let mut items = s.handle(&req, &mut scratch);
    while items.next().unwrap().is_some() {}
  }
  let mut buf = std::vec::Vec::new();
  buf.extend_from_slice(&data_frame(b""));
  buf.extend_from_slice(&data_frame(b"tail"));
  let mut chunks: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
  {
    let mut items = s.handle(&buf, &mut scratch);
    while let Some(item) = items.next().unwrap() {
      if let StreamItem::Data(c) = item {
        chunks.push(c.to_vec());
      }
    }
  }
  assert_eq!(
    chunks,
    std::vec![std::vec::Vec::new(), b"tail".to_vec()],
    "an empty occurrence then the non-empty chunk"
  );
  assert!(s.fin().is_ok());
}

#[test]
fn multiple_data_frames_in_one_buffer() {
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT")]);
  {
    let mut items = s.handle(&req, &mut scratch);
    while items.next().unwrap().is_some() {}
  }
  let mut buf = std::vec::Vec::new();
  buf.extend_from_slice(&data_frame(b"aa"));
  buf.extend_from_slice(&data_frame(b"bb"));
  let mut chunks: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
  let mut items = s.handle(&buf, &mut scratch);
  while let Some(item) = items.next().unwrap() {
    if let StreamItem::Data(c) = item {
      chunks.push(c.to_vec());
    }
  }
  assert_eq!(chunks, std::vec![b"aa".to_vec(), b"bb".to_vec()]);
}

#[test]
fn data_frame_split_across_calls() {
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT")]);
  {
    let mut items = s.handle(&req, &mut scratch);
    while items.next().unwrap().is_some() {}
  }
  let data = data_frame(b"hello");
  let mid = data.len() - 2;
  let mut collected = std::vec::Vec::new();
  {
    let mut items = s.handle(&data[..mid], &mut scratch);
    while let Some(item) = items.next().unwrap() {
      if let StreamItem::Data(c) = item {
        collected.extend_from_slice(c);
      }
    }
  }
  {
    let mut items = s.handle(&data[mid..], &mut scratch);
    while let Some(item) = items.next().unwrap() {
      if let StreamItem::Data(c) = item {
        collected.extend_from_slice(c);
      }
    }
  }
  assert_eq!(collected, b"hello");
}

#[test]
fn decodes_huffman_value_through_fsm() {
  // A HEADERS frame whose field section is name-ref :authority + Huffman("www.example.com").
  let fs: [u8; 16] = [
    0x00, 0x00, 0x50, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
  ];
  let mut frame = std::vec::Vec::new();
  let mut hdr = [0u8; 16];
  let hn = crate::frame::encode_header(crate::frame::FrameType::Headers, fs.len() as u64, &mut hdr)
    .unwrap();
  frame.extend_from_slice(&hdr[..hn]);
  frame.extend_from_slice(&fs);
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let mut items = s.handle(&frame, &mut scratch);
  match items.next().unwrap().unwrap() {
    StreamItem::Headers {
      headers: mut hs, ..
    } => {
      let p = hs.next().unwrap().unwrap();
      assert_eq!((p.name(), p.value()), (":authority", "www.example.com"));
    }
    _ => panic!("expected Headers"),
  }
}

// A field section after a DATA frame is a trailers section, tagged Trailers.
#[test]
fn headers_then_data_then_trailers_are_tagged() {
  // HEADERS(0x01) len=3 [0x00,0x00,0xd1 = :method: GET], DATA(0x00) len=2 [b"hi"],
  // HEADERS(0x01) len=3 [trailers field section: indexed static :status not valid
  // for trailers, but the FSM only checks PLACEMENT here, so reuse 0x00,0x00,0xd1].
  let mut s = Stream::new();
  let bytes = [
    0x01, 0x03, 0x00, 0x00, 0xd1, // HEADERS (final, per placement = first)
    0x00, 0x02, b'h', b'i', // DATA
    0x01, 0x03, 0x00, 0x00, 0xd1, // HEADERS after DATA = trailers
  ];
  let mut scratch = [0u8; 256];
  let mut items = s.handle(&bytes, &mut scratch);
  // First item: a header section, placement-kind Initial.
  let first = items.next().expect("ok").expect("some");
  let StreamItem::Headers { kind, .. } = first else {
    panic!("expected Headers, got Data");
  };
  assert_eq!(kind, HeadersKind::Initial);
  // Second item: the DATA chunk.
  assert!(matches!(items.next().expect("ok").expect("some"), StreamItem::Data(b) if b == b"hi"));
  // Third item: a trailers section.
  let third = items.next().expect("ok").expect("some");
  let StreamItem::Headers { kind, .. } = third else {
    panic!("expected trailers Headers");
  };
  assert_eq!(kind, HeadersKind::Trailers);
  assert!(items.next().expect("ok").is_none());
}

// A second non-trailers HEADERS with no intervening DATA is still allowed at the
// FSM level (interim 1xx are repeated HEADERS); the FSM tags both Initial and lets
// the connection/validator decide interim-vs-final by status.
#[test]
fn repeated_initial_headers_before_data_are_allowed() {
  let mut s = Stream::new();
  let bytes = [
    0x01, 0x03, 0x00, 0x00, 0xd1, // HEADERS #1 (interim candidate)
    0x01, 0x03, 0x00, 0x00, 0xd1, // HEADERS #2 (final candidate)
  ];
  let mut scratch = [0u8; 256];
  let mut items = s.handle(&bytes, &mut scratch);
  assert!(matches!(
    items.next().expect("ok").expect("some"),
    StreamItem::Headers {
      kind: HeadersKind::Initial,
      ..
    }
  ));
  assert!(matches!(
    items.next().expect("ok").expect("some"),
    StreamItem::Headers {
      kind: HeadersKind::Initial,
      ..
    }
  ));
  assert!(items.next().expect("ok").is_none());
}

// After the connection signals the leading message complete (`complete_leading`), a
// HEADERS section with NO intervening DATA is the trailing section (bodyless trailers,
// RFC 9114 §4.1) — tagged `Trailers`, not `Initial`. Without the signal the same two
// sections are both `Initial` (see `repeated_initial_headers_before_data_are_allowed`),
// so this pins that the signal is what flips the second to trailers.
#[test]
fn complete_leading_makes_next_headers_bodyless_trailers() {
  let mut s = Stream::new();
  // First feed: the leading HEADERS section (tagged Initial).
  {
    let bytes = [0x01, 0x03, 0x00, 0x00, 0xd1]; // HEADERS (leading)
    let mut scratch = [0u8; 256];
    let mut items = s.handle(&bytes, &mut scratch);
    assert!(matches!(
      items.next().expect("ok").expect("some"),
      StreamItem::Headers {
        kind: HeadersKind::Initial,
        ..
      }
    ));
    assert!(items.next().expect("ok").is_none());
  }
  // The connection signals the leading message complete (request / final response).
  s.complete_leading();
  // Second feed: a HEADERS section with NO DATA in between — now BODYLESS trailers.
  {
    let bytes = [0x01, 0x03, 0x00, 0x00, 0xd1]; // HEADERS (bodyless trailers)
    let mut scratch = [0u8; 256];
    let mut items = s.handle(&bytes, &mut scratch);
    assert!(matches!(
      items.next().expect("ok").expect("some"),
      StreamItem::Headers {
        kind: HeadersKind::Trailers,
        ..
      }
    ));
    assert!(items.next().expect("ok").is_none());
  }
  // A frame-boundary FIN after bodyless trailers is a clean half-close.
  assert!(s.fin().is_ok());
}

// `complete_leading` leaves the FSM in a clean-FIN state even with NO trailers and NO
// DATA: a bodyless final response / request then FIN is a clean half-close (the message
// is complete), not `RequestIncomplete`.
#[test]
fn complete_leading_then_fin_is_clean_half_close() {
  let mut s = Stream::new();
  {
    let bytes = [0x01, 0x03, 0x00, 0x00, 0xd1]; // HEADERS (leading)
    let mut scratch = [0u8; 256];
    let mut items = s.handle(&bytes, &mut scratch);
    let _ = items.next().expect("ok").expect("some");
  }
  s.complete_leading();
  assert!(
    s.fin().is_ok(),
    "a bodyless leading message then FIN is clean"
  );
}

// After `complete_leading`, a DATA frame still begins the body (LeadingDone -> Body), and a
// HEADERS section after that DATA is trailers — the post-leading state funnels into the
// existing body/trailers path identically.
#[test]
fn complete_leading_then_data_then_trailers() {
  let mut s = Stream::new();
  {
    let bytes = [0x01, 0x03, 0x00, 0x00, 0xd1]; // HEADERS (leading)
    let mut scratch = [0u8; 256];
    let _ = s
      .handle(&bytes, &mut scratch)
      .next()
      .expect("ok")
      .expect("some");
  }
  s.complete_leading();
  let bytes = [
    0x00, 0x02, b'h', b'i', // DATA
    0x01, 0x03, 0x00, 0x00, 0xd1, // HEADERS after DATA = trailers
  ];
  let mut scratch = [0u8; 256];
  let mut items = s.handle(&bytes, &mut scratch);
  assert!(matches!(items.next().expect("ok").expect("some"), StreamItem::Data(b) if b == b"hi"));
  assert!(matches!(
    items.next().expect("ok").expect("some"),
    StreamItem::Headers {
      kind: HeadersKind::Trailers,
      ..
    }
  ));
  assert!(items.next().expect("ok").is_none());
}

// A HEADERS after trailers is a frame-placement error (nothing follows trailers).
#[test]
fn data_after_trailers_is_frame_unexpected() {
  let mut s = Stream::new();
  let bytes = [
    0x01, 0x03, 0x00, 0x00, 0xd1, // HEADERS (initial)
    0x00, 0x01, b'x', // DATA
    0x01, 0x03, 0x00, 0x00, 0xd1, // trailers
    0x00, 0x01, b'y', // DATA after trailers — illegal
  ];
  let mut scratch = [0u8; 256];
  let mut items = s.handle(&bytes, &mut scratch);
  let _ = items.next(); // Initial
  let _ = items.next(); // Data
  let _ = items.next(); // Trailers
  // `StreamItem` does not implement `Debug` (its `HeaderSet` holds borrowed Huffman
  // scratch), so match the error rather than `unwrap_err()` (which needs `Ok: Debug`).
  assert!(matches!(items.next(), Err(H3Error::FrameUnexpected)));
}
