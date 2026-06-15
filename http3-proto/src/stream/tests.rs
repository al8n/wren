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
      StreamItem::Headers(mut hs) => {
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
      if let StreamItem::Headers(mut hs) = item {
        assert_eq!(hs.next().unwrap().unwrap().name(), ":method");
        saw = true;
      }
    }
  }
  assert!(saw);
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
fn second_headers_is_unexpected() {
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
    items.next(),
    Err(crate::error::H3Error::FrameUnexpected)
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
fn unknown_frame_is_skipped() {
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let mut buf = std::vec::Vec::new();
  buf.extend_from_slice(&[0x21, 0x02, 0xaa, 0xbb]); // GREASE type 0x21, len 2, payload
  buf.extend_from_slice(&headers_frame(&[(":method", "CONNECT")]));
  let mut items = s.handle(&buf, &mut scratch);
  match items.next().unwrap().unwrap() {
    StreamItem::Headers(mut hs) => assert_eq!(hs.next().unwrap().unwrap().name(), ":method"),
    _ => panic!("expected Headers after skipping GREASE"),
  }
}

#[test]
fn clean_fin_after_frame_ok() {
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT")]);
  {
    let mut items = s.handle(&req, &mut scratch);
    while items.next().unwrap().is_some() {}
  }
  assert!(s.fin().is_ok());
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
  assert!(s.fin().is_err());
}

#[test]
fn zero_length_data_frame_completes_cleanly() {
  let mut scratch = [0u8; 512];
  let mut s = RequestStream::new();
  let req = headers_frame(&[(":method", "CONNECT")]);
  {
    let mut items = s.handle(&req, &mut scratch);
    while items.next().unwrap().is_some() {}
  }
  // A zero-length DATA frame (header only, no payload) must yield NO item ...
  let empty = data_frame(b"");
  {
    let mut items = s.handle(&empty, &mut scratch);
    assert!(items.next().unwrap().is_none());
  }
  // ... and leave the stream at a clean boundary.
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
    StreamItem::Headers(mut hs) => {
      let p = hs.next().unwrap().unwrap();
      assert_eq!((p.name(), p.value()), (":authority", "www.example.com"));
    }
    _ => panic!("expected Headers"),
  }
}
