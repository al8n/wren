use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http3_proto::qpack::static_table::{find_name, find_name_value};
use phf::phf_map;

const CASES: &[(&str, &str)] = &[
  (":method", "CONNECT"),
  (":protocol", "websocket"),
  (":scheme", "https"),
  (":path", "/"),
  (":authority", "example.com"),
  ("content-type", "application/json"),
  ("content-type", "application/grpc"),
  ("cache-control", "no-store"),
  ("cache-control", "private"),
  (":status", "200"),
  (":status", "418"),
  ("x-frame-options", "sameorigin"),
  ("user-agent", "websockit-bench"),
  ("x-unknown-header", "value"),
];

static PHF_NAME_VALUE: phf::Map<(&'static str, &'static str), usize> = phf_map! {
  (":authority", "") => 0usize,
  (":path", "/") => 1usize,
  ("age", "0") => 2usize,
  ("content-disposition", "") => 3usize,
  ("content-length", "0") => 4usize,
  ("cookie", "") => 5usize,
  ("date", "") => 6usize,
  ("etag", "") => 7usize,
  ("if-modified-since", "") => 8usize,
  ("if-none-match", "") => 9usize,
  ("last-modified", "") => 10usize,
  ("link", "") => 11usize,
  ("location", "") => 12usize,
  ("referer", "") => 13usize,
  ("set-cookie", "") => 14usize,
  (":method", "CONNECT") => 15usize,
  (":method", "DELETE") => 16usize,
  (":method", "GET") => 17usize,
  (":method", "HEAD") => 18usize,
  (":method", "OPTIONS") => 19usize,
  (":method", "POST") => 20usize,
  (":method", "PUT") => 21usize,
  (":scheme", "http") => 22usize,
  (":scheme", "https") => 23usize,
  (":status", "103") => 24usize,
  (":status", "200") => 25usize,
  (":status", "304") => 26usize,
  (":status", "404") => 27usize,
  (":status", "503") => 28usize,
  ("accept", "*/*") => 29usize,
  ("accept", "application/dns-message") => 30usize,
  ("accept-encoding", "gzip, deflate, br") => 31usize,
  ("accept-ranges", "bytes") => 32usize,
  ("access-control-allow-headers", "cache-control") => 33usize,
  ("access-control-allow-headers", "content-type") => 34usize,
  ("access-control-allow-origin", "*") => 35usize,
  ("cache-control", "max-age=0") => 36usize,
  ("cache-control", "max-age=2592000") => 37usize,
  ("cache-control", "max-age=604800") => 38usize,
  ("cache-control", "no-cache") => 39usize,
  ("cache-control", "no-store") => 40usize,
  ("cache-control", "public, max-age=31536000") => 41usize,
  ("content-encoding", "br") => 42usize,
  ("content-encoding", "gzip") => 43usize,
  ("content-type", "application/dns-message") => 44usize,
  ("content-type", "application/javascript") => 45usize,
  ("content-type", "application/json") => 46usize,
  ("content-type", "application/x-www-form-urlencoded") => 47usize,
  ("content-type", "image/gif") => 48usize,
  ("content-type", "image/jpeg") => 49usize,
  ("content-type", "image/png") => 50usize,
  ("content-type", "text/css") => 51usize,
  ("content-type", "text/html; charset=utf-8") => 52usize,
  ("content-type", "text/plain") => 53usize,
  ("content-type", "text/plain;charset=utf-8") => 54usize,
  ("range", "bytes=0-") => 55usize,
  ("strict-transport-security", "max-age=31536000") => 56usize,
  ("strict-transport-security", "max-age=31536000; includesubdomains") => 57usize,
  ("strict-transport-security", "max-age=31536000; includesubdomains; preload") => 58usize,
  ("vary", "accept-encoding") => 59usize,
  ("vary", "origin") => 60usize,
  ("x-content-type-options", "nosniff") => 61usize,
  ("x-xss-protection", "1; mode=block") => 62usize,
  (":status", "100") => 63usize,
  (":status", "204") => 64usize,
  (":status", "206") => 65usize,
  (":status", "302") => 66usize,
  (":status", "400") => 67usize,
  (":status", "403") => 68usize,
  (":status", "421") => 69usize,
  (":status", "425") => 70usize,
  (":status", "500") => 71usize,
  ("accept-language", "") => 72usize,
  ("access-control-allow-credentials", "FALSE") => 73usize,
  ("access-control-allow-credentials", "TRUE") => 74usize,
  ("access-control-allow-headers", "*") => 75usize,
  ("access-control-allow-methods", "get") => 76usize,
  ("access-control-allow-methods", "get, post, options") => 77usize,
  ("access-control-allow-methods", "options") => 78usize,
  ("access-control-expose-headers", "content-length") => 79usize,
  ("access-control-request-headers", "content-type") => 80usize,
  ("access-control-request-method", "get") => 81usize,
  ("access-control-request-method", "post") => 82usize,
  ("alt-svc", "clear") => 83usize,
  ("authorization", "") => 84usize,
  ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'") => 85usize,
  ("early-data", "1") => 86usize,
  ("expect-ct", "") => 87usize,
  ("forwarded", "") => 88usize,
  ("if-range", "") => 89usize,
  ("origin", "") => 90usize,
  ("purpose", "prefetch") => 91usize,
  ("server", "") => 92usize,
  ("timing-allow-origin", "*") => 93usize,
  ("upgrade-insecure-requests", "1") => 94usize,
  ("user-agent", "") => 95usize,
  ("x-forwarded-for", "") => 96usize,
  ("x-frame-options", "deny") => 97usize,
  ("x-frame-options", "sameorigin") => 98usize,
};

static PHF_NAME: phf::Map<&'static str, usize> = phf_map! {
  ":authority" => 0usize,
  ":path" => 1usize,
  "age" => 2usize,
  "content-disposition" => 3usize,
  "content-length" => 4usize,
  "cookie" => 5usize,
  "date" => 6usize,
  "etag" => 7usize,
  "if-modified-since" => 8usize,
  "if-none-match" => 9usize,
  "last-modified" => 10usize,
  "link" => 11usize,
  "location" => 12usize,
  "referer" => 13usize,
  "set-cookie" => 14usize,
  ":method" => 15usize,
  ":scheme" => 22usize,
  ":status" => 24usize,
  "accept" => 29usize,
  "accept-encoding" => 31usize,
  "accept-ranges" => 32usize,
  "access-control-allow-headers" => 33usize,
  "access-control-allow-origin" => 35usize,
  "cache-control" => 36usize,
  "content-encoding" => 42usize,
  "content-type" => 44usize,
  "range" => 55usize,
  "strict-transport-security" => 56usize,
  "vary" => 59usize,
  "x-content-type-options" => 61usize,
  "x-xss-protection" => 62usize,
  "accept-language" => 72usize,
  "access-control-allow-credentials" => 73usize,
  "access-control-allow-methods" => 76usize,
  "access-control-expose-headers" => 79usize,
  "access-control-request-headers" => 80usize,
  "access-control-request-method" => 81usize,
  "alt-svc" => 83usize,
  "authorization" => 84usize,
  "content-security-policy" => 85usize,
  "early-data" => 86usize,
  "expect-ct" => 87usize,
  "forwarded" => 88usize,
  "if-range" => 89usize,
  "origin" => 90usize,
  "purpose" => 91usize,
  "server" => 92usize,
  "timing-allow-origin" => 93usize,
  "upgrade-insecure-requests" => 94usize,
  "user-agent" => 95usize,
  "x-forwarded-for" => 96usize,
  "x-frame-options" => 97usize,
};

fn bench_static_lookup(c: &mut Criterion) {
  let mut group = c.benchmark_group("qpack_static_lookup");
  group.throughput(Throughput::Elements(CASES.len() as u64));
  group.bench_function("generated_exact", |b| b.iter(generated_exact));
  group.bench_function("phf_exact", |b| b.iter(phf_exact));
  group.bench_function("generated_encoder_choice", |b| {
    b.iter(generated_encoder_choice)
  });
  group.bench_function("phf_encoder_choice", |b| b.iter(phf_encoder_choice));
  group.finish();
}

fn generated_exact() -> usize {
  let mut checksum = 0usize;
  for &(name, value) in CASES {
    checksum = checksum
      .wrapping_add(find_name_value(black_box(name), black_box(value)).unwrap_or(usize::MAX));
  }
  black_box(checksum)
}

fn phf_exact() -> usize {
  let mut checksum = 0usize;
  for &(name, value) in CASES {
    checksum = checksum.wrapping_add(
      PHF_NAME_VALUE
        .get(&(black_box(name), black_box(value)))
        .copied()
        .unwrap_or(usize::MAX),
    );
  }
  black_box(checksum)
}

fn generated_encoder_choice() -> usize {
  let mut checksum = 0usize;
  for &(name, value) in CASES {
    let exact = find_name_value(black_box(name), black_box(value));
    let selected = exact.or_else(|| find_name(black_box(name)));
    checksum = checksum.wrapping_add(selected.unwrap_or(usize::MAX));
  }
  black_box(checksum)
}

fn phf_encoder_choice() -> usize {
  let mut checksum = 0usize;
  for &(name, value) in CASES {
    let exact = PHF_NAME_VALUE
      .get(&(black_box(name), black_box(value)))
      .copied();
    let selected = exact.or_else(|| PHF_NAME.get(black_box(name)).copied());
    checksum = checksum.wrapping_add(selected.unwrap_or(usize::MAX));
  }
  black_box(checksum)
}

criterion_group!(benches, bench_static_lookup);
criterion_main!(benches);
