use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http3_proto::qpack::static_table::{find_name, find_name_value};

// `PHF_NAME_VALUE` / `PHF_NAME`, generated from the canonical static-table data
// in `xtask/src/qpack_data.rs` by `cargo run -p xtask -- qpack-codegen` (kept in
// sync via `--check`), so the phf baseline can never drift from the crate's
// `match` lookup it is benchmarked against.
include!("generated_static_lookup.rs");

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
