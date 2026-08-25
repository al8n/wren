<div align="center">
<h1>http-semantics</h1>
</div>
<div align="center">

Version-independent HTTP semantics — the rules RFC 9110 states once and every
wire format inherits: field grammar, media types, dates.

`no_std`, no-alloc capable, panic-free.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/websockit-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/websockit/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-http--semantics-66c2a5?style=for-the-badge&labelColor=555555&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMiA0MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMiAzOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMiA0MS40di0uNmwxMDIgMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/http-semantics?style=for-the-badge&logo=rust" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge" height="22">

</div>

## What it is

`http-semantics` holds the version-independent half of HTTP: the rules RFC 9110
states once and every wire format inherits.

This crate depends on no protocol crate, which is the whole reason it exists:
`http1-proto`, `http3-proto` and anything later reach the same rules without
reaching through each other. A rule that is version-independent only until you
import a version-specific crate to reach it is not version-independent, and the
second wire format to need it would be made to depend on the first.

### What belongs here

This section IS the crate root's documentation: `src/lib.rs` pulls this file in
with `#![doc = include_str!("../README.md")]`, which is what every library crate
in this workspace does. There is one copy of the membership rule, so an edit
here is an edit to what `docs.rs` shows, and the two cannot drift apart.

An item belongs here when BOTH hold:

- its rule comes from RFC 9110, or from a spec RFC 9110 builds on (RFC 3986
  for URI syntax, RFC 5234 for ABNF), rather than from any one version's wire
  format; and
- its answer is a function of the input bytes, or a derivation the RFC itself
  settles, with every other input arriving as an ARGUMENT rather than as
  state this crate holds.

An item satisfying neither is a defect here, not a judgement call.

The second clause is where the boundary actually falls. Computing an
`Accept` weight belongs here because RFC 9110 §12.5.1 and §12.4.2 settle that
derivation between them; choosing which representation to send does not,
because only the caller knows which representations exist. Deciding whether a
range is satisfiable belongs here — §14.1.2 settles it and the length is an
argument; deciding whether credentials are valid does not, because RFC 9110
settles their syntax and nothing about their verification.

## Feature flags

| Feature | Default | Enables |
|---------|:-------:|---------|
| `std` | ✅ | `thiserror/std` |
| `alloc` | | heap tier without `std` |
| `no-atomic` | | heap tier without `std` and without native atomic CAS |

`thiserror` is this crate's one dependency and `std` is the only flag that
reaches it; `alloc` and `no-atomic` pull nothing and carry tier *semantics*
alone — the same tiers `http1-proto` and `websocket-proto` publish, so a caller
forwards one flag rather than translating between two vocabularies.
`no-atomic` names the heap tier for cores with **no native atomic CAS**
(Cortex-M0+ / `thumbv6m`, e.g. the RP2040) — it stands in for `alloc` on such a
core rather than accompanying it.

The bare `no_std`, no-`alloc` tier compiles with `--no-default-features`.

## MSRV

Rust 1.91.0. The MSRV may be raised in a minor release.

## License

`http-semantics` is under the terms of both the MIT license and the Apache
License (Version 2.0).

See [LICENSE-APACHE](../LICENSE-APACHE), [LICENSE-MIT](../LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.

[Github-url]: https://github.com/al8n/websockit/
[CI-url]: https://github.com/al8n/websockit/actions/workflows/ci.yml
[doc-url]: https://docs.rs/http-semantics
[crates-url]: https://crates.io/crates/http-semantics
