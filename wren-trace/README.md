<div align="center">
<h1>wren-trace</h1>
</div>
<div align="center">

Zero-cost tracing shim for the wren WebSocket family.

</div>

With the `tracing` feature the macros forward to the [`tracing`] crate;
without it they compile to nothing while still type-checking their
arguments, so instrumented code carries no cost and no `cfg` noise.

[`tracing`]: https://docs.rs/tracing

#### License

`wren-trace` is under the terms of both the MIT license and the Apache
License (Version 2.0).

See [LICENSE-APACHE](../LICENSE-APACHE), [LICENSE-MIT](../LICENSE-MIT) for
details.

Copyright (c) 2026 Al Liu.
