<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tests

Cross-crate and workspace-level integration tests.

Per-crate unit tests live alongside their source under each crate's `src/`
(`#[cfg(test)]` modules) and per-crate integration tests under each crate's own
`tests/` directory. This top-level directory is reserved for tests that exercise
the core crate and the interposer together, and for committed catalog fixtures /
conformance vectors shared across crates.

Run everything with:

```sh
cargo test --workspace
# or
bazel test //...
```
