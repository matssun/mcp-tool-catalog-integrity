<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to MCP Tool Catalog Integrity

Thank you for your interest in MTCI.

## Scope discipline

MTCI has a deliberately narrow boundary (see
[`docs/security-boundary.md`](docs/security-boundary.md) and
[ADR-MTCI-001](docs/adr/adr-mtci-001-scope-and-boundary.md)). Contributions that
pull MTCI toward message signing, authorization, replay protection, tool safety
classification, invocation policy, or host UX are out of scope by design — those
belong to MCP-S Core or to the host, not here. Such changes will be declined even
if otherwise well-implemented.

## Licensing of contributions

By submitting a contribution you agree that it is licensed under the Apache
License, Version 2.0, the same license as the rest of this repository. Add an
`SPDX-License-Identifier: Apache-2.0` header to new source and documentation
files.

## Decisions

Architecturally significant changes should be accompanied by an ADR under
[`docs/adr/`](docs/adr/), following the existing `adr-mtci-NNN-*.md` format.

## Build and test

Run both build paths before opening a pull request:

```sh
cargo test --workspace
bazel test //...
```
