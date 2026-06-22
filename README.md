<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP Tool Catalog Integrity Profile

**MCP Tool Catalog Integrity** (MTCI) is an optional, third-party integrity
profile for the Model Context Protocol (MCP). It protects the integrity of the
**tool catalog** an MCP server advertises — the set of tool descriptors a client
discovers via `tools/list` — so that a host can detect silent, unauthorized, or
in-flight changes to those descriptors.

## Boundary

> This project defines an optional **MCP Tool Catalog Integrity Profile**. It is
> separate from MCP-S Core. It protects the integrity of MCP tool catalog
> descriptors and can compose with MCP-S, but it does **not** define MCP message
> signing, authorization, replay protection, host UX, tool safety classification,
> or tool invocation policy.

See [`docs/security-boundary.md`](docs/security-boundary.md) for the full,
signed boundary statement and [ADR-MTCI-001](docs/adr/adr-mtci-001-scope-and-boundary.md)
for the scope decision.

## What it does

- Defines a **canonical descriptor hash** over each tool descriptor and over the
  catalog as a whole, stable across JSON serialization differences.
- Maintains a **pin store**: the set of descriptor hashes a host has previously
  seen and accepted (trust-on-first-use, with explicit re-pin on change).
- Provides a **verifier** that compares a freshly observed catalog against the
  pinned baseline and reports added, removed, and **mutated** descriptors —
  fail-closed on any drift the host has not approved.

## What it does not do

MTCI is **not**:

- a message-signing or transport-security profile (that is MCP-S Core's concern);
- an authorization, delegation, or replay-protection mechanism;
- a tool *safety* classifier or an invocation/execution policy engine;
- a host UX specification.

It composes with — but does not replace or depend on — MCP-S.

## Repository layout

```text
README.md                  This file.
LICENSE                    Apache-2.0.
NOTICE.md                  Required Apache-2.0 attributions.
SECURITY.md                Vulnerability-reporting process.
THIRD_PARTY.md             Third-party-component policy.
CONTRIBUTING.md            Contribution + licensing-of-contributions terms.
CHANGELOG.md               Release notes (Keep a Changelog format).
Cargo.toml                 Workspace manifest.
MODULE.bazel               Bazel module definition.

crates/mcp-tool-catalog-integrity/             Pure verification crate (no networking/async/fs).
crates/mcp-tool-catalog-integrity-interposer/  Pure in-process catalog-integrity interposer (no transport/process/async).

docs/security-boundary.md  What MTCI protects (and what it explicitly does not).
docs/adr/                  Architecture decision records (ADR-MTCI-NNN).
docs/spec/                 The Tool Catalog Integrity Profile specification.
tests/                     Workspace-level integration tests.
examples/                  Usage examples.
```

## Build and test

The workspace builds with either Cargo or Bazel. Cargo is the public-facing
default; Bazel is the hermetic build path, and both `Cargo.toml` and
`BUILD.bazel` files are committed for every crate.

### Cargo

```sh
cargo build --workspace
cargo test --workspace
```

### Bazel

```sh
bazel test //...
```

## License

Unless otherwise stated, all files in this repository are licensed under the
Apache License, Version 2.0. See [`LICENSE`](LICENSE) and [`NOTICE.md`](NOTICE.md).

## Disclaimer

MTCI is an independent, experimental proposal. It is not part of the official MCP
specification and is not endorsed by the MCP project, Anthropic, or any MCP
maintainer unless explicitly accepted through the relevant public governance
process.
