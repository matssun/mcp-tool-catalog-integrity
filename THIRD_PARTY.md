<!-- SPDX-License-Identifier: Apache-2.0 -->

# Third-Party Dependencies

This document records the dependency-license policy for MTCI.

## Policy

MTCI should use dependencies that are compatible with Apache-2.0 distribution and
with the goal of future MCP ecosystem adoption. Security-sensitive dependencies
should be pinned through the repository's normal dependency-locking mechanism
(`Cargo.lock`) and screened by `deny.toml` in CI.

## Current inventory

Fill this table from the repository's lockfile before public release.

| Dependency | Purpose | License | Runtime / Dev | Notes |
|---|---|---:|---:|---|
| serde / serde_json | Descriptor (de)serialization | TBD | Runtime | Verify from package metadata. |
| sha2 | Descriptor hashing (SHA-256) | TBD | Runtime | Verify from package metadata. |
| base64 | Hash-identifier encoding | TBD | Runtime | Verify from package metadata. |
| thiserror | Error taxonomy | TBD | Runtime | Verify from package metadata. |
| hex | Hash rendering | TBD | Runtime | Verify from package metadata. |
| proptest | Canonicalization/hash invariant fuzzing | TBD | Dev/Test | Verify from package metadata. |

## Release requirement

Before public release, replace `TBD` values with verified license information
from package metadata. If a dependency has a restrictive or unclear license,
resolve it before proposing MTCI upstream.
