<!-- SPDX-License-Identifier: Apache-2.0 -->

# Examples

Runnable usage examples for MTCI.

Cargo binds `examples/*.rs` to a package, so per-crate examples live under each
crate (e.g. `crates/mcp-tool-catalog-integrity/examples/`). This directory holds
workspace-level walkthroughs and any non-Rust examples (catalog fixtures, host
integration sketches).

## Quick start (in code)

```rust
use mcp_tool_catalog_integrity::{repin, verify, InMemoryPinStore, ToolCatalog};
use serde_json::json;

let result = json!({ "tools": [{ "name": "echo", "description": "Echo input" }] });
let catalog = ToolCatalog::from_tools_list(&result).unwrap();

// Trust-on-first-use: pin the first observation.
let mut pins = InMemoryPinStore::new();
repin(&catalog, &mut pins).unwrap();

// Later: verify a fresh observation against the baseline.
let report = verify(&catalog, &pins).unwrap();
assert!(!report.has_drift());
```
