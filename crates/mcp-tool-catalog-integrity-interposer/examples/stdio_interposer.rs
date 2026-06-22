//! Minimal, synchronous example of a host wiring the interposer into a stdio
//! loop.
//!
//! It reads a complete `tools/list` result JSON from stdin, observes it with a
//! [`DriftPolicy::Report`] interposer over an in-memory pin store, and prints the
//! resulting drift report. On a first sighting (empty pin store) every tool is
//! reported as "added".
//!
//! A production host instead backs the interposer with a durable
//! `FilePinStore` (feature `file_pin_store`) so TOFU pins survive restart, and
//! re-pins via `repin_bytes` / `repin_complete` after the operator approves
//! drift. For paginated `tools/list` it drives a `CatalogAccumulator` over the
//! pages instead of a single `observe_bytes` call.
//!
//! Run with:
//!   echo '{"tools":[{"name":"echo","description":"v1"}]}' \
//!     | cargo run --example stdio_interposer

use std::io::Read;

use mcp_tool_catalog_integrity::InMemoryPinStore;
use mcp_tool_catalog_integrity_interposer::{
    DriftPolicy, Interposer, Observation,
};

fn main() {
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("failed to read stdin: {e}");
        std::process::exit(1);
    }

    let interposer = Interposer::new(InMemoryPinStore::new(), DriftPolicy::Report);

    match interposer.observe_bytes(&input) {
        Ok(Observation::Clean(report)) => {
            println!("clean: catalog matches pinned baseline");
            println!("  catalog hash: {}", report.observed_catalog_hash);
        }
        Ok(Observation::Drift(report)) => {
            // First sighting => all tools land in `added`.
            println!("drift detected:");
            println!("  added:     {:?}", report.added);
            println!("  removed:   {:?}", report.removed);
            println!("  mutated:   {:?}", report.mutated);
            println!("  unchanged: {:?}", report.unchanged);
            println!("  catalog hash: {}", report.observed_catalog_hash);
            // A production host would now surface this to the operator and, on
            // approval, call `interposer.repin_bytes(&input)` to accept it.
        }
        Err(e) => {
            eprintln!("observation failed: {e}");
            std::process::exit(1);
        }
    }
}
