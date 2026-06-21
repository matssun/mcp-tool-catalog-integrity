//! MCP Tool Catalog Integrity (MTCI) — pure, dependency-light verification crate
//! for the MCP Tool Catalog Integrity Profile.
//!
//! Scope and invariants are fixed by ADR-MTCI-001 and
//! `docs/security-boundary.md`: this crate protects the integrity of MCP tool
//! catalog **descriptors** only. It does **not** define MCP message signing,
//! authorization, replay protection, host UX, tool safety classification, or
//! tool invocation policy.
//!
//! It is also pure: no networking, async runtime, or filesystem access. A host
//! supplies its own persistence by implementing [`pin_store::PinStore`].
//!
//! Pipeline:
//! 1. [`manifest`] — the tool descriptor / catalog data model.
//! 2. [`descriptor_hash`] — canonicalize a descriptor and hash it; hash a catalog.
//! 3. [`pin_store`] — the host-side record of accepted descriptor hashes (TOFU).
//! 4. [`verifier`] — compare an observed catalog against the pins and report drift.

pub mod canonical;
pub mod descriptor_hash;
pub mod manifest;
pub mod pin_store;
pub mod verifier;

// Re-export the public surface at the crate root for ergonomic use.
pub use descriptor_hash::{catalog_hash, descriptor_hash, hash_id};
pub use manifest::{ToolCatalog, ToolDescriptor};
pub use pin_store::{InMemoryPinStore, PinStore};
pub use verifier::{repin, verify, DriftReport};

/// The crate's frozen, fail-closed error taxonomy.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum IntegrityError {
    /// A descriptor (or sub-value) could not be reduced to its canonical form.
    /// Canonicalization is fail-closed: it never falls back to a best-effort
    /// serialization.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),

    /// A tool descriptor lacked a string `name`, so it cannot be identified or
    /// pinned.
    #[error("tool descriptor is missing a string `name`")]
    MissingName,
}
