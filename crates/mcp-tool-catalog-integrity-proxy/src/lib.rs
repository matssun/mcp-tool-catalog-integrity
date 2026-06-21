//! MCP Tool Catalog Integrity interposer.
//!
//! A thin layer that sits between an MCP host and an MCP server and watches the
//! tool catalog the server advertises. On each `tools/list` result it observes,
//! it computes catalog drift against a host-supplied [`PinStore`] and applies a
//! [`DriftPolicy`].
//!
//! This crate composes the pure [`mcp_tool_catalog_integrity`] core with an MCP
//! transport. The transport itself is out of scope here — a host wires
//! [`Interposer::observe`] into wherever it receives `tools/list` results. Per
//! ADR-MTCI-001 this performs **no** message signing, authorization, or
//! invocation policy; it only reports descriptor-level catalog integrity.

use mcp_tool_catalog_integrity::{verify, DriftReport, IntegrityError, PinStore, ToolCatalog};
use serde_json::Value;

/// How the interposer reacts when an observation drifts from the pinned baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftPolicy {
    /// Report drift but do not treat it as an error (host decides what to do).
    Report,
    /// Treat any unapproved drift as a hard failure (fail closed).
    FailClosed,
}

impl Default for DriftPolicy {
    fn default() -> Self {
        DriftPolicy::FailClosed
    }
}

/// The outcome of observing a catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// The observed catalog matched the pinned baseline.
    Clean(DriftReport),
    /// The observed catalog drifted; under [`DriftPolicy::Report`] the host is
    /// handed the report to resolve (e.g. surface to the user and re-pin).
    Drift(DriftReport),
}

/// Errors the interposer can surface.
#[derive(Debug, thiserror::Error)]
pub enum InterposerError {
    /// The `tools/list` payload was not a recognizable catalog.
    #[error("could not parse a tool catalog from the tools/list result")]
    MalformedCatalog,

    /// The catalog could not be verified (e.g. a descriptor lacked a `name`).
    #[error(transparent)]
    Integrity(#[from] IntegrityError),

    /// Under [`DriftPolicy::FailClosed`], the observed catalog drifted from the
    /// pinned baseline.
    #[error("tool catalog drift detected: {} added, {} removed, {} mutated",
        .0.added.len(), .0.removed.len(), .0.mutated.len())]
    Drift(DriftReport),
}

/// Watches the tool catalog a server advertises, holding the host's pin store.
pub struct Interposer<P: PinStore> {
    pins: P,
    policy: DriftPolicy,
}

impl<P: PinStore> Interposer<P> {
    /// Build an interposer over a pin store with the given policy.
    pub fn new(pins: P, policy: DriftPolicy) -> Self {
        Self { pins, policy }
    }

    /// Observe a `tools/list` result. Accepts either the full result object
    /// (`{"tools": [...]}`) or a bare descriptor array.
    ///
    /// Under [`DriftPolicy::FailClosed`], drift returns
    /// [`InterposerError::Drift`]; under [`DriftPolicy::Report`], drift returns
    /// `Ok(Observation::Drift(..))` for the host to resolve.
    pub fn observe(&self, tools_list_result: &Value) -> Result<Observation, InterposerError> {
        let catalog = ToolCatalog::from_tools_list(tools_list_result)
            .ok_or(InterposerError::MalformedCatalog)?;
        let report = verify(&catalog, &self.pins)?;

        if !report.has_drift() {
            return Ok(Observation::Clean(report));
        }
        match self.policy {
            DriftPolicy::Report => Ok(Observation::Drift(report)),
            DriftPolicy::FailClosed => Err(InterposerError::Drift(report)),
        }
    }

    /// Borrow the underlying pin store (e.g. to re-pin after approving drift via
    /// [`mcp_tool_catalog_integrity::repin`]).
    pub fn pins_mut(&mut self) -> &mut P {
        &mut self.pins
    }

    /// Consume the interposer and return its pin store.
    pub fn into_pins(self) -> P {
        self.pins
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_tool_catalog_integrity::{repin, InMemoryPinStore, ToolCatalog};
    use serde_json::json;

    fn tools_list(tools: Value) -> Value {
        json!({ "tools": tools })
    }

    #[test]
    fn clean_after_repin() {
        let result = tools_list(json!([{"name": "echo", "description": "v1"}]));
        let mut pins = InMemoryPinStore::new();
        let catalog = ToolCatalog::from_tools_list(&result).unwrap();
        repin(&catalog, &mut pins).unwrap();

        let interposer = Interposer::new(pins, DriftPolicy::FailClosed);
        match interposer.observe(&result).unwrap() {
            Observation::Clean(_) => {}
            other => panic!("expected clean, got {other:?}"),
        }
    }

    #[test]
    fn fail_closed_on_mutation() {
        let baseline = tools_list(json!([{"name": "echo", "description": "v1"}]));
        let mut pins = InMemoryPinStore::new();
        repin(&ToolCatalog::from_tools_list(&baseline).unwrap(), &mut pins).unwrap();

        let interposer = Interposer::new(pins, DriftPolicy::FailClosed);
        let mutated = tools_list(json!([{"name": "echo", "description": "v2"}]));
        match interposer.observe(&mutated) {
            Err(InterposerError::Drift(report)) => assert_eq!(report.mutated, vec!["echo"]),
            other => panic!("expected drift error, got {other:?}"),
        }
    }

    #[test]
    fn report_policy_returns_drift() {
        let interposer = Interposer::new(InMemoryPinStore::new(), DriftPolicy::Report);
        let result = tools_list(json!([{"name": "echo", "description": "v1"}]));
        match interposer.observe(&result).unwrap() {
            Observation::Drift(report) => assert_eq!(report.added, vec!["echo"]),
            other => panic!("expected drift observation, got {other:?}"),
        }
    }
}
