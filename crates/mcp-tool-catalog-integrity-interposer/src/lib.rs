//! MCP Tool Catalog Integrity interposer.
//!
//! A thin layer that sits between an MCP host and an MCP server and watches the
//! tool catalog the server advertises. On each `tools/list` result it observes,
//! it computes catalog drift against a host-supplied [`PinStore`] and applies a
//! [`DriftPolicy`].
//!
//! This crate composes the pure [`mcp_tool_catalog_integrity`] core with an MCP
//! transport. The transport itself is left to the host — it wires
//! [`Interposer::observe`] (or [`Interposer::observe_bytes`]) into wherever it
//! receives `tools/list` results. Per ADR-MTCI-001 this performs **no** message
//! signing, authorization, or invocation policy; it only reports
//! descriptor-level catalog integrity.
//!
//! # Raw-bytes ingestion
//! [`Interposer::observe_bytes`] / [`Interposer::repin_bytes`] validate the raw
//! wire bytes with the full RFC 8785 parser before deserializing, so duplicate
//! object member names and other JCS-domain violations are rejected **at the
//! wire boundary** — a `serde_json::Value`-only path would silently keep the
//! last duplicate. Prefer the `*_bytes` methods when the original bytes are
//! available.
//!
//! # Pagination
//! MCP `tools/list` is paginated via `nextCursor`; drift must be judged over the
//! **complete** catalog, not a single page. [`CatalogAccumulator`] makes that
//! pagination state explicit: the host drives the page fetch loop, feeding each
//! page to [`CatalogAccumulator::observe_page_bytes`] (which returns the page's
//! `nextCursor`) and calling [`CatalogAccumulator::finish`] once the cursor is
//! exhausted. The [`Interposer`] never hides pagination.
//!
//! # `tools/list_changed`
//! On an MCP `notifications/tools/list_changed`, the host re-fetches `tools/list`
//! and re-observes — either via [`Interposer::observe_bytes`] for a single-page
//! catalog, or via a fresh [`CatalogAccumulator`] for a paginated one. The
//! interposer is stateless per observation; the host drives **when** to
//! re-observe. MTCI does not subscribe to or parse notifications itself.

use mcp_tool_catalog_integrity::{
    repin, verify, DriftReport, IntegrityError, PinStore, ToolCatalog,
};
use serde_json::Value;

#[cfg(feature = "file_pin_store")]
pub mod file_pin_store;

#[cfg(feature = "file_pin_store")]
pub use file_pin_store::FilePinStore;

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
        self.apply_policy(report)
    }

    /// Observe a `tools/list` result from its raw wire bytes.
    ///
    /// The bytes are validated with the full RFC 8785 parser first, so duplicate
    /// object member names and other JCS-domain violations are rejected at the
    /// wire boundary (surfacing as [`InterposerError::Integrity`]) before any
    /// `serde_json::Value` is built. Hashing the resulting value is byte-identical
    /// to hashing the raw bytes (the core proves this via
    /// `json_value_helper_matches_raw_path_for_valid_float_input`), so the drift
    /// verdict is the same as [`observe`](Self::observe) — but with the dup-key
    /// gap closed.
    pub fn observe_bytes(
        &self,
        tools_list_result: &[u8],
    ) -> Result<Observation, InterposerError> {
        let v = Self::parse_wire(tools_list_result)?;
        self.observe(&v)
    }

    /// Accept a `tools/list` result (from raw wire bytes) as the new pinned
    /// baseline, validating the bytes with the full RFC 8785 parser first.
    pub fn repin_bytes(&mut self, tools_list_result: &[u8]) -> Result<(), InterposerError> {
        let v = Self::parse_wire(tools_list_result)?;
        let catalog =
            ToolCatalog::from_tools_list(&v).ok_or(InterposerError::MalformedCatalog)?;
        repin(&catalog, &mut self.pins)?;
        Ok(())
    }

    /// Accept an already-assembled (e.g. paginated) catalog as the new pinned
    /// baseline. The host obtains the complete catalog from
    /// [`CatalogAccumulator::catalog`] before calling
    /// [`CatalogAccumulator::finish`], then re-pins here once the immutable
    /// borrow has ended and after approving the reported drift.
    pub fn repin_complete(&mut self, catalog: &ToolCatalog) -> Result<(), InterposerError> {
        repin(catalog, &mut self.pins)?;
        Ok(())
    }

    /// Validate raw wire bytes with the full RFC 8785 parser (rejecting duplicate
    /// keys and JCS-domain violations at the boundary), then deserialize to a
    /// [`Value`].
    fn parse_wire(bytes: &[u8]) -> Result<Value, InterposerError> {
        mcp_tool_catalog_integrity::canonical::parse(bytes)?;
        serde_json::from_slice(bytes).map_err(|_| InterposerError::MalformedCatalog)
    }

    /// Apply the configured [`DriftPolicy`] to a [`DriftReport`], turning it into
    /// an [`Observation`] (or, under [`DriftPolicy::FailClosed`], an error).
    fn apply_policy(&self, report: DriftReport) -> Result<Observation, InterposerError> {
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

/// Explicit pagination state for assembling a complete `tools/list` catalog
/// across `nextCursor`-paginated pages before judging drift.
///
/// MCP `tools/list` may span multiple pages; drift must be judged over the
/// **union** of every page, never a single page. The host drives the fetch loop:
/// for each page it calls [`observe_page_bytes`](Self::observe_page_bytes) (or
/// [`observe_page`](Self::observe_page)), which appends that page's descriptors
/// and returns the page's `nextCursor`; when the cursor is exhausted the host
/// calls [`finish`](Self::finish) to verify the assembled catalog.
///
/// The accumulator borrows the [`Interposer`] immutably, so re-pinning after
/// approving drift is done by the host **after** `finish` returns (the borrow
/// then ends) via [`Interposer::repin_complete`], using a catalog cloned via
/// [`catalog`](Self::catalog) before `finish`.
pub struct CatalogAccumulator<'a, P: PinStore> {
    interposer: &'a Interposer<P>,
    descriptors: Vec<Value>,
}

impl<'a, P: PinStore> CatalogAccumulator<'a, P> {
    /// Start accumulating pages against `interposer`'s pins and policy.
    pub fn new(interposer: &'a Interposer<P>) -> Self {
        Self {
            interposer,
            descriptors: Vec::new(),
        }
    }

    /// Ingest one `tools/list` page from raw wire bytes (validated by the full
    /// RFC 8785 parser, rejecting duplicate keys at the boundary), append its
    /// descriptors, and return the page's `nextCursor` if present.
    pub fn observe_page_bytes(
        &mut self,
        page: &[u8],
    ) -> Result<Option<String>, InterposerError> {
        let v = Interposer::<P>::parse_wire(page)?;
        self.observe_page(&v)
    }

    /// Ingest one `tools/list` page from an already-parsed [`Value`] (no raw
    /// dup-key check on this path), append its descriptors, and return the page's
    /// `nextCursor` if present.
    ///
    /// Accepts either the full page object (`{"tools": [...], "nextCursor": ..}`)
    /// or a bare descriptor array (`[...]`, which carries no cursor).
    pub fn observe_page(&mut self, page: &Value) -> Result<Option<String>, InterposerError> {
        let tools = page
            .get("tools")
            .and_then(Value::as_array)
            .or_else(|| page.as_array())
            .ok_or(InterposerError::MalformedCatalog)?;
        self.descriptors.extend(tools.iter().cloned());
        let next_cursor = page
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(next_cursor)
    }

    /// The complete catalog assembled so far (clone) — capture this before
    /// [`finish`](Self::finish) to re-pin via [`Interposer::repin_complete`]
    /// after approving drift.
    pub fn catalog(&self) -> ToolCatalog {
        ToolCatalog::from_values(self.descriptors.clone())
    }

    /// Verify the **complete** assembled catalog against the interposer's pins
    /// and apply its policy.
    pub fn finish(self) -> Result<Observation, InterposerError> {
        let catalog = ToolCatalog::from_values(self.descriptors);
        let report = verify(&catalog, &self.interposer.pins)?;
        self.interposer.apply_policy(report)
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

    #[test]
    fn observe_bytes_matches_observe_value() {
        let result = tools_list(json!([{"name": "echo", "description": "v1"}]));
        let bytes = serde_json::to_vec(&result).unwrap();

        let a = Interposer::new(InMemoryPinStore::new(), DriftPolicy::Report);
        let from_value = a.observe(&result).unwrap();

        let b = Interposer::new(InMemoryPinStore::new(), DriftPolicy::Report);
        let from_bytes = b.observe_bytes(&bytes).unwrap();

        assert_eq!(from_value, from_bytes);
    }

    #[test]
    fn observe_bytes_rejects_duplicate_keys() {
        // serde_json would silently keep the last `name`; the raw RFC 8785 parse
        // in observe_bytes must reject the duplicate member at the wire boundary.
        let raw = br#"{"tools":[{"name":"a","name":"a"}]}"#;
        let interposer = Interposer::new(InMemoryPinStore::new(), DriftPolicy::Report);
        match interposer.observe_bytes(raw) {
            Err(InterposerError::Integrity(_)) => {}
            other => panic!("expected integrity error, got {other:?}"),
        }
    }

    #[test]
    fn repin_bytes_then_observe_bytes_is_clean() {
        let bytes = serde_json::to_vec(&tools_list(
            json!([{"name": "echo", "description": "v1"}]),
        ))
        .unwrap();
        let mut interposer = Interposer::new(InMemoryPinStore::new(), DriftPolicy::FailClosed);
        interposer.repin_bytes(&bytes).unwrap();
        match interposer.observe_bytes(&bytes).unwrap() {
            Observation::Clean(_) => {}
            other => panic!("expected clean, got {other:?}"),
        }
    }

    #[test]
    fn accumulator_assembles_pages_and_reports_union_drift() {
        let interposer = Interposer::new(InMemoryPinStore::new(), DriftPolicy::Report);
        let mut acc = CatalogAccumulator::new(&interposer);

        let page1 = json!({"tools": [{"name": "a"}], "nextCursor": "c1"});
        let page2 = json!({"tools": [{"name": "b"}]});

        let cursor1 = acc.observe_page(&page1).unwrap();
        assert_eq!(cursor1.as_deref(), Some("c1"));
        let cursor2 = acc.observe_page(&page2).unwrap();
        assert_eq!(cursor2, None);

        match acc.finish().unwrap() {
            Observation::Drift(report) => assert_eq!(report.added, vec!["a", "b"]),
            other => panic!("expected union drift, got {other:?}"),
        }
    }

    #[test]
    fn accumulator_observe_page_bytes_returns_next_cursor() {
        let interposer = Interposer::new(InMemoryPinStore::new(), DriftPolicy::Report);
        let mut acc = CatalogAccumulator::new(&interposer);
        let page = br#"{"tools":[{"name":"a"}],"nextCursor":"NEXT"}"#;
        let cursor = acc.observe_page_bytes(page).unwrap();
        assert_eq!(cursor.as_deref(), Some("NEXT"));
    }

    #[test]
    fn accumulator_bare_array_page_has_no_cursor() {
        let interposer = Interposer::new(InMemoryPinStore::new(), DriftPolicy::Report);
        let mut acc = CatalogAccumulator::new(&interposer);
        let cursor = acc.observe_page(&json!([{"name": "a"}])).unwrap();
        assert_eq!(cursor, None);
    }

    #[test]
    fn repin_complete_then_finish_is_clean() {
        let mut interposer = Interposer::new(InMemoryPinStore::new(), DriftPolicy::FailClosed);

        let catalog = {
            let mut acc = CatalogAccumulator::new(&interposer);
            acc.observe_page(&json!({"tools": [{"name": "a"}], "nextCursor": "c1"}))
                .unwrap();
            acc.observe_page(&json!({"tools": [{"name": "b"}]})).unwrap();
            acc.catalog()
        };
        interposer.repin_complete(&catalog).unwrap();

        let mut acc = CatalogAccumulator::new(&interposer);
        acc.observe_page(&json!({"tools": [{"name": "a"}], "nextCursor": "c1"}))
            .unwrap();
        acc.observe_page(&json!({"tools": [{"name": "b"}]})).unwrap();
        match acc.finish().unwrap() {
            Observation::Clean(_) => {}
            other => panic!("expected clean, got {other:?}"),
        }
    }
}
