//! Compare an observed catalog against the pinned baseline and report drift.
//!
//! The verifier is fail-closed: every tool is classified as added, removed,
//! mutated, or unchanged, and any of the first three constitutes drift the host
//! has not approved (see [`DriftReport::has_drift`]). A descriptor with no string
//! `name` is rejected outright rather than skipped.

use std::collections::HashSet;

use crate::descriptor_hash::{catalog_hash, descriptor_hash};
use crate::manifest::ToolCatalog;
use crate::pin_store::PinStore;
use crate::IntegrityError;

/// The result of verifying an observed catalog against a [`PinStore`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DriftReport {
    /// Tools present in the observation but not pinned.
    pub added: Vec<String>,
    /// Tools pinned but absent from the observation.
    pub removed: Vec<String>,
    /// Tools present in both whose descriptor hash differs from the pin.
    pub mutated: Vec<String>,
    /// Tools present in both with a matching descriptor hash.
    pub unchanged: Vec<String>,
    /// The catalog hash of the observed catalog.
    pub observed_catalog_hash: String,
}

impl DriftReport {
    /// Whether the observation drifted from the pinned baseline in any way the
    /// host has not approved.
    pub fn has_drift(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.mutated.is_empty()
    }
}

/// Verify `catalog` against `pins`, classifying every tool and computing the
/// observed catalog hash. Does not mutate the pin store; a host calls
/// [`repin`] to accept the observation.
pub fn verify(catalog: &ToolCatalog, pins: &dyn PinStore) -> Result<DriftReport, IntegrityError> {
    let mut report = DriftReport::default();
    let mut observed: HashSet<String> = HashSet::new();
    let mut hashes: Vec<String> = Vec::with_capacity(catalog.tools.len());

    for tool in &catalog.tools {
        let name = tool.name().ok_or(IntegrityError::MissingName)?;
        let hash = descriptor_hash(&tool.value)?;
        hashes.push(hash.clone());
        observed.insert(name.to_string());

        match pins.get(name) {
            None => report.added.push(name.to_string()),
            Some(pinned) if pinned == hash => report.unchanged.push(name.to_string()),
            Some(_) => report.mutated.push(name.to_string()),
        }
    }

    for name in pins.pinned_names() {
        if !observed.contains(&name) {
            report.removed.push(name);
        }
    }

    report.added.sort();
    report.removed.sort();
    report.mutated.sort();
    report.unchanged.sort();
    report.observed_catalog_hash = catalog_hash(hashes);

    Ok(report)
}

/// Accept an observed catalog as the new baseline: pin every observed
/// descriptor hash, drop pins for tools no longer present, and record the
/// catalog hash. This is the explicit, host-approved re-pin.
pub fn repin(catalog: &ToolCatalog, pins: &mut dyn PinStore) -> Result<(), IntegrityError> {
    let mut observed: HashSet<String> = HashSet::new();
    let mut hashes: Vec<String> = Vec::with_capacity(catalog.tools.len());

    for tool in &catalog.tools {
        let name = tool.name().ok_or(IntegrityError::MissingName)?;
        let hash = descriptor_hash(&tool.value)?;
        pins.set(name, &hash);
        hashes.push(hash);
        observed.insert(name.to_string());
    }

    for name in pins.pinned_names() {
        if !observed.contains(&name) {
            pins.remove(&name);
        }
    }

    pins.set_catalog_hash(&catalog_hash(hashes));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ToolCatalog;
    use crate::pin_store::InMemoryPinStore;
    use serde_json::json;

    fn catalog(tools: Vec<serde_json::Value>) -> ToolCatalog {
        ToolCatalog::from_values(tools)
    }

    #[test]
    fn first_observation_is_all_added() {
        let cat = catalog(vec![json!({"name": "echo", "description": "v1"})]);
        let pins = InMemoryPinStore::new();
        let report = verify(&cat, &pins).unwrap();
        assert_eq!(report.added, vec!["echo"]);
        assert!(report.has_drift());
    }

    #[test]
    fn repinned_catalog_has_no_drift() {
        let cat = catalog(vec![json!({"name": "echo", "description": "v1"})]);
        let mut pins = InMemoryPinStore::new();
        repin(&cat, &mut pins).unwrap();
        let report = verify(&cat, &pins).unwrap();
        assert!(!report.has_drift());
        assert_eq!(report.unchanged, vec!["echo"]);
        assert_eq!(Some(report.observed_catalog_hash.as_str()), pins.catalog_hash());
    }

    #[test]
    fn detects_mutation_addition_removal() {
        let baseline = catalog(vec![
            json!({"name": "echo", "description": "v1"}),
            json!({"name": "gone", "description": "to be removed"}),
        ]);
        let mut pins = InMemoryPinStore::new();
        repin(&baseline, &mut pins).unwrap();

        let observed = catalog(vec![
            json!({"name": "echo", "description": "v2-changed"}),
            json!({"name": "new", "description": "added"}),
        ]);
        let report = verify(&observed, &pins).unwrap();
        assert_eq!(report.mutated, vec!["echo"]);
        assert_eq!(report.added, vec!["new"]);
        assert_eq!(report.removed, vec!["gone"]);
        assert!(report.has_drift());
    }

    #[test]
    fn descriptor_without_name_is_rejected() {
        let cat = catalog(vec![json!({"description": "no name here"})]);
        let pins = InMemoryPinStore::new();
        assert_eq!(verify(&cat, &pins), Err(IntegrityError::MissingName));
    }
}
