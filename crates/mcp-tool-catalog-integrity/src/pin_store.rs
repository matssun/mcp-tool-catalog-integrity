//! The host-side record of accepted descriptor hashes (trust-on-first-use).
//!
//! MTCI is pure: it does not persist anything itself. A host supplies durability
//! by implementing [`PinStore`]; [`InMemoryPinStore`] is the reference,
//! non-durable implementation used by tests and by hosts that pin per session.

use std::collections::HashMap;

/// A store of the descriptor hash a host last accepted for each tool, plus the
/// last accepted catalog hash.
pub trait PinStore {
    /// The pinned descriptor hash for `tool_name`, if any.
    fn get(&self, tool_name: &str) -> Option<&str>;

    /// Pin (or re-pin) `tool_name` to `descriptor_hash`.
    fn set(&mut self, tool_name: &str, descriptor_hash: &str);

    /// Drop the pin for `tool_name` (e.g. after an approved removal).
    fn remove(&mut self, tool_name: &str);

    /// The names of all currently pinned tools.
    fn pinned_names(&self) -> Vec<String>;

    /// The last accepted catalog hash, if any.
    fn catalog_hash(&self) -> Option<&str>;

    /// Record the last accepted catalog hash.
    fn set_catalog_hash(&mut self, catalog_hash: &str);
}

/// In-memory, non-durable [`PinStore`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InMemoryPinStore {
    pins: HashMap<String, String>,
    catalog_hash: Option<String>,
}

impl InMemoryPinStore {
    /// An empty pin store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of pinned tools.
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// Whether no tools are pinned.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

impl PinStore for InMemoryPinStore {
    fn get(&self, tool_name: &str) -> Option<&str> {
        self.pins.get(tool_name).map(String::as_str)
    }

    fn set(&mut self, tool_name: &str, descriptor_hash: &str) {
        self.pins
            .insert(tool_name.to_string(), descriptor_hash.to_string());
    }

    fn remove(&mut self, tool_name: &str) {
        self.pins.remove(tool_name);
    }

    fn pinned_names(&self) -> Vec<String> {
        self.pins.keys().cloned().collect()
    }

    fn catalog_hash(&self) -> Option<&str> {
        self.catalog_hash.as_deref()
    }

    fn set_catalog_hash(&mut self, catalog_hash: &str) {
        self.catalog_hash = Some(catalog_hash.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_remove_round_trip() {
        let mut store = InMemoryPinStore::new();
        assert!(store.is_empty());
        store.set("echo", "sha256:abc");
        assert_eq!(store.get("echo"), Some("sha256:abc"));
        assert_eq!(store.len(), 1);
        store.remove("echo");
        assert_eq!(store.get("echo"), None);
        assert!(store.is_empty());
    }

    #[test]
    fn catalog_hash_round_trip() {
        let mut store = InMemoryPinStore::new();
        assert_eq!(store.catalog_hash(), None);
        store.set_catalog_hash("sha256:cat");
        assert_eq!(store.catalog_hash(), Some("sha256:cat"));
    }
}
