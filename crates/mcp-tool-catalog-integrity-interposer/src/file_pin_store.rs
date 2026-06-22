//! Durable, file-backed [`PinStore`] (feature `file_pin_store`).
//!
//! [`FilePinStore`] is the reference **durable** store: TOFU pins must survive a
//! host restart, or a malicious server can replace the catalog while the host is
//! down and the host has no baseline to detect the rug-pull against. The core
//! [`mcp_tool_catalog_integrity::InMemoryPinStore`] is **ephemeral**
//! (test/per-session) and therefore CANNOT provide rug-pull detection across
//! restarts.
//!
//! The [`PinStore`] mutators are infallible (they return `()`), so they mutate
//! only the in-memory maps. The host MUST call [`FilePinStore::flush`] after a
//! re-pin to persist; `flush` is where the IO errors the infallible trait cannot
//! surface are returned. Persistence is atomic (temp file + `sync_all` +
//! `rename`) so a crash mid-write never corrupts the existing pin file.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use mcp_tool_catalog_integrity::PinStore;
use serde_json::Value;

/// A [`PinStore`] persisted to a single JSON file on disk.
///
/// On-disk shape: `{"pins": {name: hash, ...}, "catalog_hash": <string|null>}`.
/// Pins are kept in a [`BTreeMap`] so the serialized file is deterministic.
pub struct FilePinStore {
    path: PathBuf,
    pins: BTreeMap<String, String>,
    catalog_hash: Option<String>,
}

impl FilePinStore {
    /// Open the store at `path`.
    ///
    /// If the file exists it is read and parsed; a malformed file is a fail-closed
    /// [`io::ErrorKind::InvalidData`] error rather than a silent empty start over
    /// a corrupt baseline. If the file is absent the store starts empty.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        match fs::read(&path) {
            Ok(bytes) => {
                let value: Value = serde_json::from_slice(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let pins = Self::parse_pins(&value)?;
                let catalog_hash = Self::parse_catalog_hash(&value)?;
                Ok(Self {
                    path,
                    pins,
                    catalog_hash,
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self {
                path,
                pins: BTreeMap::new(),
                catalog_hash: None,
            }),
            Err(e) => Err(e),
        }
    }

    fn parse_pins(value: &Value) -> io::Result<BTreeMap<String, String>> {
        let mut pins = BTreeMap::new();
        match value.get("pins") {
            None | Some(Value::Null) => {}
            Some(Value::Object(map)) => {
                for (name, hash) in map {
                    let hash = hash.as_str().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "pin value is not a string",
                        )
                    })?;
                    pins.insert(name.clone(), hash.to_string());
                }
            }
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "`pins` is not a JSON object",
                ));
            }
        }
        Ok(pins)
    }

    fn parse_catalog_hash(value: &Value) -> io::Result<Option<String>> {
        match value.get("catalog_hash") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "`catalog_hash` is not a string or null",
            )),
        }
    }

    /// Persist the current pins and catalog hash to disk atomically.
    ///
    /// Writes to a temp file in the same directory, `sync_all`s it, then renames
    /// it over the target so a concurrent reader sees either the old file or the
    /// new one, never a partial write. The host MUST call this after a re-pin;
    /// this is where IO errors the infallible [`PinStore`] mutators cannot return
    /// are surfaced.
    pub fn flush(&self) -> io::Result<()> {
        let mut pins = serde_json::Map::new();
        for (name, hash) in &self.pins {
            pins.insert(name.clone(), Value::String(hash.clone()));
        }
        let doc = Value::Object({
            let mut m = serde_json::Map::new();
            m.insert("pins".to_string(), Value::Object(pins));
            m.insert(
                "catalog_hash".to_string(),
                match &self.catalog_hash {
                    Some(h) => Value::String(h.clone()),
                    None => Value::Null,
                },
            );
            m
        });
        let bytes = serde_json::to_vec(&doc)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);

        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)
    }
}

impl PinStore for FilePinStore {
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

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let unique = format!(
            "mtci_filepinstore_{}_{}_{}.json",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        p.push(unique);
        p
    }

    #[test]
    fn set_flush_reopen_survives() {
        let path = temp_path("survives");
        {
            let mut store = FilePinStore::open(&path).unwrap();
            assert_eq!(store.get("echo"), None);
            store.set("echo", "sha256:abc");
            store.flush().unwrap();
        }
        let reopened = FilePinStore::open(&path).unwrap();
        assert_eq!(reopened.get("echo"), Some("sha256:abc"));
        assert_eq!(reopened.pinned_names(), vec!["echo".to_string()]);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn catalog_hash_round_trips_through_file() {
        let path = temp_path("cathash");
        {
            let mut store = FilePinStore::open(&path).unwrap();
            assert_eq!(store.catalog_hash(), None);
            store.set_catalog_hash("sha256:cat");
            store.flush().unwrap();
        }
        let reopened = FilePinStore::open(&path).unwrap();
        assert_eq!(reopened.catalog_hash(), Some("sha256:cat"));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn corrupt_file_fails_closed() {
        let path = temp_path("corrupt");
        fs::write(&path, b"{ this is not json").unwrap();
        match FilePinStore::open(&path) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("expected open of corrupt file to fail"),
        }
        fs::remove_file(&path).ok();
    }

    #[test]
    fn absent_file_starts_empty() {
        let path = temp_path("absent");
        let store = FilePinStore::open(&path).unwrap();
        assert!(store.pinned_names().is_empty());
        assert_eq!(store.catalog_hash(), None);
    }
}
