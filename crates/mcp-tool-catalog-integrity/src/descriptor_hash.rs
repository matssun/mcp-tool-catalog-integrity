//! Canonicalization and hashing of tool descriptors and catalogs.
//!
//! A descriptor hash is a stable identifier over a descriptor's canonical form;
//! two descriptors share a hash iff their canonical bytes are identical. The
//! catalog hash is computed over the *sorted* set of descriptor hashes, so it is
//! independent of the order in which a server lists its tools.

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::IntegrityError;

/// Render a SHA-256 digest of `bytes` as the MTCI hash identifier
/// `"sha256:<base64url-nopad>"`.
pub fn hash_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

/// Reduce a JSON value to its RFC 8785 (JCS) canonical byte form.
///
/// Delegates to the vendored RFC 8785 canonicalizer ([`crate::canonical`], copied
/// verbatim from MCP-S so the two emit byte-identical output): object members
/// sorted by UTF-16 code-unit order, integer-only numbers in shortest decimal
/// form, minimal string escaping, and no insignificant whitespace.
///
/// Canonicalization is **fail-closed**: any value outside the JCS-safe domain (a
/// fractional / exponent / out-of-range number, an invalid string, or nesting
/// beyond the depth bound) yields [`IntegrityError::Canonicalization`] rather than
/// a best-effort encoding, satisfying §2 of the profile spec.
///
/// NOTE: duplicate object members cannot be detected on this path, because the
/// input is an already-parsed [`serde_json::Value`] (serde's map silently keeps
/// the last duplicate). A raw-bytes ingestion path can call
/// [`crate::canonical::canonicalize`] over the original descriptor bytes to also
/// reject duplicate members per §2; wiring that through the descriptor model is a
/// separate follow-up.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, IntegrityError> {
    canonical::canonicalize_json_value(value)
}

/// The descriptor hash of a single descriptor value.
pub fn descriptor_hash(value: &Value) -> Result<String, IntegrityError> {
    Ok(hash_id(&canonicalize(value)?))
}

/// The catalog hash over a set of descriptor hashes.
///
/// The hashes are sorted ascending as byte strings and joined with a NUL
/// separator before hashing, so the result is independent of catalog ordering
/// and unambiguous across hash boundaries.
pub fn catalog_hash<I, S>(descriptor_hashes: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut sorted: Vec<String> = descriptor_hashes
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect();
    sorted.sort();

    let mut hasher = Sha256::new();
    for h in &sorted {
        hasher.update(h.as_bytes());
        hasher.update([0x00]);
    }
    format!(
        "sha256:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn descriptor_hash_is_key_order_independent() {
        let a = json!({"name": "echo", "description": "Echo input", "inputSchema": {"type": "object"}});
        let b = json!({"inputSchema": {"type": "object"}, "description": "Echo input", "name": "echo"});
        assert_eq!(descriptor_hash(&a).unwrap(), descriptor_hash(&b).unwrap());
    }

    #[test]
    fn descriptor_hash_detects_mutation() {
        let a = json!({"name": "echo", "description": "Echo input"});
        let b = json!({"name": "echo", "description": "Echo input (changed)"});
        assert_ne!(descriptor_hash(&a).unwrap(), descriptor_hash(&b).unwrap());
    }

    #[test]
    fn hash_id_has_expected_shape() {
        let id = hash_id(b"");
        assert!(id.starts_with("sha256:"));
        // SHA-256 (32 bytes) base64url-nopad is 43 chars; plus the "sha256:" prefix.
        assert_eq!(id.len(), "sha256:".len() + 43);
    }

    #[test]
    fn catalog_hash_is_order_independent() {
        let one = catalog_hash(["sha256:aaa", "sha256:bbb"]);
        let two = catalog_hash(["sha256:bbb", "sha256:aaa"]);
        assert_eq!(one, two);
    }
}
