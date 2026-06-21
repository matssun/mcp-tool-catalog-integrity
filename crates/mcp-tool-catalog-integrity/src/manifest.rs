//! The tool descriptor / catalog data model.
//!
//! A [`ToolDescriptor`] is the descriptor object an MCP server advertises for a
//! single tool (a `tools/list` result entry): its `name`, `description`,
//! `inputSchema`, and any annotations. A [`ToolCatalog`] is the set of those
//! descriptors observed at a point in time. Descriptors are kept as raw JSON so
//! MTCI can hash whatever the server advertised without lossy re-modeling.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One tool descriptor, retained as the raw JSON value the server advertised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ToolDescriptor {
    /// The full descriptor as advertised, including its `name` member.
    pub value: Value,
}

impl ToolDescriptor {
    /// Wrap a raw descriptor value.
    pub fn new(value: Value) -> Self {
        Self { value }
    }

    /// The descriptor's `name`, if present as a JSON string. A descriptor with no
    /// string `name` cannot be identified or pinned (see
    /// [`crate::IntegrityError::MissingName`]).
    pub fn name(&self) -> Option<&str> {
        self.value.get("name").and_then(Value::as_str)
    }
}

impl From<Value> for ToolDescriptor {
    fn from(value: Value) -> Self {
        Self::new(value)
    }
}

/// A complete tool catalog: the ordered set of descriptors as observed. Ordering
/// is not significant to MTCI — the catalog hash sorts descriptor hashes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ToolCatalog {
    pub tools: Vec<ToolDescriptor>,
}

impl ToolCatalog {
    /// Build a catalog from a sequence of descriptor values.
    pub fn from_values<I>(values: I) -> Self
    where
        I: IntoIterator<Item = Value>,
    {
        Self {
            tools: values.into_iter().map(ToolDescriptor::new).collect(),
        }
    }

    /// Parse a catalog from the `tools` array of a `tools/list` result.
    ///
    /// Accepts either the full result object (`{"tools": [...]}`) or a bare
    /// array (`[...]`).
    pub fn from_tools_list(result: &Value) -> Option<Self> {
        let array = result
            .get("tools")
            .or(Some(result))
            .and_then(Value::as_array)?;
        Some(Self {
            tools: array.iter().cloned().map(ToolDescriptor::new).collect(),
        })
    }
}
