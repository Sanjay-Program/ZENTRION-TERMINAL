use std::collections::{HashMap, HashSet};
use z_core::error::{Area, ZenError, ZenResult};
use z_tool::ToolId;

/// A graph mapping abstract capabilities (e.g., "sast", "port-scan") to concrete tools.
#[derive(Debug, Clone, Default)]
pub struct CapabilityGraph {
    /// Maps a capability name to a list of tool IDs that provide it.
    pub capabilities: HashMap<String, Vec<ToolId>>,
}

impl CapabilityGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool as providing a specific capability.
    pub fn register(&mut self, capability: &str, tool_id: ToolId) {
        self.capabilities
            .entry(capability.to_string())
            .or_default()
            .push(tool_id);
    }

    /// Resolve a capability into a list of tool IDs.
    pub fn resolve(&self, capability: &str) -> ZenResult<Vec<ToolId>> {
        if let Some(tools) = self.capabilities.get(capability) {
            Ok(tools.clone())
        } else {
            Err(ZenError::new(
                Area::Reg,
                7300,
                format!("No tools registered for capability '{}'", capability),
            ))
        }
    }

    /// Load the graph from a JSON string.
    pub fn from_json(json: &str) -> ZenResult<Self> {
        let raw: HashMap<String, Vec<String>> = serde_json::from_str(json).map_err(|e| {
            ZenError::new(
                Area::Reg,
                7301,
                format!("Failed to parse CapabilityGraph JSON: {}", e),
            )
        })?;

        let mut graph = Self::new();
        for (cap, tools) in raw {
            for t in tools {
                let tid = ToolId::parse(&t).map_err(|e| {
                    ZenError::new(Area::Reg, 7302, format!("Invalid tool ID in graph: {}", e))
                })?;
                graph.register(&cap, tid);
            }
        }
        Ok(graph)
    }
}
