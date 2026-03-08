use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub name: String,
    pub capabilities: SecurityCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCapabilities {
    pub allow_workflow_tools: bool,
    pub allow_cli_tools: bool,
    pub allow_explorer: bool,
    pub allow_human_delegated_credentials: bool,
}
