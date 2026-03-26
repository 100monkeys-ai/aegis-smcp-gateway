use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub name: String,
    pub capabilities: SecurityCapabilities,
    /// Optional tenant slug that owns this security context (ADR-056).
    /// `None` means the context is system-wide (available to all tenants).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCapabilities {
    pub allow_workflow_tools: bool,
    pub allow_cli_tools: bool,
    pub allow_explorer: bool,
    pub allow_human_delegated_credentials: bool,
}
