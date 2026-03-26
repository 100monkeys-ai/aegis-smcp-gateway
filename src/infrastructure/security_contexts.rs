use crate::domain::{SecurityCapabilities, SecurityContext};

pub fn default_security_contexts() -> Vec<SecurityContext> {
    vec![
        SecurityContext {
            name: "default".to_string(),
            capabilities: SecurityCapabilities {
                allow_workflow_tools: true,
                allow_cli_tools: true,
                allow_explorer: false,
                allow_human_delegated_credentials: false,
            },
            tenant_id: None, // System-wide context
        },
        SecurityContext {
            name: "internal".to_string(),
            capabilities: SecurityCapabilities {
                allow_workflow_tools: true,
                allow_cli_tools: true,
                allow_explorer: true,
                allow_human_delegated_credentials: true,
            },
            tenant_id: None, // System-wide context
        },
        SecurityContext {
            name: "zaru-free".to_string(),
            capabilities: SecurityCapabilities {
                allow_workflow_tools: true,
                allow_cli_tools: true,
                allow_explorer: false,
                allow_human_delegated_credentials: true,
            },
            tenant_id: None, // System-wide context
        },
    ]
}
