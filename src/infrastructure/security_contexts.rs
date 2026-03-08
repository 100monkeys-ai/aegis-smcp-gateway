use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::domain::{SecurityCapabilities, SecurityContext, SecurityContextRepository};
use crate::infrastructure::errors::GatewayError;

#[derive(Clone)]
pub struct InMemorySecurityContextStore {
    contexts: Arc<HashMap<String, SecurityContext>>,
}

impl InMemorySecurityContextStore {
    pub fn with_defaults() -> Self {
        let mut contexts = HashMap::new();

        contexts.insert(
            "default".to_string(),
            SecurityContext {
                name: "default".to_string(),
                capabilities: SecurityCapabilities {
                    allow_workflow_tools: true,
                    allow_cli_tools: true,
                    allow_explorer: false,
                    allow_human_delegated_credentials: false,
                },
            },
        );
        contexts.insert(
            "internal".to_string(),
            SecurityContext {
                name: "internal".to_string(),
                capabilities: SecurityCapabilities {
                    allow_workflow_tools: true,
                    allow_cli_tools: true,
                    allow_explorer: true,
                    allow_human_delegated_credentials: true,
                },
            },
        );
        contexts.insert(
            "zaru-free".to_string(),
            SecurityContext {
                name: "zaru-free".to_string(),
                capabilities: SecurityCapabilities {
                    allow_workflow_tools: true,
                    allow_cli_tools: true,
                    allow_explorer: false,
                    allow_human_delegated_credentials: true,
                },
            },
        );

        Self {
            contexts: Arc::new(contexts),
        }
    }
}

#[async_trait]
impl SecurityContextRepository for InMemorySecurityContextStore {
    async fn find_by_name(&self, name: &str) -> Result<Option<SecurityContext>, GatewayError> {
        Ok(self.contexts.get(name).cloned())
    }
}
