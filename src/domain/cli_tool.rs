use serde::{Deserialize, Serialize};

use crate::domain::api_spec::CredentialRef;
use crate::infrastructure::errors::GatewayError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralCliTool {
    pub name: String,
    pub description: String,
    pub docker_image: String,
    pub allowed_subcommands: Vec<String>,
    pub require_semantic_judge: bool,
    pub default_timeout_seconds: u32,
    pub registry_credentials_ref: Option<CredentialRef>,
}

impl EphemeralCliTool {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.name.trim().is_empty() {
            return Err(GatewayError::Validation(
                "EphemeralCliTool.name cannot be empty".to_string(),
            ));
        }
        if self.allowed_subcommands.is_empty() {
            return Err(GatewayError::Validation(
                "EphemeralCliTool.allowed_subcommands cannot be empty".to_string(),
            ));
        }
        if self.default_timeout_seconds > 300 {
            return Err(GatewayError::Validation(
                "EphemeralCliTool.default_timeout_seconds must be <= 300".to_string(),
            ));
        }
        if self.docker_image.trim().is_empty() {
            return Err(GatewayError::Validation(
                "EphemeralCliTool.docker_image cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralCliToolSummary {
    pub name: String,
    pub description: String,
    pub docker_image: String,
    pub allowed_subcommands: Vec<String>,
}
