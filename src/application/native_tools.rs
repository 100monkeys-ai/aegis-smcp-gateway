//! Native built-in tools that proxy directly to the orchestrator REST API.
//!
//! All aegis.* built-in tools have been moved to the orchestrator's direct
//! dispatch layer. This module retains the infrastructure (catalog, engine,
//! dispatch) so that external MCP tool servers can still be routed through
//! the same path if needed in the future.

use serde_json::Value;

use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::http_client::HttpClient;

/// Metadata for a single native tool, used by the tool-listing endpoints.
#[derive(Debug, Clone)]
pub struct NativeToolMeta {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

/// Static catalog of every native tool exposed by this gateway.
///
/// Currently empty — all aegis.* tools have been moved to the orchestrator.
pub fn native_tool_catalog() -> Vec<NativeToolMeta> {
    vec![]
}

/// Returns `true` if `name` matches a native tool in the catalog.
pub fn is_native_tool(name: &str) -> bool {
    native_tool_catalog().iter().any(|meta| meta.name == name)
}

/// Engine that dispatches native tool invocations to the orchestrator REST API.
#[derive(Clone)]
pub struct NativeToolEngine {
    http_client: HttpClient,
    orchestrator_url: String,
}

impl NativeToolEngine {
    pub fn new(http_client: HttpClient, orchestrator_url: String) -> Self {
        Self {
            http_client,
            orchestrator_url,
        }
    }

    /// Invoke a native tool by name. `bearer_token` is forwarded as-is to the
    /// orchestrator so it can enforce per-tenant authorization.
    pub async fn invoke(
        &self,
        tool_name: &str,
        _args: &Value,
        _bearer_token: &str,
    ) -> Result<Value, GatewayError> {
        // Suppress unused-field warnings while the engine is retained for
        // future external MCP tool routing.
        let _ = &self.http_client;
        let _ = &self.orchestrator_url;

        Err(GatewayError::NotFound(format!(
            "native tool '{tool_name}' not found"
        )))
    }
}

/// Convert an orchestrator HTTP response into a `Result<Value, GatewayError>`.
///
/// 2xx → `Ok(response_body)`
/// 4xx → `GatewayError::Validation`
/// 5xx → `GatewayError::Internal`
#[allow(dead_code)]
fn wrap_response(status: u16, body: Value) -> Result<Value, GatewayError> {
    match status {
        200..=299 => Ok(body),
        400..=499 => Err(GatewayError::Validation(
            body.get("error")
                .or_else(|| body.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("orchestrator rejected the request")
                .to_string(),
        )),
        _ => Err(GatewayError::Internal(format!(
            "orchestrator returned status {status}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn catalog_is_empty() {
        assert_eq!(native_tool_catalog().len(), 0);
    }

    #[test]
    fn is_native_tool_rejects_all_names() {
        assert!(!is_native_tool("aegis.volume.create"));
        assert!(!is_native_tool("aegis.file.read"));
        assert!(!is_native_tool("aegis.git.clone"));
        assert!(!is_native_tool("aegis.script.save"));
        assert!(!is_native_tool("aegis.workflow.run"));
        assert!(!is_native_tool(""));
    }

    #[test]
    fn wrap_response_ok_on_2xx() {
        let body = json!({"id": "vol-1"});
        assert!(wrap_response(200, body.clone()).is_ok());
        assert!(wrap_response(201, body.clone()).is_ok());
    }

    #[test]
    fn wrap_response_validation_on_4xx() {
        let body = json!({"error": "not found"});
        let err = wrap_response(404, body).unwrap_err();
        assert!(matches!(err, GatewayError::Validation(_)));
    }

    #[test]
    fn wrap_response_internal_on_5xx() {
        let body = json!({});
        let err = wrap_response(500, body).unwrap_err();
        assert!(matches!(err, GatewayError::Internal(_)));
    }
}
