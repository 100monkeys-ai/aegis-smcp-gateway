use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::application::ApiExplorerRequest;
use crate::domain::SmcpEnvelope;
use crate::presentation::control_plane::error_response;
use crate::presentation::state::AppState;

pub async fn invoke_smcp(
    State(state): State<AppState>,
    Json(envelope): Json<SmcpEnvelope>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = state
        .invocation_service
        .invoke_smcp(envelope, None)
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"result": result})))
}

#[derive(Deserialize)]
pub struct InternalInvokeRequest {
    pub execution_id: String,
    pub tool_name: String,
    pub args: Value,
    pub zaru_user_token: Option<String>,
}

pub async fn invoke_internal(
    State(state): State<AppState>,
    Json(request): Json<InternalInvokeRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = state
        .invocation_service
        .invoke_internal(
            &request.execution_id,
            &request.tool_name,
            request.args,
            request.zaru_user_token.as_deref(),
        )
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"result": result})))
}

pub async fn explore_api(
    State(state): State<AppState>,
    Json(req): Json<ApiExplorerRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = state
        .explorer_service
        .explore(req, None)
        .await
        .map_err(error_response)?;
    Ok(Json(json!(result)))
}
