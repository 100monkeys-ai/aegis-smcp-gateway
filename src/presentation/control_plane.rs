use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::domain::{
    ApiSpec, ApiSpecId, CredentialResolutionPath, EphemeralCliTool, ToolWorkflow, WorkflowId,
};
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::openapi::parse_operations;
use crate::presentation::state::AppState;

#[derive(Deserialize)]
pub struct RegisterSpecRequest {
    pub name: String,
    pub base_url: String,
    pub source_url: Option<String>,
    pub inline_json: Option<Value>,
    pub source_fetch_url: Option<String>,
    pub credential_path: Option<CredentialResolutionPath>,
}

pub async fn register_spec(
    State(state): State<AppState>,
    Json(req): Json<RegisterSpecRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Some(source_url) = req.source_url.as_ref() {
        let existing = state
            .specs
            .find_by_source_url(source_url)
            .await
            .map_err(error_response)?;
        if let Some(spec) = existing {
            return Ok(Json(
                json!({"id": spec.id.0.to_string(), "deduplicated": true}),
            ));
        }
    }

    let raw_spec = if let Some(inline) = req.inline_json {
        inline
    } else if let Some(url) = req.source_fetch_url {
        let body = reqwest::get(&url)
            .await
            .map_err(|e| error_response(GatewayError::Http(e.to_string())))?
            .json::<Value>()
            .await
            .map_err(|e| error_response(GatewayError::Http(e.to_string())))?;
        body
    } else {
        return Err(error_response(GatewayError::Validation(
            "provide inline_json or source_fetch_url".to_string(),
        )));
    };

    let operations = parse_operations(&raw_spec).map_err(error_response)?;
    let spec = ApiSpec::new(
        req.name,
        req.base_url,
        req.source_url,
        raw_spec,
        operations,
        req.credential_path
            .unwrap_or(CredentialResolutionPath::None),
    )
    .map_err(error_response)?;

    let id = spec.id;
    state.specs.save(spec).await.map_err(error_response)?;

    Ok(Json(json!({"id": id.0.to_string()})))
}

pub async fn list_specs(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let specs = state.specs.list_all().await.map_err(error_response)?;
    Ok(Json(json!(specs)))
}

pub async fn get_spec(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let parsed = parse_api_spec_id(&id).map_err(error_response)?;
    let spec = state
        .specs
        .find_by_id(parsed)
        .await
        .map_err(error_response)?;
    match spec {
        Some(s) => Ok(Json(json!(s))),
        None => Err(error_response(GatewayError::NotFound(
            "spec not found".to_string(),
        ))),
    }
}

pub async fn delete_spec(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let parsed = parse_api_spec_id(&id).map_err(error_response)?;
    state.specs.delete(parsed).await.map_err(error_response)?;
    Ok(Json(json!({"deleted": true})))
}

#[derive(Deserialize)]
pub struct RegisterWorkflowRequest {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub api_spec_id: String,
    pub steps: Vec<crate::domain::WorkflowStep>,
}

pub async fn register_workflow(
    State(state): State<AppState>,
    Json(req): Json<RegisterWorkflowRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let api_spec_id = parse_api_spec_id(&req.api_spec_id).map_err(error_response)?;
    let workflow = ToolWorkflow::new(
        req.name,
        req.description,
        req.input_schema,
        api_spec_id,
        req.steps,
    )
    .map_err(error_response)?;
    let id = workflow.id;
    state
        .workflows
        .save(workflow)
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"id": id.0.to_string()})))
}

pub async fn list_workflows(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let list = state.workflows.list_all().await.map_err(error_response)?;
    Ok(Json(json!(list)))
}

pub async fn get_workflow(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let parsed = parse_workflow_id(&id).map_err(error_response)?;
    let wf = state
        .invocation_service
        .find_workflow_by_id(parsed)
        .await
        .map_err(error_response)?;
    match wf {
        Some(v) => Ok(Json(json!(v))),
        None => Err(error_response(GatewayError::NotFound(
            "workflow not found".to_string(),
        ))),
    }
}

pub async fn delete_workflow(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let parsed = parse_workflow_id(&id).map_err(error_response)?;
    state
        .workflows
        .delete(parsed)
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"deleted": true})))
}

#[derive(Deserialize)]
pub struct RegisterCliToolRequest {
    pub name: String,
    pub description: String,
    pub docker_image: String,
    pub allowed_subcommands: Vec<String>,
    pub require_semantic_judge: bool,
    pub default_timeout_seconds: u32,
    pub registry_credentials_ref: Option<crate::domain::CredentialRef>,
}

pub async fn register_cli_tool(
    State(state): State<AppState>,
    Json(req): Json<RegisterCliToolRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let tool = EphemeralCliTool {
        name: req.name,
        description: req.description,
        docker_image: req.docker_image,
        allowed_subcommands: req.allowed_subcommands,
        require_semantic_judge: req.require_semantic_judge,
        default_timeout_seconds: req.default_timeout_seconds,
        registry_credentials_ref: req.registry_credentials_ref,
    };
    tool.validate().map_err(error_response)?;
    state.cli_tools.save(tool).await.map_err(error_response)?;
    Ok(Json(json!({"saved": true})))
}

pub async fn list_cli_tools(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let list = state.cli_tools.list_all().await.map_err(error_response)?;
    Ok(Json(json!(list)))
}

pub async fn delete_cli_tool(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    state
        .cli_tools
        .delete(&name)
        .await
        .map_err(error_response)?;
    Ok(Json(json!({"deleted": true})))
}

pub async fn list_tools(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let workflows = state.workflows.list_all().await.map_err(error_response)?;
    let cli_tools = state.cli_tools.list_all().await.map_err(error_response)?;

    let workflow_tools = workflows.into_iter().map(|wf| {
        json!({
            "name": wf.name,
            "description": wf.description,
            "kind": "workflow"
        })
    });
    let cli_tools = cli_tools.into_iter().map(|tool| {
        json!({
            "name": tool.name,
            "description": tool.description,
            "kind": "cli"
        })
    });

    let all = workflow_tools.chain(cli_tools).collect::<Vec<_>>();
    Ok(Json(json!(all)))
}

fn parse_api_spec_id(input: &str) -> Result<ApiSpecId, GatewayError> {
    let id = uuid::Uuid::parse_str(input)
        .map_err(|e| GatewayError::Validation(format!("invalid api spec id: {e}")))?;
    Ok(ApiSpecId(id))
}

fn parse_workflow_id(input: &str) -> Result<WorkflowId, GatewayError> {
    let id = uuid::Uuid::parse_str(input)
        .map_err(|e| GatewayError::Validation(format!("invalid workflow id: {e}")))?;
    Ok(WorkflowId(id))
}

pub fn error_response(err: GatewayError) -> (StatusCode, Json<Value>) {
    match err {
        GatewayError::Validation(msg) => (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))),
        GatewayError::NotFound(msg) => (StatusCode::NOT_FOUND, Json(json!({"error": msg}))),
        GatewayError::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        ),
        GatewayError::Forbidden => (StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))),
        other => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": other.to_string()})),
        ),
    }
}
