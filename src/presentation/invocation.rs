use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::application::ApiExplorerRequest;
use crate::domain::SealEnvelope;
use crate::infrastructure::auth::TenantContext;
use crate::infrastructure::errors::{classify_seal_error, GatewayError, SealErrorResponse};
use crate::presentation::control_plane::error_response;
use crate::presentation::state::AppState;

/// Convert a `GatewayError` to a SEAL-aware HTTP error tuple.
///
/// `GatewayError::Seal` variants produce a structured `SealErrorResponse`;
/// all other variants fall through to the generic `error_response`.
fn seal_error_response(err: GatewayError) -> (StatusCode, Json<Value>) {
    log_pool_timeout("invoke_seal", &err);
    match err {
        GatewayError::Seal(ref msg) => {
            let code = classify_seal_error(msg);
            let status = match code {
                1001..=1006 => StatusCode::UNAUTHORIZED,
                2000..=2999 => StatusCode::FORBIDDEN,
                _ => StatusCode::BAD_REQUEST,
            };
            let body = SealErrorResponse::new(code, msg.clone())
                .with_request_id(Uuid::new_v4().to_string());
            (
                status,
                Json(serde_json::to_value(body).unwrap_or_else(|_| json!({"error": msg}))),
            )
        }
        other => error_response(other),
    }
}

#[utoipa::path(
    post,
    path = "/v1/invoke",
    tag = "Invocation",
    request_body = SealEnvelope,
    responses(
        (status = 200, description = "Invocation result"),
        (status = 400, description = "Validation / policy error"),
        (status = 401, description = "SEAL signature verification failed"),
    ),
)]
pub async fn invoke_seal(
    State(state): State<AppState>,
    Extension(tenant): Extension<TenantContext>,
    Json(envelope): Json<SealEnvelope>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = state
        .invocation_service
        .invoke_seal(envelope, None, tenant.identity_kind)
        .await
        .map_err(seal_error_response)?;
    Ok(Json(json!({"result": result})))
}

#[utoipa::path(
    post,
    path = "/v1/explorer",
    tag = "Explorer",
    request_body = ApiExplorerRequest,
    responses(
        (status = 200, description = "Sliced API exploration response"),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_jwt" = [])),
)]
pub async fn explore_api(
    State(state): State<AppState>,
    Json(req): Json<ApiExplorerRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = state
        .explorer_service
        .explore(req, None)
        .await
        .map_err(|err| {
            log_pool_timeout("explore_api", &err);
            error_response(err)
        })?;
    Ok(Json(json!(result)))
}

#[cfg(test)]
mod tests {
    //! Regression coverage for the SEAL request path's identity-kind
    //! propagation. Prior to this fix, `invoke_seal` ignored the
    //! `TenantContext` injected by `inject_seal_tenant_context` and
    //! hard-coded `IdentityKind::Consumer` when constructing the
    //! `CliInvocation`, making the ADR-100 service-account delegation
    //! exception unreachable for SEAL traffic. The test below stands up the
    //! real axum middleware in front of a probe handler that mirrors the
    //! `Extension<TenantContext>` extraction performed by `invoke_seal`,
    //! and asserts the JWT-derived identity kind reaches the handler.
    use crate::infrastructure::auth::{inject_seal_tenant_context, IdentityKind, TenantContext};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::{Extension, Router};
    use base64::Engine;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    fn make_unsigned_jwt(claims: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).expect("serialize claims"));
        format!("{header}.{payload}.")
    }

    fn build_seal_envelope_body(token: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "protocol": "seal/v1",
            "security_token": token,
            "payload": {},
            "signature": "",
            "timestamp": "2026-04-27T00:00:00Z"
        }))
        .expect("serialize envelope")
    }

    /// Regression: the SEAL request path MUST extract `TenantContext` from
    /// request extensions and forward its `identity_kind` to the
    /// application service. A service-account JWT (identifiable via the
    /// `service-account-` prefix on `preferred_username`) must surface as
    /// `IdentityKind::ServiceAccount` at the handler boundary so the
    /// downstream `cli_engine` tenant-arg delegation gate (ADR-100) is
    /// reachable for SEAL traffic. The previously-shipped code hard-coded
    /// `IdentityKind::Consumer` in `invoke_seal`, breaking delegation.
    #[tokio::test]
    async fn invoke_seal_handler_propagates_service_account_identity_kind() {
        let captured: Arc<Mutex<Option<IdentityKind>>> = Arc::new(Mutex::new(None));

        // Probe handler that mirrors the `Extension<TenantContext>`
        // extraction `invoke_seal` performs and records what it observes.
        async fn probe_handler(
            axum::extract::State(slot): axum::extract::State<Arc<Mutex<Option<IdentityKind>>>>,
            Extension(tenant): Extension<TenantContext>,
            _body: axum::body::Bytes,
        ) -> StatusCode {
            *slot.lock().expect("lock") = Some(tenant.identity_kind);
            StatusCode::OK
        }

        let app: Router = Router::new()
            .route("/v1/seal/invoke", post(probe_handler))
            .layer(axum::middleware::from_fn(inject_seal_tenant_context))
            .with_state(captured.clone());

        let token = make_unsigned_jwt(serde_json::json!({
            "sub": "agent-1",
            "exec_id": "exec-1",
            "tenant_id": "u-delegated-tenant",
            "preferred_username": "service-account-zaru",
        }));
        let body_bytes = build_seal_envelope_body(&token);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/seal/invoke")
            .body(Body::from(body_bytes))
            .expect("build request");

        let response = app.oneshot(request).await.expect("router oneshot");
        assert_eq!(response.status(), StatusCode::OK);

        let observed = captured.lock().expect("lock").take();
        assert_eq!(
            observed,
            Some(IdentityKind::ServiceAccount),
            "service-account JWT must surface as IdentityKind::ServiceAccount at the handler"
        );
    }

    /// Regression: a vanilla consumer JWT (no `service-account-` prefix on
    /// `preferred_username` and no explicit `identity_kind` claim) must
    /// surface as `IdentityKind::Consumer`, preserving the ADR-097 tenant
    /// boundary for non-service-account callers.
    #[tokio::test]
    async fn invoke_seal_handler_propagates_consumer_identity_kind() {
        let captured: Arc<Mutex<Option<IdentityKind>>> = Arc::new(Mutex::new(None));

        async fn probe_handler(
            axum::extract::State(slot): axum::extract::State<Arc<Mutex<Option<IdentityKind>>>>,
            Extension(tenant): Extension<TenantContext>,
            _body: axum::body::Bytes,
        ) -> StatusCode {
            *slot.lock().expect("lock") = Some(tenant.identity_kind);
            StatusCode::OK
        }

        let app: Router = Router::new()
            .route("/v1/seal/invoke", post(probe_handler))
            .layer(axum::middleware::from_fn(inject_seal_tenant_context))
            .with_state(captured.clone());

        let token = make_unsigned_jwt(serde_json::json!({
            "sub": "agent-1",
            "exec_id": "exec-1",
            "tenant_id": "u-mytenant-cafef00d",
            "preferred_username": "alice",
        }));
        let body_bytes = build_seal_envelope_body(&token);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/seal/invoke")
            .body(Body::from(body_bytes))
            .expect("build request");

        let response = app.oneshot(request).await.expect("router oneshot");
        assert_eq!(response.status(), StatusCode::OK);

        let observed = captured.lock().expect("lock").take();
        assert_eq!(observed, Some(IdentityKind::Consumer));
    }
}

/// Emit a structured `error!` log when a request handler fails because the
/// Postgres pool's `acquire_timeout` elapsed. Without this log, pool
/// starvation incidents leave no trace in the request path — the gateway
/// just appears unreachable while every handler hangs on `pool.acquire()`.
fn log_pool_timeout(handler: &'static str, err: &GatewayError) {
    if err.is_pool_timeout() {
        tracing::error!(
            handler = handler,
            error = %err,
            "database pool acquire timed out — request path starved"
        );
    }
}
