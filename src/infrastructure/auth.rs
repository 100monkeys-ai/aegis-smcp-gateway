use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::Engine;

use crate::infrastructure::config::GatewayConfig;
use crate::presentation::state::AppState;

pub async fn require_operator(
    State(app_state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if app_state.config.auth_disabled {
        let mut request = request;
        request.extensions_mut().insert(TenantContext(None));
        return Ok(next.run(request).await);
    }

    let auth = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let tenant_id = verify_operator_token(&app_state.config, token).await?;

    // Inject tenant context into request extensions for downstream handlers (ADR-056).
    let mut request = request;
    request.extensions_mut().insert(TenantContext(tenant_id));

    Ok(next.run(request).await)
}

/// Middleware for `/v1/invoke` and `/v1/seal/invoke`.
///
/// Reads the SEAL envelope body, extracts the `tenant_id` claim from the
/// `security_token` JWT (without cryptographic verification — full verification
/// happens inside `InvocationService::invoke_seal`), injects `TenantContext`
/// into the request extensions, and re-assembles the body so the downstream
/// handler can deserialize it normally.
pub async fn inject_seal_tenant_context(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let (parts, body) = request.into_parts();

    // Buffer the entire request body so it can be deserialized and re-injected.
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Best-effort extraction: if we cannot parse the envelope or the token,
    // we still allow the request through with an empty TenantContext — the
    // full SEAL verification in InvocationService will reject invalid requests.
    let tenant_id: Option<String> = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.get("security_token")
                .and_then(|t| t.as_str())
                .and_then(decode_jwt_tenant_id_unverified)
        });

    let mut request = Request::from_parts(parts, Body::from(bytes));
    request
        .extensions_mut()
        .insert(TenantContext(tenant_id.filter(|s| !s.is_empty())));

    Ok(next.run(request).await)
}

/// Decode a JWT payload without signature verification and return the `tenant_id` claim.
///
/// This is intentionally unverified — it is used only for routing/context injection.
/// Cryptographic verification of the full SEAL token is performed later inside
/// `InvocationService::invoke_seal` via `verify_and_extract`.
fn decode_jwt_tenant_id_unverified(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    claims
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
}

/// Extracted tenant identity from an authenticated request (ADR-056).
#[derive(Debug, Clone)]
pub struct TenantContext(pub Option<String>);

fn check_operator_role(
    claims: &crate::infrastructure::jwks_validator::JwtClaims,
    claim_name: &str,
) -> Result<Option<String>, axum::http::StatusCode> {
    match claims.get_claim(claim_name).as_deref() {
        Some("aegis:admin") | Some("aegis:operator") => Ok(claims.tenant_id.clone()),
        Some(role) => {
            tracing::warn!(role = %role, "Insufficient role for SEAL operator access");
            Err(axum::http::StatusCode::FORBIDDEN)
        }
        None => {
            tracing::warn!("Missing {} claim in operator JWT", claim_name);
            Err(axum::http::StatusCode::FORBIDDEN)
        }
    }
}

pub async fn verify_operator_token(
    config: &GatewayConfig,
    token: &str,
) -> Result<Option<String>, StatusCode> {
    let claims = config
        .jwks_validator
        .validate(
            token,
            &config.operator_jwt_issuer,
            &config.operator_jwt_audience,
        )
        .await?;
    check_operator_role(&claims, &config.operator_role_claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::jwks_validator::JwtClaims;
    use std::collections::HashMap;

    fn claims_with_role(claim_name: &str, role: &str) -> JwtClaims {
        let mut extra = HashMap::new();
        if claim_name != "aegis_role" {
            extra.insert(
                claim_name.to_owned(),
                serde_json::Value::String(role.to_owned()),
            );
            JwtClaims {
                aegis_role: None,
                tenant_id: Some("tenant-x".to_owned()),
                extra,
            }
        } else {
            JwtClaims {
                aegis_role: Some(role.to_owned()),
                tenant_id: Some("tenant-x".to_owned()),
                extra,
            }
        }
    }

    fn claims_without_role() -> JwtClaims {
        JwtClaims {
            aegis_role: None,
            tenant_id: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn test_role_check_admin() {
        let claims = claims_with_role("aegis_role", "aegis:admin");
        let result = check_operator_role(&claims, "aegis_role");
        assert!(result.is_ok());
    }

    #[test]
    fn test_role_check_operator() {
        let claims = claims_with_role("aegis_role", "aegis:operator");
        let result = check_operator_role(&claims, "aegis_role");
        assert!(result.is_ok());
    }

    #[test]
    fn test_role_check_wrong_role() {
        let claims = claims_with_role("aegis_role", "aegis:viewer");
        let result = check_operator_role(&claims, "aegis_role");
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_role_check_missing_claim() {
        let claims = claims_without_role();
        let result = check_operator_role(&claims, "aegis_role");
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_role_check_custom_claim_name() {
        let claims = claims_with_role("my_role", "aegis:admin");
        let result = check_operator_role(&claims, "my_role");
        assert!(result.is_ok());
    }
}
