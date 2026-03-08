use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::infrastructure::config::GatewayConfig;

#[derive(Debug, Clone, Deserialize)]
struct JwtClaims {
    exp: usize,
    aegis_role: Option<String>,
}

pub async fn require_operator(
    State(config): State<GatewayConfig>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if config.auth_disabled {
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

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let claims = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;

    let _exp = claims.exp;
    let role = claims.aegis_role.unwrap_or_default();
    if role != "aegis:admin" && role != "aegis:operator" {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}
