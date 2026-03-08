use std::env;

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub bind_addr: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub auth_disabled: bool,
    pub smcp_token_secret: String,
}

impl GatewayConfig {
    pub fn from_env() -> Self {
        let bind_addr =
            env::var("SMCP_GATEWAY_BIND").unwrap_or_else(|_| "0.0.0.0:8089".to_string());
        let database_url =
            env::var("SMCP_GATEWAY_DB").unwrap_or_else(|_| "sqlite://gateway.db".to_string());
        let jwt_secret =
            env::var("SMCP_GATEWAY_JWT_SECRET").unwrap_or_else(|_| "dev-secret".to_string());
        let smcp_token_secret = env::var("SMCP_GATEWAY_SMCP_TOKEN_SECRET")
            .unwrap_or_else(|_| "smcp-dev-secret".to_string());
        let auth_disabled = env::var("SMCP_GATEWAY_AUTH_DISABLED")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            bind_addr,
            database_url,
            jwt_secret,
            auth_disabled,
            smcp_token_secret,
        }
    }
}
