use std::env;

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub bind_addr: String,
    pub grpc_bind_addr: String,
    pub database_url: String,
    pub operator_jwt_public_key_pem: String,
    pub operator_jwt_issuer: String,
    pub operator_jwt_audience: String,
    pub auth_disabled: bool,
    pub smcp_jwt_public_key_pem: String,
    pub smcp_jwt_issuer: String,
    pub smcp_jwt_audience: String,
    pub openbao_addr: Option<String>,
    pub openbao_token: Option<String>,
    pub openbao_kv_mount: String,
    pub keycloak_token_exchange_url: Option<String>,
    pub keycloak_client_id: Option<String>,
    pub keycloak_client_secret: Option<String>,
    pub semantic_judge_url: Option<String>,
    pub ui_enabled: bool,
    pub nfs_server_host: String,
    pub nfs_port: u16,
    pub nfs_mount_port: u16,
}

impl GatewayConfig {
    pub fn from_env() -> Self {
        let bind_addr =
            env::var("SMCP_GATEWAY_BIND").unwrap_or_else(|_| "0.0.0.0:8089".to_string());
        let grpc_bind_addr =
            env::var("SMCP_GATEWAY_GRPC_BIND").unwrap_or_else(|_| "0.0.0.0:50055".to_string());
        let database_url =
            env::var("SMCP_GATEWAY_DB").unwrap_or_else(|_| "sqlite://gateway.db".to_string());
        let operator_jwt_public_key_pem =
            env::var("SMCP_GATEWAY_OPERATOR_JWT_PUBLIC_KEY_PEM").unwrap_or_else(|_| String::new());
        let operator_jwt_issuer = env::var("SMCP_GATEWAY_OPERATOR_JWT_ISSUER")
            .unwrap_or_else(|_| "aegis-keycloak".to_string());
        let operator_jwt_audience = env::var("SMCP_GATEWAY_OPERATOR_JWT_AUDIENCE")
            .unwrap_or_else(|_| "aegis-smcp-gateway".to_string());
        let smcp_jwt_public_key_pem =
            env::var("SMCP_GATEWAY_SMCP_JWT_PUBLIC_KEY_PEM").unwrap_or_else(|_| String::new());
        let smcp_jwt_issuer = env::var("SMCP_GATEWAY_SMCP_JWT_ISSUER")
            .unwrap_or_else(|_| "aegis-orchestrator".to_string());
        let smcp_jwt_audience = env::var("SMCP_GATEWAY_SMCP_JWT_AUDIENCE")
            .unwrap_or_else(|_| "aegis-agents".to_string());
        let openbao_addr = env::var("SMCP_GATEWAY_OPENBAO_ADDR")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let openbao_token = env::var("SMCP_GATEWAY_OPENBAO_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let openbao_kv_mount =
            env::var("SMCP_GATEWAY_OPENBAO_KV_MOUNT").unwrap_or_else(|_| "secret".to_string());
        let keycloak_token_exchange_url = env::var("SMCP_GATEWAY_KEYCLOAK_TOKEN_EXCHANGE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let keycloak_client_id = env::var("SMCP_GATEWAY_KEYCLOAK_CLIENT_ID")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let keycloak_client_secret = env::var("SMCP_GATEWAY_KEYCLOAK_CLIENT_SECRET")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let semantic_judge_url = env::var("SMCP_GATEWAY_SEMANTIC_JUDGE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let ui_enabled = env::var("SMCP_GATEWAY_UI_ENABLED")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let nfs_server_host =
            env::var("SMCP_GATEWAY_NFS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let nfs_port = env::var("SMCP_GATEWAY_NFS_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(2049);
        let nfs_mount_port = env::var("SMCP_GATEWAY_NFS_MOUNT_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(20048);
        let auth_disabled = env::var("SMCP_GATEWAY_AUTH_DISABLED")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            bind_addr,
            grpc_bind_addr,
            database_url,
            operator_jwt_public_key_pem,
            operator_jwt_issuer,
            operator_jwt_audience,
            auth_disabled,
            smcp_jwt_public_key_pem,
            smcp_jwt_issuer,
            smcp_jwt_audience,
            openbao_addr,
            openbao_token,
            openbao_kv_mount,
            keycloak_token_exchange_url,
            keycloak_client_id,
            keycloak_client_secret,
            semantic_judge_url,
            ui_enabled,
            nfs_server_host,
            nfs_port,
            nfs_mount_port,
        }
    }
}
