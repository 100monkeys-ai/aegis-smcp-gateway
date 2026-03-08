use async_trait::async_trait;

use crate::infrastructure::errors::GatewayError;

pub mod postgres;
pub mod sqlite;

#[async_trait]
pub trait EventStore: Send + Sync {
    async fn append_event(
        &self,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<(), GatewayError>;
}
