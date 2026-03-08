use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;

use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::application::semantic_gate::{SemanticDecision, SemanticGate};
use crate::domain::{EphemeralCliToolRepository, GatewayEvent};
use crate::infrastructure::errors::GatewayError;
use crate::infrastructure::persistence::sqlite::SqliteStore;

#[derive(Clone)]
pub struct CliEngine {
    cli_tools: Arc<dyn EphemeralCliToolRepository>,
    semantic_gate: SemanticGate,
    store: SqliteStore,
}

pub struct CliInvocation {
    pub execution_id: String,
    pub tool_name: String,
    pub command: String,
    pub args: Vec<String>,
    pub workspace_path: Option<String>,
}

impl CliEngine {
    pub fn new(
        cli_tools: Arc<dyn EphemeralCliToolRepository>,
        semantic_gate: SemanticGate,
        store: SqliteStore,
    ) -> Self {
        Self {
            cli_tools,
            semantic_gate,
            store,
        }
    }

    pub async fn invoke(
        &self,
        invocation: CliInvocation,
    ) -> Result<serde_json::Value, GatewayError> {
        let tool = self
            .cli_tools
            .find_by_name(&invocation.tool_name)
            .await?
            .ok_or_else(|| GatewayError::NotFound("CLI tool not found".to_string()))?;

        match self
            .semantic_gate
            .evaluate(&tool, &invocation.command, &invocation.args)
        {
            SemanticDecision::Rejected(reason) => {
                self.store
                    .append_event(
                        "CliToolSemanticRejected",
                        &serde_json::to_value(GatewayEvent::CliToolSemanticRejected {
                            execution_id: invocation.execution_id,
                            tool_name: tool.name,
                            requested_subcommand: invocation.command,
                            rejection_reason: reason.clone(),
                            security_context: "unknown".to_string(),
                            rejected_at: chrono::Utc::now(),
                        })?,
                    )
                    .await?;
                return Err(GatewayError::Forbidden);
            }
            SemanticDecision::Allowed => {}
        }

        self.store
            .append_event(
                "CliToolInvocationStarted",
                &serde_json::to_value(GatewayEvent::CliToolInvocationStarted {
                    execution_id: invocation.execution_id.clone(),
                    tool_name: tool.name.clone(),
                    docker_image: tool.docker_image.clone(),
                    command: invocation.command.clone(),
                    args: invocation.args.clone(),
                    started_at: chrono::Utc::now(),
                })?,
            )
            .await?;

        let mut cmd = Command::new("docker");
        cmd.arg("run")
            .arg("--rm")
            .arg("--network")
            .arg("none")
            .arg("--read-only")
            .arg("--cap-drop")
            .arg("ALL");

        if let Some(workspace) = invocation.workspace_path {
            cmd.arg("-v")
                .arg(format!("{workspace}:/workspace"))
                .arg("-w")
                .arg("/workspace");
        }

        cmd.arg(&tool.docker_image)
            .arg(&invocation.command)
            .args(&invocation.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let start = Instant::now();
        let mut child = cmd
            .spawn()
            .map_err(|e| GatewayError::Internal(format!("failed to spawn docker: {e}")))?;

        let timeout = std::time::Duration::from_secs(tool.default_timeout_seconds as u64);
        let output = tokio::time::timeout(timeout, async move {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut out) = child.stdout.take() {
                let _ = out.read_to_end(&mut stdout).await;
            }
            if let Some(mut err) = child.stderr.take() {
                let _ = err.read_to_end(&mut stderr).await;
            }
            let status = child.wait().await;
            (stdout, stderr, status)
        })
        .await
        .map_err(|_| GatewayError::Internal("cli invocation timeout".to_string()))?;

        let (mut stdout, mut stderr, status_res) = output;
        if stdout.len() > 1_048_576 {
            stdout.truncate(1_048_576);
        }
        if stderr.len() > 1_048_576 {
            stderr.truncate(1_048_576);
        }

        let status = status_res
            .map_err(|e| GatewayError::Internal(format!("failed to wait process: {e}")))?;
        let code = status.code().unwrap_or(-1);

        self.store
            .append_event(
                "CliToolInvocationCompleted",
                &serde_json::to_value(GatewayEvent::CliToolInvocationCompleted {
                    execution_id: invocation.execution_id,
                    tool_name: tool.name,
                    exit_code: code,
                    stdout_bytes: stdout.len(),
                    stderr_bytes: stderr.len(),
                    duration_ms: start.elapsed().as_millis() as u64,
                    completed_at: chrono::Utc::now(),
                })?,
            )
            .await?;

        Ok(json!({
            "exit_code": code,
            "stdout": String::from_utf8_lossy(&stdout).to_string(),
            "stderr": String::from_utf8_lossy(&stderr).to_string()
        }))
    }
}
