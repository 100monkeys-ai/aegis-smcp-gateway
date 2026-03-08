use crate::domain::EphemeralCliTool;

#[derive(Debug, Clone)]
pub enum SemanticDecision {
    Allowed,
    Rejected(String),
}

#[derive(Clone)]
pub struct SemanticGate;

impl SemanticGate {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(
        &self,
        tool: &EphemeralCliTool,
        subcommand: &str,
        args: &[String],
    ) -> SemanticDecision {
        if !tool.allowed_subcommands.iter().any(|s| s == subcommand) {
            return SemanticDecision::Rejected(format!(
                "subcommand '{subcommand}' is not in allowed_subcommands"
            ));
        }

        if tool.require_semantic_judge {
            let joined = args.join(" ");
            if joined.contains("-destroy") || joined.contains(" destroy ") {
                return SemanticDecision::Rejected(
                    "semantic judge rejected destructive command intent".to_string(),
                );
            }
        }

        SemanticDecision::Allowed
    }
}
