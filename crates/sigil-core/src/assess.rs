//! Shared types for the `assess` primitive — score a proposed shell command or
//! MCP server definition against the host's loaded policy.
//!
//! Used by `sigil-agent` (engine) and `sigil-mcp` (client).

use serde::{Deserialize, Serialize};

use crate::event::{AiGuardBucket, AiGuardReason};

/// Input to the assess engine: either a shell command or an MCP server
/// definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AssessInput {
    /// A proposed shell command with its arguments.
    Command { command: String, args: Vec<String> },
    /// A proposed MCP server definition (name + raw JSON definition object).
    McpServer {
        server_name: String,
        definition: serde_json::Value,
    },
}

/// The assess engine's verdict on a proposed action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Warn,
    Deny,
}

/// A matched deny rule contributing to the verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DenyMatch {
    pub rule_id: String,
    pub reason: String,
}

/// The full verdict returned by the assess engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssessVerdict {
    pub bucket: AiGuardBucket,
    pub score: f32,
    pub reasons: Vec<AiGuardReason>,
    pub deny_match: Option<DenyMatch>,
    pub decision: Decision,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AiGuardBucket, AiGuardReason};

    #[test]
    fn assess_input_command_serde_round_trip() {
        let input = AssessInput::Command {
            command: "rm".to_string(),
            args: vec!["-rf".to_string(), "/tmp/foo".to_string()],
        };
        let json = serde_json::to_string(&input).expect("serialize");
        let back: AssessInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, input);
        // Verify the kind tag is present
        assert!(json.contains("\"kind\":\"command\""), "got: {json}");
        assert!(json.contains("\"command\":\"rm\""), "got: {json}");
    }

    #[test]
    fn assess_input_mcp_serde_round_trip() {
        let input = AssessInput::McpServer {
            server_name: "my-mcp".to_string(),
            definition: serde_json::json!({
                "transport": "stdio",
                "command": "node",
                "args": ["/usr/local/lib/mcp-server/index.js"]
            }),
        };
        let json = serde_json::to_string(&input).expect("serialize");
        let back: AssessInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, input);
        assert!(json.contains("\"kind\":\"mcp_server\""), "got: {json}");
        assert!(json.contains("\"server_name\":\"my-mcp\""), "got: {json}");
    }

    #[test]
    fn assess_verdict_serde_round_trip() {
        let verdict = AssessVerdict {
            bucket: AiGuardBucket::High,
            score: 6.5,
            reasons: vec![AiGuardReason::NoSandbox {
                executor: "host_shell".to_string(),
            }],
            deny_match: Some(DenyMatch {
                rule_id: "no-rm-rf-root".to_string(),
                reason: "destructive command targeting root".to_string(),
            }),
            decision: Decision::Deny,
        };
        let json = serde_json::to_string(&verdict).expect("serialize");
        let back: AssessVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, verdict);
        assert_eq!(back.bucket, AiGuardBucket::High);
        assert_eq!(back.score, 6.5);
        assert_eq!(back.decision, Decision::Deny);
        assert!(back.deny_match.is_some());
        assert_eq!(back.reasons.len(), 1);
    }

    #[test]
    fn decision_wire_format() {
        assert_eq!(serde_json::to_string(&Decision::Deny).unwrap(), "\"deny\"");
        assert_eq!(
            serde_json::to_string(&Decision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(serde_json::to_string(&Decision::Warn).unwrap(), "\"warn\"");
    }
}
