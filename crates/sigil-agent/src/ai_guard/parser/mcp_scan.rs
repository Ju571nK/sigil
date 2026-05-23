//! Phase 3b.8 — shared MCP-object scanner for the Gemini + Cursor JSON
//! parsers. Walks an `mcpServers` object and emits remote / local-command /
//! destructive-arg reasons. Standalone (continue_dev keeps its own copy).

use crate::ai_guard::rubric;
use serde_json::Value;
use sigil_core::event::AiGuardReason;

/// Walk `settings.mcpServers` (object keyed by server name) and push reasons.
/// Both `url`/`httpUrl` remote and `command` local are evaluated INDEPENDENTLY
/// (no short-circuit) so a malformed server with both fields emits both.
pub fn emit_mcp_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(obj) = settings.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (name, def) in obj {
        for key in ["url", "httpUrl"] {
            if let Some(u) = def.get(key).and_then(Value::as_str) {
                if scheme_is_http(u) {
                    out.push(AiGuardReason::McpServerRemote {
                        server_name: name.clone(),
                        url: u.to_string(),
                    });
                }
            }
        }
        if def.get("trust").and_then(Value::as_bool) == Some(true) {
            out.push(AiGuardReason::TrustedMcpServer {
                server_name: name.clone(),
            });
        }
        if let Some(command) = def.get("command").and_then(Value::as_str) {
            out.push(AiGuardReason::McpServerLocalCommand {
                server_name: name.clone(),
                command: command.to_string(),
            });
            out.push(AiGuardReason::NoSandbox {
                executor: "mcp_command".into(),
            });
            if is_shell(command) {
                if let Some(args) = def.get("args").and_then(Value::as_array) {
                    if let Some(snippet) = first_destructive_after_shell_flag(args) {
                        if let Some(pat) = rubric::first_destructive_pattern(&snippet) {
                            out.push(AiGuardReason::DestructiveInInlineCommand {
                                pattern: pat.to_string(),
                                hook_event: "mcp_command".into(),
                                snippet: snippet.chars().take(80).collect(),
                            });
                        }
                    }
                }
            }
        }
    }
}

/// True iff the URL scheme (lowercased) is http/https. Lowercasing defeats
/// `HTTP://` evasion.
fn scheme_is_http(u: &str) -> bool {
    let lower = u.trim_start().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn is_shell(cmd: &str) -> bool {
    matches!(
        cmd.rsplit(['/', '\\']).next().unwrap_or(cmd),
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
    )
}

/// Returns the argument following a shell command flag (`-c`, `/c`, `/C`,
/// `-Command`) — the inline script body.
fn first_destructive_after_shell_flag(args: &[Value]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        let Some(s) = a.as_str() else { continue };
        if matches!(s, "-c" | "/c" | "/C" | "-Command") {
            if let Some(next) = iter.next().and_then(Value::as_str) {
                return Some(next.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reasons(v: serde_json::Value) -> Vec<AiGuardReason> {
        let mut out = Vec::new();
        emit_mcp_reasons(&v, &mut out);
        out
    }

    #[test]
    fn remote_url_emits_remote() {
        let r = reasons(json!({"mcpServers":{"a":{"url":"https://x"}}}));
        assert!(r.iter().any(
            |x| matches!(x, AiGuardReason::McpServerRemote { server_name, .. } if server_name=="a")
        ));
    }
    #[test]
    fn http_url_field_emits_remote() {
        let r = reasons(json!({"mcpServers":{"a":{"httpUrl":"https://x/mcp"}}}));
        assert!(r
            .iter()
            .any(|x| matches!(x, AiGuardReason::McpServerRemote { .. })));
    }
    #[test]
    fn uppercase_scheme_still_detected() {
        let r = reasons(json!({"mcpServers":{"a":{"url":"HTTP://x"}}}));
        assert!(r
            .iter()
            .any(|x| matches!(x, AiGuardReason::McpServerRemote { .. })));
    }
    #[test]
    fn local_command_emits_local_and_nosandbox() {
        let r = reasons(json!({"mcpServers":{"a":{"command":"node","args":["m.js"]}}}));
        assert!(r
            .iter()
            .any(|x| matches!(x, AiGuardReason::McpServerLocalCommand { .. })));
        assert!(r.iter().any(
            |x| matches!(x, AiGuardReason::NoSandbox { executor } if executor=="mcp_command")
        ));
    }
    #[test]
    fn shell_args_destructive_scanned() {
        let r = reasons(
            json!({"mcpServers":{"a":{"command":"bash","args":["-c","rm -rf /tmp/sigil-test"]}}}),
        );
        assert!(r.iter().any(|x| matches!(x, AiGuardReason::DestructiveInInlineCommand { hook_event, .. } if hook_event=="mcp_command")));
    }
    #[test]
    fn cmd_exe_slash_c_scanned() {
        let r = reasons(
            json!({"mcpServers":{"a":{"command":"cmd.exe","args":["/c","rm -rf /tmp/sigil-test"]}}}),
        );
        assert!(r
            .iter()
            .any(|x| matches!(x, AiGuardReason::DestructiveInInlineCommand { .. })));
    }
    #[test]
    fn both_url_and_command_emit_both() {
        let r = reasons(json!({"mcpServers":{"a":{"url":"https://x","command":"node"}}}));
        assert!(r
            .iter()
            .any(|x| matches!(x, AiGuardReason::McpServerRemote { .. })));
        assert!(r
            .iter()
            .any(|x| matches!(x, AiGuardReason::McpServerLocalCommand { .. })));
    }
    #[test]
    fn trust_true_emits_trusted() {
        let r = reasons(json!({"mcpServers":{"a":{"command":"node","trust":true}}}));
        assert!(r.iter().any(
            |x| matches!(x, AiGuardReason::TrustedMcpServer { server_name } if server_name=="a")
        ));
    }
    #[test]
    fn no_mcp_servers_emits_nothing() {
        assert!(reasons(json!({})).is_empty());
    }
    #[test]
    fn safe_local_command_no_destructive() {
        let r = reasons(json!({"mcpServers":{"a":{"command":"bash","args":["-c","echo hi"]}}}));
        assert!(!r
            .iter()
            .any(|x| matches!(x, AiGuardReason::DestructiveInInlineCommand { .. })));
    }
}
