//! `sigil-mcp --print-config [codex|claude]` — emit a ready-to-paste MCP client
//! config block that pins the **absolute** path of this binary
//! (`std::env::current_exe()`), so registration works even when the client
//! doesn't see the user's interactive-shell PATH (#72).

/// Supported clients (and their aliases) for `render_config`.
pub const CLIENTS: &str = "codex, claude";

fn codex_block(exe: &str) -> String {
    format!(
        "# Codex — add to ~/.codex/config.toml\n\
         [mcp_servers.sigil-fleet]\n\
         command = \"{exe}\"\n\
         # Fleet mode — point at your sigil-server's read API:\n\
         env = {{ SIGIL_SERVER_BASE_URL = \"https://your-sigil-server:PORT\", SIGIL_SERVER_READ_TOKEN = \"your-read-token\" }}\n\
         # Local mode (this host's own posture, no server): delete the env line.\n"
    )
}

fn claude_block(exe: &str) -> String {
    format!(
        "// Claude Code / Claude Desktop — \"mcpServers\" entry\n\
         {{\n  \"mcpServers\": {{\n    \"sigil-fleet\": {{\n      \"command\": \"{exe}\",\n      \"env\": {{\n        \"SIGIL_SERVER_BASE_URL\": \"https://your-sigil-server:PORT\",\n        \"SIGIL_SERVER_READ_TOKEN\": \"your-read-token\"\n      }}\n    }}\n  }}\n}}\n// Local mode (this host's own posture, no server): omit the \"env\" object.\n"
    )
}

/// Render a config block for `client` (None = all clients) with `exe` as the
/// command path. Returns Err with a usage hint for an unknown client.
pub fn render_config(exe: &str, client: Option<&str>) -> Result<String, String> {
    match client {
        None => Ok(format!("{}\n{}", codex_block(exe), claude_block(exe))),
        Some("codex") => Ok(codex_block(exe)),
        Some("claude") | Some("claude-code") | Some("claude-desktop") => Ok(claude_block(exe)),
        Some(other) => Err(format!(
            "unknown client '{other}' — supported: {CLIENTS} (or omit for all)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_uses_absolute_exe_path_and_toml_table() {
        let out = render_config("/opt/sigil/sigil-mcp", Some("codex")).unwrap();
        assert!(out.contains("[mcp_servers.sigil-fleet]"));
        assert!(out.contains("command = \"/opt/sigil/sigil-mcp\""));
        assert!(out.contains("SIGIL_SERVER_BASE_URL"));
    }

    #[test]
    fn claude_aliases_render_json_with_exe() {
        for c in ["claude", "claude-code", "claude-desktop"] {
            let out = render_config("/abs/sigil-mcp", Some(c)).unwrap();
            assert!(out.contains("\"mcpServers\""), "{c}");
            assert!(out.contains("\"command\": \"/abs/sigil-mcp\""), "{c}");
        }
    }

    #[test]
    fn no_client_renders_both() {
        let out = render_config("/x/sigil-mcp", None).unwrap();
        assert!(out.contains("[mcp_servers.sigil-fleet]"));
        assert!(out.contains("\"mcpServers\""));
    }

    #[test]
    fn unknown_client_is_error_with_hint() {
        let err = render_config("/x/sigil-mcp", Some("nano")).unwrap_err();
        assert!(err.contains("unknown client 'nano'"));
        assert!(err.contains("codex"));
    }
}
