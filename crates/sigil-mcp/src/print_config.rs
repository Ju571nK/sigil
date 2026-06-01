//! `sigil-mcp --print-config [codex|claude]` — emit a ready-to-paste MCP client
//! config block that pins the **absolute** path of this binary
//! (`std::env::current_exe()`), so registration works even when the client
//! doesn't see the user's interactive-shell PATH (#72).
//!
//! The default registration is `sigil-check`: this host's own posture, single
//! host, no server required. The fleet-wide `sigil-fleet` view is for operators
//! (run beside sigil-server / sigil-manager) and is shown as a commented add-on,
//! never as the default an AI coding agent gets.

/// Supported clients (and their aliases) for `render_config`.
pub const CLIENTS: &str = "codex, claude";

fn codex_block(exe: &str) -> String {
    format!(
        "# Codex — add to ~/.codex/config.toml\n\
         # sigil-check — THIS host's own Sigil posture (single host, no server):\n\
         [mcp_servers.sigil-check]\n\
         command = \"{exe}\"\n\
         \n\
         # Operators only — fleet-wide view via your sigil-server's read API.\n\
         # Register this as a SECOND server beside sigil-server / sigil-manager;\n\
         # don't replace sigil-check above.\n\
         # [mcp_servers.sigil-fleet]\n\
         # command = \"{exe}\"\n\
         # env = {{ SIGIL_SERVER_BASE_URL = \"https://your-sigil-server:PORT\", SIGIL_SERVER_READ_TOKEN = \"your-read-token\" }}\n"
    )
}

fn claude_block(exe: &str) -> String {
    format!(
        "// Claude Code / Claude Desktop — \"mcpServers\" entry\n\
         // sigil-check — THIS host's own Sigil posture (single host, no server):\n\
         {{\n  \"mcpServers\": {{\n    \"sigil-check\": {{\n      \"command\": \"{exe}\"\n    }}\n  }}\n}}\n\
         // Operators only — fleet-wide view via your sigil-server's read API. Add a\n\
         // SECOND entry \"sigil-fleet\" with command \"{exe}\" and env\n\
         // SIGIL_SERVER_BASE_URL + SIGIL_SERVER_READ_TOKEN pointing at your\n\
         // sigil-server; don't replace sigil-check above.\n"
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
    fn codex_defaults_to_single_host_check_with_absolute_exe() {
        let out = render_config("/opt/sigil/sigil-mcp", Some("codex")).unwrap();
        // sigil-check is the active (uncommented) default; no server env on it.
        assert!(out.contains("[mcp_servers.sigil-check]"));
        assert!(out.contains("command = \"/opt/sigil/sigil-mcp\""));
        // Fleet is present only as a commented operator add-on.
        assert!(out.contains("# [mcp_servers.sigil-fleet]"));
        assert!(out.contains("SIGIL_SERVER_BASE_URL"));
    }

    #[test]
    fn claude_aliases_render_check_json_with_exe() {
        for c in ["claude", "claude-code", "claude-desktop"] {
            let out = render_config("/abs/sigil-mcp", Some(c)).unwrap();
            assert!(out.contains("\"mcpServers\""), "{c}");
            assert!(out.contains("\"sigil-check\""), "{c}");
            assert!(out.contains("\"command\": \"/abs/sigil-mcp\""), "{c}");
        }
    }

    #[test]
    fn no_client_renders_both() {
        let out = render_config("/x/sigil-mcp", None).unwrap();
        assert!(out.contains("[mcp_servers.sigil-check]"));
        assert!(out.contains("\"mcpServers\""));
    }

    #[test]
    fn unknown_client_is_error_with_hint() {
        let err = render_config("/x/sigil-mcp", Some("nano")).unwrap_err();
        assert!(err.contains("unknown client 'nano'"));
        assert!(err.contains("codex"));
    }
}
