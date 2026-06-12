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
pub const CLIENTS: &str = "codex, claude, hermes, openclaw";

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

// Hermes Agent (NousResearch) registers MCP servers in `config.yaml` under
// `mcp_servers:`; each becomes an auto-discovered `mcp-<server>` toolset. The
// `assess` tool then lets a Hermes task pre-flight a command/MCP server against
// this host's loaded Sigil policy.
fn hermes_block(exe: &str) -> String {
    format!(
        "# Hermes Agent — add to your config.yaml\n\
         # sigil-check — THIS host's own Sigil posture (single host, no server):\n\
         mcp_servers:\n  \
           sigil-check:\n    \
             command: \"{exe}\"\n\
         # Hermes auto-discovers this server's tools as the `mcp-sigil-check`\n\
         # toolset (includes `assess`). Enable it for a platform, e.g.:\n\
         #   platform_toolsets:\n\
         #     cli: [hermes-cli, mcp-sigil-check]\n\
         #\n\
         # Operators only — fleet-wide view: add a SECOND server `sigil-fleet`\n\
         # with the same command plus env SIGIL_SERVER_BASE_URL +\n\
         # SIGIL_SERVER_READ_TOKEN; don't replace sigil-check above.\n"
    )
}

// OpenClaw registers MCP servers in `~/.openclaw/openclaw.json` under
// `mcpServers` (same JSON convention as Claude). A SKILL.md drives WHEN to call
// the `assess` tool; a skill can alternatively shell out to `sigil assess`.
fn openclaw_block(exe: &str) -> String {
    format!(
        "// OpenClaw — add to ~/.openclaw/openclaw.json\n\
         // sigil-check — THIS host's own Sigil posture (single host, no server):\n\
         {{\n  \"mcpServers\": {{\n    \"sigil-check\": {{\n      \"command\": \"{exe}\"\n    }}\n  }}\n}}\n\
         // The `assess` tool lets a skill pre-flight a command/MCP server before\n\
         // acting. See examples/integrations/openclaw/SKILL.md for a ready-to-use\n\
         // skill (it can also call `sigil assess` via the CLI — no MCP wiring).\n\
         //\n\
         // Operators only — fleet-wide view: add a SECOND entry \"sigil-fleet\" with\n\
         // the same command and env SIGIL_SERVER_BASE_URL + SIGIL_SERVER_READ_TOKEN.\n"
    )
}

/// Render a config block for `client` (None = all clients) with `exe` as the
/// command path. Returns Err with a usage hint for an unknown client.
pub fn render_config(exe: &str, client: Option<&str>) -> Result<String, String> {
    match client {
        None => Ok(format!(
            "{}\n{}\n{}\n{}",
            codex_block(exe),
            claude_block(exe),
            hermes_block(exe),
            openclaw_block(exe)
        )),
        Some("codex") => Ok(codex_block(exe)),
        Some("claude") | Some("claude-code") | Some("claude-desktop") => Ok(claude_block(exe)),
        Some("hermes") | Some("hermes-agent") => Ok(hermes_block(exe)),
        Some("openclaw") => Ok(openclaw_block(exe)),
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
    fn no_client_renders_all() {
        let out = render_config("/x/sigil-mcp", None).unwrap();
        assert!(out.contains("[mcp_servers.sigil-check]")); // codex (TOML)
        assert!(out.contains("\"mcpServers\"")); // claude / openclaw (JSON)
        assert!(out.contains("mcp_servers:")); // hermes (YAML)
        assert!(out.contains("~/.openclaw/openclaw.json")); // openclaw
    }

    #[test]
    fn hermes_renders_yaml_mcp_servers_with_exe() {
        for c in ["hermes", "hermes-agent"] {
            let out = render_config("/abs/sigil-mcp", Some(c)).unwrap();
            assert!(out.contains("mcp_servers:"), "{c}");
            assert!(out.contains("sigil-check:"), "{c}");
            assert!(out.contains("command: \"/abs/sigil-mcp\""), "{c}");
            // The auto-generated toolset name is documented.
            assert!(out.contains("mcp-sigil-check"), "{c}");
        }
    }

    #[test]
    fn openclaw_renders_mcpservers_json_with_exe_and_skill_pointer() {
        let out = render_config("/abs/sigil-mcp", Some("openclaw")).unwrap();
        assert!(out.contains("~/.openclaw/openclaw.json"));
        assert!(out.contains("\"mcpServers\""));
        assert!(out.contains("\"sigil-check\""));
        assert!(out.contains("\"command\": \"/abs/sigil-mcp\""));
        // Points at the CLI/SKILL.md path too.
        assert!(out.contains("sigil assess") || out.contains("SKILL.md"));
    }

    #[test]
    fn unknown_client_is_error_with_hint() {
        let err = render_config("/x/sigil-mcp", Some("nano")).unwrap_err();
        assert!(err.contains("unknown client 'nano'"));
        assert!(err.contains("codex"));
        assert!(err.contains("hermes"));
        assert!(err.contains("openclaw"));
    }
}
