//! Handler for `sigil assess` — cold-disk pre-flight verdict (#149 Task 6).
//!
//! Evaluates a proposed command or single MCP server definition against the
//! host's loaded policy (cold-disk, no daemon required) and prints a JSON
//! verdict on stdout.
//!
//! # Exit codes
//! | Condition                              | Code |
//! |----------------------------------------|------|
//! | `Allow`                                | 0    |
//! | `Warn` (without `--fail-on-warn`)      | 0    |
//! | `Warn` (with `--fail-on-warn`)         | 2    |
//! | `Deny`                                 | 2    |
//! | Usage / input / policy-load error      | 1    |
//!
//! # Fail-closed
//! Malformed or oversize input → exit 1. Policy-load failure → exit 1.
//! NEVER produce an Allow verdict for malformed input.

use crate::ai_guard::assess::{assess, AssessCtx};
use crate::effective_policy::load_effective_policy;
use sigil_core::assess::{AssessInput, AssessVerdict, Decision};
use std::io::Read;
use std::path::{Path, PathBuf};

// ── Input size limits (fail-closed) ──────────────────────────────────────────
const MAX_COMMAND_BYTES: usize = 16_384;
const MAX_ARG_COUNT: usize = 64;
const MAX_ARG_BYTES: usize = 8_192;
const MAX_MCP_BYTES: usize = 65_536;

/// Map a `Decision` (plus `--fail-on-warn` flag) to a process exit code.
///
/// This is a pure function — unit-tested in the `#[cfg(test)]` block below.
pub fn exit_code(decision: Decision, fail_on_warn: bool) -> i32 {
    match decision {
        Decision::Allow => 0,
        Decision::Warn => {
            if fail_on_warn {
                2
            } else {
                0
            }
        }
        Decision::Deny => 2,
    }
}

/// Arguments for the `assess` subcommand, extracted from the clap parse.
pub struct AssessArgs {
    pub command: Option<String>,
    pub args: Vec<String>,
    pub mcp_config: Option<PathBuf>,
    pub mcp_stdin: bool,
    pub mcp_name: Option<String>,
    pub fail_on_warn: bool,
    pub policy_override: Option<PathBuf>,
}

/// Entry point called from `main.rs`. Returns a process exit code (0/1/2).
pub fn run(args: AssessArgs) -> i32 {
    // ── Step 1: validate XOR — exactly one input mode ────────────────────────
    let has_command = args.command.is_some();
    let has_mcp = args.mcp_config.is_some() || args.mcp_stdin;
    match (has_command, has_mcp) {
        (false, false) => {
            eprintln!("sigil assess: one of --command or (--mcp-config | --mcp-stdin) is required");
            return 1;
        }
        (true, true) => {
            eprintln!(
                "sigil assess: --command and --mcp-config/--mcp-stdin are mutually exclusive"
            );
            return 1;
        }
        _ => {}
    }

    // ── Step 2: build AssessInput with size limits ────────────────────────────
    let input = if has_command {
        let command = args.command.unwrap();
        if command.len() > MAX_COMMAND_BYTES {
            eprintln!(
                "sigil assess: --command exceeds {MAX_COMMAND_BYTES} byte limit ({} bytes)",
                command.len()
            );
            return 1;
        }
        if args.args.len() > MAX_ARG_COUNT {
            eprintln!(
                "sigil assess: too many --arg values ({} > {MAX_ARG_COUNT})",
                args.args.len()
            );
            return 1;
        }
        for (i, arg) in args.args.iter().enumerate() {
            if arg.len() > MAX_ARG_BYTES {
                eprintln!(
                    "sigil assess: --arg[{i}] exceeds {MAX_ARG_BYTES} byte limit ({} bytes)",
                    arg.len()
                );
                return 1;
            }
        }
        AssessInput::Command {
            command,
            args: args.args,
        }
    } else {
        // MCP mode
        let server_name = match args.mcp_name.as_deref() {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => {
                eprintln!("sigil assess: --mcp-name is required with --mcp-config/--mcp-stdin");
                return 1;
            }
        };

        let json_bytes = if args.mcp_stdin {
            // Read from stdin
            let mut buf = Vec::new();
            if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
                eprintln!("sigil assess: failed to read --mcp-stdin: {e}");
                return 1;
            }
            buf
        } else {
            // Read from file
            let path = args.mcp_config.as_ref().unwrap();
            match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!(
                        "sigil assess: cannot read --mcp-config {}: {e}",
                        path.display()
                    );
                    return 1;
                }
            }
        };

        if json_bytes.len() > MAX_MCP_BYTES {
            eprintln!(
                "sigil assess: MCP JSON exceeds {MAX_MCP_BYTES} byte limit ({} bytes)",
                json_bytes.len()
            );
            return 1;
        }

        // Parse and validate: must be a JSON object (not array, null, string…)
        let value: serde_json::Value = match serde_json::from_slice(&json_bytes) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("sigil assess: MCP JSON parse error: {e}");
                return 1;
            }
        };
        if !value.is_object() {
            eprintln!(
                "sigil assess: MCP JSON must be a JSON object (got {}); \
                 rejecting to avoid producing an Allow verdict for unexpected input",
                json_type_name(&value)
            );
            return 1;
        }

        AssessInput::McpServer {
            server_name,
            definition: value,
        }
    };

    // ── Step 3: load policy (fail-loud, exit 1 on error) ─────────────────────
    let (policy_path, rule_packs_path) = resolve_policy_paths(args.policy_override.as_deref());
    let (rubric, deny, enforce_bucket) = match load_effective_policy(&policy_path, &rule_packs_path)
    {
        Ok(triple) => triple,
        Err(e) => {
            eprintln!("sigil assess: policy load failed: {e}");
            return 1;
        }
    };

    // ── Step 4: assess ────────────────────────────────────────────────────────
    let ctx = AssessCtx {
        rubric: &rubric,
        deny: &deny,
        enforce_bucket,
    };
    let verdict: AssessVerdict = assess(&input, &ctx);

    // ── Step 5: emit one-line JSON, then exit ─────────────────────────────────
    match serde_json::to_string(&verdict) {
        Ok(line) => println!("{line}"),
        Err(e) => {
            eprintln!("sigil assess: failed to serialize verdict: {e}");
            return 1;
        }
    }

    exit_code(verdict.decision, args.fail_on_warn)
}

/// Return canonical `(policy.yaml, rule-packs.yaml)` paths, respecting an
/// optional `--policy` override from the global CLI. `rule-packs.yaml` lives
/// beside `policy.yaml` (same directory, different file name).
fn resolve_policy_paths(policy_override: Option<&Path>) -> (PathBuf, PathBuf) {
    let policy = policy_override
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_policy_yaml_path);
    let rule_packs = policy.with_file_name("rule-packs.yaml");
    (policy, rule_packs)
}

/// Platform-specific default for `policy.yaml`. Mirrors `runtime.rs`.
fn default_policy_yaml_path() -> PathBuf {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        PathBuf::from("/etc/sigil/policy.yaml")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\Sigil\policy.yaml")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/etc/sigil/policy.yaml")
    }
}

/// Human-readable name of the top-level JSON type (for error messages).
fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — pure functions only, no disk access
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::assess::Decision;

    // ── exit_code mapping ─────────────────────────────────────────────────────

    #[test]
    fn exit_code_allow_is_0() {
        assert_eq!(exit_code(Decision::Allow, false), 0);
        assert_eq!(exit_code(Decision::Allow, true), 0);
    }

    #[test]
    fn exit_code_deny_is_2() {
        assert_eq!(exit_code(Decision::Deny, false), 2);
        assert_eq!(exit_code(Decision::Deny, true), 2);
    }

    #[test]
    fn exit_code_warn_without_flag_is_0() {
        assert_eq!(exit_code(Decision::Warn, false), 0);
    }

    #[test]
    fn exit_code_warn_with_fail_on_warn_is_2() {
        assert_eq!(exit_code(Decision::Warn, true), 2);
    }

    // ── json_type_name ────────────────────────────────────────────────────────

    #[test]
    fn json_type_name_array() {
        let v = serde_json::json!([1, 2, 3]);
        assert_eq!(json_type_name(&v), "array");
    }

    #[test]
    fn json_type_name_null() {
        assert_eq!(json_type_name(&serde_json::Value::Null), "null");
    }

    #[test]
    fn json_type_name_object() {
        let v = serde_json::json!({"a": 1});
        assert_eq!(json_type_name(&v), "object");
    }

    // ── resolve_policy_paths ─────────────────────────────────────────────────

    #[test]
    fn resolve_policy_paths_uses_default_when_no_override() {
        let (policy, rule_packs) = resolve_policy_paths(None);
        // Must be something ending in policy.yaml and rule-packs.yaml
        assert!(
            policy.to_str().unwrap().ends_with("policy.yaml"),
            "default policy path should end in policy.yaml: {policy:?}"
        );
        assert!(
            rule_packs.to_str().unwrap().ends_with("rule-packs.yaml"),
            "rule-packs path should end in rule-packs.yaml: {rule_packs:?}"
        );
    }

    #[test]
    fn resolve_policy_paths_respects_override() {
        let tmp = tempfile::tempdir().unwrap();
        let custom = tmp.path().join("custom-policy.yaml");
        let (policy, rule_packs) = resolve_policy_paths(Some(&custom));
        assert_eq!(policy, custom);
        assert_eq!(rule_packs, tmp.path().join("rule-packs.yaml"));
    }

    // ── fail_on_warn plumbs through assess logic ──────────────────────────────
    // This test drives the pure `exit_code` function to verify the matrix is
    // exhaustive, without spawning the binary.

    #[test]
    fn exit_code_matrix_is_complete() {
        // All 6 cells of the (Decision × fail_on_warn) matrix
        assert_eq!(exit_code(Decision::Allow, false), 0);
        assert_eq!(exit_code(Decision::Allow, true), 0);
        assert_eq!(exit_code(Decision::Warn, false), 0);
        assert_eq!(exit_code(Decision::Warn, true), 2);
        assert_eq!(exit_code(Decision::Deny, false), 2);
        assert_eq!(exit_code(Decision::Deny, true), 2);
    }
}
