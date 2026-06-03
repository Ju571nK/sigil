//! Phase 3b.7 — RulePackParser: generic AiGuardParser driven by a RulePack.

use crate::ai_guard::parser::{AiGuardParser, AssessError};
use crate::ai_guard::rule_pack::matcher::{compile_pack_regexes, matches_value, CompileError};
use crate::ai_guard::rule_pack::selector::{eval_json, eval_toml, MatchedValue};
use sigil_core::event::{AiGuardReason, AiGuardScope, AiTool};
use sigil_core::policy::{RuleFormat, RulePack, RulePackScope};
use std::path::{Path, PathBuf};

pub struct RulePackParser {
    pub pack: RulePack,
    /// Compiled regexes parallel to pack.rules (None when matcher != Regex).
    compiled_regexes: Vec<Option<regex::Regex>>,
    pub(crate) repo_root: Option<std::path::PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum PackLoadError {
    #[error("rule pack '{id}' regex compile failed: {source}")]
    Regex { id: String, source: CompileError },
}

impl RulePackParser {
    pub fn new(pack: RulePack) -> Result<Self, PackLoadError> {
        let compiled_regexes =
            compile_pack_regexes(&pack.rules).map_err(|e| PackLoadError::Regex {
                id: pack.id.clone(),
                source: e,
            })?;
        Ok(Self {
            pack,
            compiled_regexes,
            repo_root: None,
        })
    }

    /// Phase 3b.7.2 — a Project-scoped instance bound to one discovered repo.
    /// on_file / watched_paths are resolved relative to `repo_root`.
    pub fn new_project(
        pack: RulePack,
        repo_root: std::path::PathBuf,
    ) -> Result<Self, PackLoadError> {
        let mut p = Self::new(pack)?;
        p.repo_root = Some(repo_root);
        Ok(p)
    }

    /// UserGlobal: env-expand the raw path (absolute). Project: join the raw
    /// (relative) path under repo_root.
    fn resolve(&self, raw: &str) -> Option<PathBuf> {
        match &self.repo_root {
            Some(root) => Some(root.join(raw)),
            None => {
                sigil_core::policy::expand::expand(raw, &sigil_core::policy::expand::EnvLookup).ok()
            }
        }
    }
}

impl AiGuardParser for RulePackParser {
    fn tool(&self) -> AiTool {
        self.pack.tool
    }

    fn scope(&self) -> AiGuardScope {
        match self.pack.scope {
            RulePackScope::UserGlobal => AiGuardScope::UserGlobal,
            RulePackScope::Project => AiGuardScope::Project {
                path: self.repo_root.clone().unwrap_or_default(),
            },
        }
    }

    fn rule_pack_id(&self) -> Option<&str> {
        Some(&self.pack.id)
    }

    fn watched_paths(&self, _home: &Path) -> Vec<PathBuf> {
        self.pack
            .watched_paths
            .iter()
            .filter_map(|raw| self.resolve(raw))
            .collect()
    }

    fn assess(&self, _home: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let mut out = Vec::new();
        for (idx, rule) in self.pack.rules.iter().enumerate() {
            let Some(file_path) = self.resolve(&rule.on_file) else {
                return Err(AssessError::Parse {
                    path: PathBuf::from(&rule.on_file),
                    message: "resolve failed".into(),
                });
            };

            let text = match std::fs::read_to_string(&file_path) {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(AssessError::Io {
                        path: file_path,
                        source,
                    })
                }
            };

            let matches = match rule.format {
                RuleFormat::Json => eval_json(&text, &rule.selector, &file_path)?,
                RuleFormat::Toml => eval_toml(&text, &rule.selector, &file_path)?,
            };

            for matched in &matches {
                if matches_value(&rule.matcher, matched, self.compiled_regexes[idx].as_ref()) {
                    out.push(interpolate_reason(&rule.emit, matched));
                }
            }
        }
        Ok(out)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Interpolate `<selector-key>` and `<selector-value>` tokens in every
/// String field of the AiGuardReason by serialize → str::replace →
/// deserialize round-trip. Variants without String fields pass through.
fn interpolate_reason(reason: &AiGuardReason, matched: &MatchedValue) -> AiGuardReason {
    let serialized = match serde_json::to_string(reason) {
        Ok(s) => s,
        Err(_) => return reason.clone(),
    };
    if !serialized.contains("<selector-key>") && !serialized.contains("<selector-value>") {
        return reason.clone();
    }
    // Escape the matched key/value for JSON-safe embedding.
    let key_escaped = serde_json::to_string(&matched.key)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| matched.key.clone());
    let value_escaped = serde_json::to_string(&matched.value)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| matched.value.clone());
    let interpolated = serialized
        .replace("<selector-key>", &key_escaped)
        .replace("<selector-value>", &value_escaped);
    serde_json::from_str(&interpolated).unwrap_or_else(|_| reason.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::event::AiGuardReason;
    use sigil_core::policy::{Matcher, RuleEntry, RuleFormat, RulePack, RulePackScope};
    use tempfile::tempdir;

    fn pack_with_one_rule(
        on_file_abs: &str,
        selector: &str,
        matcher: Matcher,
        emit: AiGuardReason,
    ) -> RulePack {
        RulePack {
            id: "test-pack".into(),
            pack_version: 1,
            tool: AiTool::Gemini,
            scope: RulePackScope::UserGlobal,
            watched_paths: vec![on_file_abs.into()],
            platforms: None,
            rules: vec![RuleEntry {
                id: "r1".into(),
                on_file: on_file_abs.into(),
                format: RuleFormat::Json,
                selector: selector.into(),
                matcher,
                emit,
            }],
        }
    }

    #[test]
    fn missing_watched_file_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir
            .path()
            .join("missing.json")
            .to_string_lossy()
            .to_string();
        let pack = pack_with_one_rule(
            &path,
            "$.foo",
            Matcher::Exists,
            AiGuardReason::SandboxDisabled,
        );
        let p = RulePackParser::new(pack).unwrap();
        assert!(p.assess(Path::new("/unused")).unwrap().is_empty());
    }

    #[test]
    fn matched_rule_emits_reason() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("settings.json");
        std::fs::write(&file, r#"{"sandbox": false}"#).unwrap();
        let pack = pack_with_one_rule(
            file.to_str().unwrap(),
            "$.sandbox",
            Matcher::Equals {
                value: "false".into(),
            },
            AiGuardReason::SandboxDisabled,
        );
        let p = RulePackParser::new(pack).unwrap();
        let out = p.assess(Path::new("/unused")).unwrap();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], AiGuardReason::SandboxDisabled));
    }

    #[test]
    fn interpolation_substitutes_selector_key_in_emit() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mcp.json");
        std::fs::write(&file, r#"{"mcpServers": {"alpha": {"url": "https://a"}}}"#).unwrap();
        // McpServerRemote has 2 required fields: server_name + url. Use
        // distinct tokens to verify both interpolate independently.
        let pack = pack_with_one_rule(
            file.to_str().unwrap(),
            "$.mcpServers.*.url",
            Matcher::Exists,
            AiGuardReason::McpServerRemote {
                server_name: "<selector-key>".into(),
                url: "<selector-value>".into(),
            },
        );
        let p = RulePackParser::new(pack).unwrap();
        let out = p.assess(Path::new("/unused")).unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            AiGuardReason::McpServerRemote { server_name, url } => {
                assert_eq!(server_name, "alpha");
                assert_eq!(url, "https://a");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn corrupt_json_returns_parse_error() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("bad.json");
        std::fs::write(&file, "{ not json").unwrap();
        let pack = pack_with_one_rule(
            file.to_str().unwrap(),
            "$.foo",
            Matcher::Exists,
            AiGuardReason::SandboxDisabled,
        );
        let p = RulePackParser::new(pack).unwrap();
        let err = p.assess(Path::new("/unused")).unwrap_err();
        assert!(matches!(err, AssessError::Parse { .. }));
    }

    #[test]
    fn pack_with_malformed_regex_rejected_at_new() {
        let pack = RulePack {
            id: "bad-regex".into(),
            pack_version: 1,
            tool: AiTool::Gemini,
            scope: RulePackScope::UserGlobal,
            watched_paths: vec![],
            platforms: None,
            rules: vec![RuleEntry {
                id: "r1".into(),
                on_file: "/tmp/x".into(),
                format: RuleFormat::Json,
                selector: "$.x".into(),
                matcher: Matcher::Regex {
                    pattern: "[unclosed".into(),
                },
                emit: AiGuardReason::SandboxDisabled,
            }],
        };
        assert!(RulePackParser::new(pack).is_err());
    }

    #[test]
    fn tool_and_scope_from_pack() {
        let pack = pack_with_one_rule(
            "/tmp/x",
            "$.x",
            Matcher::Exists,
            AiGuardReason::SandboxDisabled,
        );
        let p = RulePackParser::new(pack).unwrap();
        assert_eq!(p.tool(), AiTool::Gemini);
        assert!(matches!(p.scope(), AiGuardScope::UserGlobal));
    }

    #[test]
    fn new_project_resolves_on_file_under_repo_root() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repoA");
        std::fs::create_dir_all(repo.join(".gemini")).unwrap();
        std::fs::write(repo.join(".gemini/settings.json"), r#"{"sandbox": false}"#).unwrap();

        let mut pack = pack_with_one_rule(
            ".gemini/settings.json",
            "$.sandbox",
            Matcher::Equals {
                value: "false".into(),
            },
            AiGuardReason::SandboxDisabled,
        );
        pack.scope = RulePackScope::Project;
        pack.watched_paths = vec![".gemini/settings.json".into()];

        let p = RulePackParser::new_project(pack, repo.clone()).unwrap();
        assert_eq!(p.scope(), AiGuardScope::Project { path: repo.clone() });
        assert_eq!(p.rule_pack_id(), Some("test-pack"));
        assert_eq!(
            p.watched_paths(Path::new("/unused")),
            vec![repo.join(".gemini/settings.json")]
        );
        let out = p.assess(Path::new("/unused")).unwrap();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], AiGuardReason::SandboxDisabled));
    }
}
