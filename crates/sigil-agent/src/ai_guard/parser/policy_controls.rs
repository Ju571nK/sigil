//! Local policy-file observations, not effective-policy or enforcement attestations.
//! Cloud policy, MDM, parent hosts, and running-session state are not resolved here.

use super::AssessError;
use serde_json::Value;
use sigil_core::event::AiGuardControl;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_DROP_INS: usize = 128;

pub(super) fn codex_requirements_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("OpenAI")
            .join("Codex")
            .join("requirements.toml")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/codex/requirements.toml")
    }
}

pub(super) fn codex_controls(path: &Path) -> Result<Vec<AiGuardControl>, AssessError> {
    let Some(text) = read_policy(path)? else {
        return Ok(Vec::new());
    };
    let policy: toml::Value = toml::from_str(&text).map_err(|e| AssessError::Parse {
        path: path.into(),
        message: e.to_string(),
    })?;
    let mut out = Vec::new();
    for (key, expected) in [
        ("allow_managed_hooks_only", true),
        ("allow_remote_control", false),
        ("allow_login_shell", false),
        ("allow_browser_and_computer_use", false),
        ("allow_appshots", false),
    ] {
        if policy.get(key).and_then(toml::Value::as_bool) == Some(expected) {
            out.push(observation("codex", path, key, Value::Bool(expected)));
        }
    }
    // Do not infer protection from arbitrary profiles or granular approval
    // names. Only bounded, known restrictive enum lists qualify.
    for (key, allowed) in [
        (
            "allowed_approval_policies",
            &["on-request", "untrusted"][..],
        ),
        (
            "allowed_sandbox_modes",
            &["read-only", "workspace-write"][..],
        ),
        ("allowed_approvals_reviewers", &["user"][..]),
    ] {
        let Some(values) = policy.get(key).and_then(toml::Value::as_array) else {
            continue;
        };
        if values.is_empty() || values.len() > 16 {
            continue;
        }
        let Some(mut strings) = values
            .iter()
            .map(toml::Value::as_str)
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        if strings.iter().any(|value| !allowed.contains(value)) {
            continue;
        }
        strings.sort_unstable();
        strings.dedup();
        out.push(observation("codex", path, key, serde_json::json!(strings)));
    }
    Ok(out)
}

pub(super) fn claude_policy_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/ClaudeCode")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\Program Files\ClaudeCode")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/etc/claude-code")
    }
}

pub(super) fn claude_paths(dir: &Path) -> Vec<PathBuf> {
    vec![
        dir.join("managed-settings.json"),
        dir.join("managed-settings.d"),
    ]
}

fn read_policy(path: &Path) -> Result<Option<String>, AssessError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AssessError::Io {
                path: path.into(),
                source,
            })
        }
    };
    let mut text = String::new();
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|source| AssessError::Io {
            path: path.into(),
            source,
        })?;
    if text.len() as u64 > MAX_POLICY_BYTES {
        return Err(AssessError::Parse {
            path: path.into(),
            message: "policy exceeds 1 MiB limit".into(),
        });
    }
    Ok(Some(text))
}

fn dotted<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    key.split('.').try_fold(value, |v, k| v.get(k))
}

fn observation(product: &str, source: &Path, key: &str, value: Value) -> AiGuardControl {
    AiGuardControl {
        id: format!("{product}.configured.{key}"),
        source_path: source.into(),
        setting: key.into(),
        value,
    }
}

pub(super) fn claude_controls(dir: &Path) -> Result<Vec<AiGuardControl>, AssessError> {
    let mut paths = vec![dir.join("managed-settings.json")];
    let drop_dir = dir.join("managed-settings.d");
    match std::fs::read_dir(&drop_dir) {
        Ok(entries) => {
            let mut drops = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|source| AssessError::Io {
                    path: drop_dir.clone(),
                    source,
                })?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json")
                    && !entry.file_name().to_string_lossy().starts_with('.')
                {
                    drops.push(path);
                    if drops.len() > MAX_DROP_INS {
                        return Err(AssessError::Parse {
                            path: drop_dir,
                            message: "too many policy drop-ins".into(),
                        });
                    }
                }
            }
            drops.sort();
            paths.extend(drops);
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(source) => {
            return Err(AssessError::Io {
                path: drop_dir,
                source,
            })
        }
    }
    let mut layers = Vec::new();
    for path in paths {
        let Some(text) = read_policy(&path)? else {
            continue;
        };
        let value: Value = serde_json::from_str(&text).map_err(|e| AssessError::Parse {
            path: path.clone(),
            message: e.to_string(),
        })?;
        if !value.is_object() {
            return Err(AssessError::Parse {
                path,
                message: "policy must be an object".into(),
            });
        }
        layers.push((path, value));
    }
    // Scalar restrictions only: last explicitly supplied value wins within
    // the local file source. A replaced parent of the wrong type invalidates it.
    let mut merged = Value::Object(Default::default());
    for (_, value) in &layers {
        merged = super::claude_code::merge_overlay(merged, Some(value.clone()));
    }
    let mut out = Vec::new();
    for (key, expected) in [
        ("permissions.disableAutoMode", Value::from("disable")),
        (
            "permissions.disableBypassPermissionsMode",
            Value::from("disable"),
        ),
        ("allowManagedPermissionRulesOnly", Value::from(true)),
        ("allowManagedHooksOnly", Value::from(true)),
        ("allowManagedMcpServersOnly", Value::from(true)),
        ("disableSideloadFlags", Value::from(true)),
        ("disableSkillShellExecution", Value::from(true)),
        ("strictPluginOnlyCustomization", Value::from(true)),
        ("sandbox.enabled", Value::from(true)),
        ("sandbox.allowUnsandboxedCommands", Value::from(false)),
        ("sandbox.network.allowManagedDomainsOnly", Value::from(true)),
        (
            "sandbox.filesystem.allowManagedReadPathsOnly",
            Value::from(true),
        ),
    ] {
        if key.starts_with("sandbox.")
            && key != "sandbox.enabled"
            && dotted(&merged, "sandbox.enabled") != Some(&Value::Bool(true))
        {
            continue;
        }
        if dotted(&merged, key) != Some(&expected) {
            continue;
        }
        if let Some((path, _)) = layers.iter().rev().find(|(_, v)| dotted(v, key).is_some()) {
            out.push(observation("claude_code", path, key, expected));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_requirements_restrictions_are_explicit_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("requirements.toml");
        assert!(codex_controls(&path).unwrap().is_empty());
        std::fs::write(&path, "allow_managed_hooks_only = true\nallow_remote_control = false\nallowed_sandbox_modes = ['workspace-write', 'read-only', 'read-only']\nallowed_approval_policies = ['on-request']\nsecret = 'not-evidence'\n").unwrap();
        let controls = codex_controls(&path).unwrap();
        assert_eq!(controls.len(), 4);
        assert_eq!(
            controls
                .iter()
                .find(|c| c.setting == "allowed_sandbox_modes")
                .unwrap()
                .value,
            serde_json::json!(["read-only", "workspace-write"])
        );
        assert!(controls
            .iter()
            .all(|c| c.source_path == path && c.id.starts_with("codex.configured.")));
        assert!(!serde_json::to_string(&controls)
            .unwrap()
            .contains("not-evidence"));
        std::fs::write(&path, "allow_managed_hooks_only = false\nallow_remote_control = true\nallowed_sandbox_modes = ['danger-full-access']\nallowed_approval_policies = ['granular']\nallowed_approvals_reviewers = []\n").unwrap();
        assert!(codex_controls(&path).unwrap().is_empty());
    }

    #[test]
    fn codex_wrong_types_and_unknown_enums_never_claim_restrictions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("requirements.toml");
        std::fs::write(&path, "allow_remote_control = 'false'\nallowed_approval_policies = ['on-request', 'future']\nallowed_sandbox_modes = ['read-only', 1]\n").unwrap();
        assert!(codex_controls(&path).unwrap().is_empty());
        std::fs::write(&path, "[broken").unwrap();
        assert!(codex_controls(&path).is_err());
    }

    #[test]
    fn claude_reports_only_allowlisted_local_file_restrictions() {
        let dir = tempfile::tempdir().unwrap();
        assert!(claude_controls(dir.path()).unwrap().is_empty());
        let path = dir.path().join("managed-settings.json");
        std::fs::write(&path, r#"{"permissions":{"disableAutoMode":"disable"},"allowManagedHooksOnly":true,"disableSideloadFlags":"true","sandbox":{"enabled":true,"allowUnsandboxedCommands":false},"env":{"TOKEN":"secret"}}"#).unwrap();
        let controls = claude_controls(dir.path()).unwrap();
        assert_eq!(controls.len(), 4);
        assert!(controls
            .iter()
            .all(|c| c.source_path == path && c.id.contains(".configured.")));
        assert!(!serde_json::to_string(&controls).unwrap().contains("secret"));
    }

    #[test]
    fn claude_drop_ins_override_scalars_with_correct_provenance() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("managed-settings.json"), r#"{"allowManagedHooksOnly":true,"sandbox":{"enabled":true,"allowUnsandboxedCommands":false}}"#).unwrap();
        let drops = dir.path().join("managed-settings.d");
        std::fs::create_dir(&drops).unwrap();
        std::fs::write(
            drops.join("10-disable.json"),
            r#"{"allowManagedHooksOnly":false,"sandbox":{"enabled":false}}"#,
        )
        .unwrap();
        assert!(claude_controls(dir.path()).unwrap().is_empty());
        let last = drops.join("20-enable.json");
        std::fs::write(&last, r#"{"allowManagedHooksOnly":true}"#).unwrap();
        std::fs::write(drops.join(".hidden.json"), "broken").unwrap();
        let controls = claude_controls(dir.path()).unwrap();
        assert_eq!(controls.len(), 1);
        assert_eq!(controls[0].source_path, last);
    }

    #[test]
    fn malformed_and_oversized_policies_fail_instead_of_empty_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed-settings.json");
        for text in ["{", "[]", "", "null"] {
            std::fs::write(&path, text).unwrap();
            assert!(claude_controls(dir.path()).is_err());
        }
        std::fs::write(&path, " ".repeat(MAX_POLICY_BYTES as usize + 1)).unwrap();
        assert!(claude_controls(dir.path()).is_err());
    }
}
